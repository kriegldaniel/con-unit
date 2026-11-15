package main

import (
	"archive/tar"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Paths whose content is kept. The two os-release paths follow os-release(5):
// /etc/os-release first and /usr/lib/os-release when the first does not exist.
// The release marker files are a secondary signal that is used only when the
// image has no os-release file at all.
const (
	pathEtcOSRelease = "/etc/os-release"
	pathLibOSRelease = "/usr/lib/os-release"
)

var markerPaths = []string{
	"/etc/alpine-release",
	"/etc/debian_version",
	"/etc/redhat-release",
	"/etc/system-release",
}

// shellPaths decide between a distroless style image and an image of an
// unrecognized distribution when no release file exists.
var shellPaths = []string{"/bin/sh", "/usr/bin/sh", "/busybox/sh"}

// maxCapturedBytes bounds how much of a captured file is read. These files are
// a few hundred bytes in practice.
const maxCapturedBytes = 64 << 10

// maxLinkHops bounds the links that are followed, so that a cycle ends as
// unresolved.
const maxLinkHops = 8

func capturedSet() map[string]bool {
	set := map[string]bool{pathEtcOSRelease: true, pathLibOSRelease: true}
	for _, p := range markerPaths {
		set[p] = true
	}
	return set
}

// finalView is what the layers leave of the watched paths once whiteouts and
// replacements are applied from the base layer upward.
type finalView struct {
	files   map[string][]byte // content of captured regular files
	links   map[string]string // target of captured links, absolute or relative to the link directory
	present map[string]bool   // captured and shell paths that exist
}

func newFinalView() *finalView {
	return &finalView{
		files:   map[string][]byte{},
		links:   map[string]string{},
		present: map[string]bool{},
	}
}

func normalizePath(p string) string {
	return path.Clean("/" + strings.TrimPrefix(p, "/"))
}

type layerEntry struct {
	content []byte
	link    string
	isLink  bool
	isFile  bool
}

// remove deletes the path and everything below it from the view.
func (v *finalView) remove(deleted string) {
	prefix := deleted + "/"
	for p := range v.present {
		if p == deleted || strings.HasPrefix(p, prefix) {
			delete(v.present, p)
			delete(v.files, p)
			delete(v.links, p)
		}
	}
}

// removeChildren deletes what is below a directory, for an opaque whiteout.
func (v *finalView) removeChildren(dir string) {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for p := range v.present {
		if strings.HasPrefix(p, prefix) {
			delete(v.present, p)
			delete(v.files, p)
			delete(v.links, p)
		}
	}
}

// scanImage reads the layers from the base upward and returns the final view
// of the watched paths. Entries that a layer adds survive the whiteouts of the
// same layer, whatever their order in the tar stream.
func scanImage(img v1.Image) (*finalView, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading the layer list: %w", err)
	}
	captured := capturedSet()
	watched := map[string]bool{}
	for p := range captured {
		watched[p] = true
	}
	for _, p := range shellPaths {
		watched[p] = true
	}

	view := newFinalView()
	for number, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("opening layer %d: %w", number+1, err)
		}
		var removed, opaque []string
		added := map[string]layerEntry{}

		reader := tar.NewReader(rc)
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = rc.Close()
				return nil, fmt.Errorf("reading layer %d: %w", number+1, err)
			}
			norm := normalizePath(header.Name)
			base, dir := path.Base(norm), path.Dir(norm)

			if strings.HasPrefix(base, ".wh.") {
				if base == ".wh..wh..opq" {
					opaque = append(opaque, dir)
				} else if name := strings.TrimPrefix(base, ".wh."); name != "" {
					removed = append(removed, normalizePath(path.Join(dir, name)))
				}
				continue
			}
			if !watched[norm] {
				continue
			}

			entry := layerEntry{}
			switch header.Typeflag {
			case tar.TypeSymlink:
				entry.isLink, entry.link = true, header.Linkname
			case tar.TypeLink:
				entry.isLink, entry.link = true, normalizePath(header.Linkname)
			case tar.TypeReg, tar.TypeRegA:
				entry.isFile = true
				if captured[norm] {
					content, err := io.ReadAll(io.LimitReader(reader, maxCapturedBytes))
					if err != nil {
						_ = rc.Close()
						return nil, fmt.Errorf("reading %s in layer %d: %w", norm, number+1, err)
					}
					entry.content = content
				}
			}
			added[norm] = entry
		}
		if err := rc.Close(); err != nil {
			return nil, fmt.Errorf("closing layer %d: %w", number+1, err)
		}

		for _, deleted := range removed {
			view.remove(deleted)
		}
		for _, dir := range opaque {
			view.removeChildren(dir)
		}
		for p, entry := range added {
			delete(view.files, p)
			delete(view.links, p)
			view.present[p] = true
			switch {
			case entry.isLink:
				view.links[p] = entry.link
			case entry.isFile && captured[p]:
				view.files[p] = entry.content
			}
		}
	}
	return view, nil
}

// File states of resolveFile.
const (
	stateFile       = "file"
	stateAbsent     = "absent"
	stateUnresolved = "unresolved"
)

type resolved struct {
	State   string
	Path    string // the path the content was read from
	Content []byte
	Reason  string
}

func linkTarget(from, target string) string {
	if strings.HasPrefix(target, "/") {
		return path.Clean(target)
	}
	return path.Clean(path.Join(path.Dir(from), target))
}

// resolveFile returns the content that a path has in the final view, following
// links that lead to another captured path. A link to a path that was not
// captured is unresolved, because the existence of its target is unknown.
func (v *finalView) resolveFile(p string) resolved {
	captured := capturedSet()
	current := p
	for hops := 0; hops <= maxLinkHops; hops++ {
		if content, ok := v.files[current]; ok {
			return resolved{State: stateFile, Path: current, Content: content}
		}
		target, isLink := v.links[current]
		if !isLink {
			if v.present[current] {
				return resolved{State: stateUnresolved, Reason: fmt.Sprintf("%s exists but is not a regular file", current)}
			}
			if current == p {
				return resolved{State: stateAbsent}
			}
			return resolved{State: stateAbsent, Reason: fmt.Sprintf("link %s leads to %s, which does not exist", p, current)}
		}
		next := linkTarget(current, target)
		if !captured[next] {
			return resolved{State: stateUnresolved, Reason: fmt.Sprintf("link %s leads to %s, which is not a captured path", current, next)}
		}
		current = next
	}
	return resolved{State: stateUnresolved, Reason: fmt.Sprintf("more than %d links were followed from %s", maxLinkHops, p)}
}

// osRelease is the outcome of reading os-release.
type osRelease struct {
	Path    string
	Content string
	Note    string // set when no content could be read
}

// readOSRelease applies os-release(5): /etc/os-release, then /usr/lib/os-release
// only when the first does not exist. An unresolved first path stops the
// search, because the file may exist.
func readOSRelease(v *finalView) osRelease {
	for _, p := range []string{pathEtcOSRelease, pathLibOSRelease} {
		r := v.resolveFile(p)
		switch r.State {
		case stateFile:
			return osRelease{Path: r.Path, Content: string(r.Content)}
		case stateUnresolved:
			return osRelease{Note: r.Reason}
		}
	}
	return osRelease{Note: "no /etc/os-release and no /usr/lib/os-release in the final filesystem"}
}

// parseOSRelease reads the KEY=VALUE lines of an os-release file. Values may
// be wrapped in single or double quotes. Comments and blank lines are skipped.
func parseOSRelease(content string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			first, last := value[0], value[len(value)-1]
			if (first == '"' || first == '\'') && first == last {
				value = value[1 : len(value)-1]
			}
		}
		fields[strings.TrimSpace(key)] = value
	}
	return fields
}

// Base families, as used by tools/internal/analysis.
const (
	familyAlpine     = "alpine"
	familyDebian     = "debian"
	familyUbuntu     = "ubuntu"
	familyFedoraRHEL = "fedora-rhel"
	familyScratch    = "scratch-or-distroless"
	familyOther      = "other"
	familyUnknown    = "unknown"
)

// familyOfToken maps one os-release ID or ID_LIKE token to a family, or "".
func familyOfToken(token string) string {
	switch strings.ToLower(token) {
	case "alpine":
		return familyAlpine
	case "ubuntu":
		return familyUbuntu
	case "debian":
		return familyDebian
	case "rhel", "fedora", "centos":
		return familyFedoraRHEL
	}
	return ""
}

// classification explains how a family was derived.
type classification struct {
	Family string
	Rule   string
}

// classify derives the base family. The rules are applied in this order and the
// first that applies decides.
//
//  1. os-release exists and names a family in ID, or else in the first matching
//     token of ID_LIKE: that family.
//  2. os-release exists and names no listed family: other.
//  3. os-release exists but has no ID: unknown.
//  4. No os-release but a release marker file exists: the family of the marker.
//  5. No os-release, no marker and no shell: scratch-or-distroless.
//  6. Anything else: unknown.
//
// An unresolved os-release path is unknown and never guessed from other files.
func classify(osr osRelease, markers map[string]string, hasShell bool) classification {
	if osr.Path != "" {
		fields := parseOSRelease(osr.Content)
		id := fields["ID"]
		if id == "" {
			return classification{familyUnknown, "os-release has no ID"}
		}
		tokens := append([]string{id}, strings.Fields(fields["ID_LIKE"])...)
		for i, token := range tokens {
			if family := familyOfToken(token); family != "" {
				if i == 0 {
					return classification{family, fmt.Sprintf("os-release ID %s", id)}
				}
				return classification{family, fmt.Sprintf("os-release ID %s, ID_LIKE token %s", id, token)}
			}
		}
		return classification{familyOther, fmt.Sprintf("os-release ID %s is not in a listed family", id)}
	}
	if osr.Path == "" && osr.Note != "" && !strings.HasPrefix(osr.Note, "no /etc/os-release") {
		return classification{familyUnknown, "os-release could not be resolved: " + osr.Note}
	}
	for _, marker := range []struct{ path, family string }{
		{"/etc/alpine-release", familyAlpine},
		{"/etc/debian_version", familyDebian},
		{"/etc/redhat-release", familyFedoraRHEL},
		{"/etc/system-release", familyFedoraRHEL},
	} {
		if _, ok := markers[marker.path]; ok {
			return classification{marker.family, fmt.Sprintf("no os-release, release marker %s", marker.path)}
		}
	}
	if !hasShell {
		return classification{familyScratch, "no os-release, no release marker and no shell"}
	}
	return classification{familyUnknown, "no os-release and no release marker, but the image has a shell"}
}

// firstLine returns the first line of a marker file, trimmed and bounded.
func firstLine(content []byte) string {
	line, _, _ := strings.Cut(string(content), "\n")
	line = strings.TrimSpace(line)
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}

// markersOf returns the first line of each marker file that exists.
func markersOf(v *finalView) map[string]string {
	markers := map[string]string{}
	for _, p := range markerPaths {
		if r := v.resolveFile(p); r.State == stateFile {
			markers[p] = firstLine(r.Content)
		}
	}
	return markers
}

func hasShell(v *finalView) bool {
	for _, p := range shellPaths {
		if v.present[p] {
			return true
		}
	}
	return false
}
