package main

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type tarEntry struct {
	name     string
	typeflag byte
	linkname string
	data     string
}

func file(name, data string) tarEntry { return tarEntry{name: name, typeflag: tar.TypeReg, data: data} }
func symlink(name, target string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeSymlink, linkname: target}
}
func hardlink(name, target string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeLink, linkname: target}
}
func whiteout(name string) tarEntry { return tarEntry{name: name, typeflag: tar.TypeReg} }

func layerOf(t *testing.T, entries ...tarEntry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		header := &tar.Header{Name: e.name, Mode: 0644, Typeflag: e.typeflag, Linkname: e.linkname, Size: int64(len(e.data))}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("header %q: %v", e.name, err)
		}
		if _, err := tw.Write([]byte(e.data)); err != nil {
			t.Fatalf("data %q: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer: %v", err)
	}
	layer, err := tarball.LayerFromReader(&buf)
	if err != nil {
		t.Fatalf("layer: %v", err)
	}
	return layer
}

func imageOf(t *testing.T, layers ...[]tarEntry) v1.Image {
	t.Helper()
	built := make([]v1.Layer, 0, len(layers))
	for _, entries := range layers {
		built = append(built, layerOf(t, entries...))
	}
	if len(built) == 0 {
		return empty.Image
	}
	img, err := mutate.AppendLayers(empty.Image, built...)
	if err != nil {
		t.Fatalf("image: %v", err)
	}
	return img
}

const (
	alpineOSRelease = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.22.0\n"
	debianOSRelease = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n"
	ubuntuOSRelease = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n"
)

func TestScanImageResolvesOSReleaseLikeTheFinalFilesystem(t *testing.T) {
	cases := []struct {
		name         string
		layers       [][]tarEntry
		wantPath     string
		wantContent  string
		wantNote     string
		wantMarkers  map[string]string
		wantHasShell bool
	}{
		{
			name:        "regular file in /etc",
			layers:      [][]tarEntry{{file("etc/os-release", alpineOSRelease)}},
			wantPath:    "/etc/os-release",
			wantContent: alpineOSRelease,
		},
		{
			name:        "relative link to /usr/lib across layers",
			layers:      [][]tarEntry{{file("usr/lib/os-release", debianOSRelease)}, {symlink("etc/os-release", "../usr/lib/os-release")}},
			wantPath:    "/usr/lib/os-release",
			wantContent: debianOSRelease,
		},
		{
			name:        "absolute link to /usr/lib",
			layers:      [][]tarEntry{{symlink("etc/os-release", "/usr/lib/os-release"), file("usr/lib/os-release", ubuntuOSRelease)}},
			wantPath:    "/usr/lib/os-release",
			wantContent: ubuntuOSRelease,
		},
		{
			name:        "hard link to /usr/lib",
			layers:      [][]tarEntry{{file("usr/lib/os-release", debianOSRelease), hardlink("etc/os-release", "usr/lib/os-release")}},
			wantPath:    "/usr/lib/os-release",
			wantContent: debianOSRelease,
		},
		{
			name:        "only /usr/lib/os-release is the fallback",
			layers:      [][]tarEntry{{file("usr/lib/os-release", debianOSRelease)}},
			wantPath:    "/usr/lib/os-release",
			wantContent: debianOSRelease,
		},
		{
			name:        "/etc/os-release wins over /usr/lib/os-release",
			layers:      [][]tarEntry{{file("usr/lib/os-release", debianOSRelease), file("etc/os-release", alpineOSRelease)}},
			wantPath:    "/etc/os-release",
			wantContent: alpineOSRelease,
		},
		{
			name:        "a later layer replaces the content",
			layers:      [][]tarEntry{{file("etc/os-release", debianOSRelease)}, {file("etc/os-release", ubuntuOSRelease)}},
			wantPath:    "/etc/os-release",
			wantContent: ubuntuOSRelease,
		},
		{
			name:        "whiteout of /etc/os-release falls back to /usr/lib",
			layers:      [][]tarEntry{{file("etc/os-release", alpineOSRelease), file("usr/lib/os-release", debianOSRelease)}, {whiteout("etc/.wh.os-release")}},
			wantPath:    "/usr/lib/os-release",
			wantContent: debianOSRelease,
		},
		{
			name:     "whiteout of the only file leaves none",
			layers:   [][]tarEntry{{file("etc/os-release", alpineOSRelease)}, {whiteout("etc/.wh.os-release")}},
			wantNote: "no /etc/os-release and no /usr/lib/os-release",
		},
		{
			name:     "whiteout of /etc removes the file below it",
			layers:   [][]tarEntry{{file("etc/os-release", alpineOSRelease)}, {whiteout(".wh.etc")}},
			wantNote: "no /etc/os-release and no /usr/lib/os-release",
		},
		{
			name: "opaque directory removes lower files but keeps additions of the same layer",
			layers: [][]tarEntry{
				{file("etc/os-release", alpineOSRelease)},
				{file("etc/alpine-release", "3.22.0\n"), whiteout("etc/.wh..wh..opq")},
			},
			wantNote:    "no /etc/os-release and no /usr/lib/os-release",
			wantMarkers: map[string]string{"/etc/alpine-release": "3.22.0"},
		},
		{
			name:     "dangling link counts as absent",
			layers:   [][]tarEntry{{symlink("etc/os-release", "../usr/lib/os-release")}},
			wantNote: "no /etc/os-release and no /usr/lib/os-release",
		},
		{
			name:     "link to a path that was not captured is unresolved",
			layers:   [][]tarEntry{{symlink("etc/os-release", "../usr/lib/os-release-custom")}},
			wantNote: "not a captured path",
		},
		{
			name:     "link cycle is unresolved",
			layers:   [][]tarEntry{{symlink("etc/os-release", "/usr/lib/os-release"), symlink("usr/lib/os-release", "/etc/os-release")}},
			wantNote: "links were followed",
		},
		{
			name:         "marker files and a shell",
			layers:       [][]tarEntry{{file("etc/debian_version", "12.5\nextra\n"), file("bin/sh", "x"), file("etc/os-release", debianOSRelease)}},
			wantPath:     "/etc/os-release",
			wantContent:  debianOSRelease,
			wantMarkers:  map[string]string{"/etc/debian_version": "12.5"},
			wantHasShell: true,
		},
		{
			name:         "a shell that is a link counts",
			layers:       [][]tarEntry{{symlink("bin/sh", "busybox")}},
			wantNote:     "no /etc/os-release and no /usr/lib/os-release",
			wantHasShell: true,
		},
		{
			name:     "a shell removed by a later layer does not count",
			layers:   [][]tarEntry{{file("bin/sh", "x")}, {whiteout("bin/.wh.sh")}},
			wantNote: "no /etc/os-release and no /usr/lib/os-release",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view, err := scanImage(imageOf(t, tc.layers...))
			if err != nil {
				t.Fatalf("scanImage: %v", err)
			}
			osr := readOSRelease(view)
			if osr.Path != tc.wantPath || osr.Content != tc.wantContent {
				t.Errorf("os-release = path %q content %q, want path %q content %q", osr.Path, osr.Content, tc.wantPath, tc.wantContent)
			}
			if tc.wantNote == "" && osr.Note != "" {
				t.Errorf("unexpected note %q", osr.Note)
			}
			if tc.wantNote != "" && !strings.Contains(osr.Note, tc.wantNote) {
				t.Errorf("note = %q, want it to contain %q", osr.Note, tc.wantNote)
			}
			markers := markersOf(view)
			if len(markers) != len(tc.wantMarkers) {
				t.Errorf("markers = %v, want %v", markers, tc.wantMarkers)
			}
			for path, line := range tc.wantMarkers {
				if markers[path] != line {
					t.Errorf("marker %s = %q, want %q", path, markers[path], line)
				}
			}
			if got := hasShell(view); got != tc.wantHasShell {
				t.Errorf("hasShell = %t, want %t", got, tc.wantHasShell)
			}
		})
	}
}

func TestScanImageBoundsTheCapturedContent(t *testing.T) {
	big := strings.Repeat("A", maxCapturedBytes+1000)
	view, err := scanImage(imageOf(t, []tarEntry{file("etc/os-release", big)}))
	if err != nil {
		t.Fatalf("scanImage: %v", err)
	}
	if got := len(readOSRelease(view).Content); got != maxCapturedBytes {
		t.Errorf("captured %d bytes, want the bound of %d", got, maxCapturedBytes)
	}
}

func TestScanImageOfAnEmptyImage(t *testing.T) {
	view, err := scanImage(imageOf(t))
	if err != nil {
		t.Fatalf("scanImage: %v", err)
	}
	if osr := readOSRelease(view); osr.Path != "" || osr.Note == "" {
		t.Errorf("empty image gave %+v, want no file and a note", osr)
	}
	if hasShell(view) || len(markersOf(view)) != 0 {
		t.Error("an empty image has no shell and no markers")
	}
}

func TestParseOSRelease(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    map[string]string
	}{
		{"double quotes", "ID=\"ol\"\nID_LIKE=\"fedora\"\n", map[string]string{"ID": "ol", "ID_LIKE": "fedora"}},
		{"single quotes", "ID='arch'\n", map[string]string{"ID": "arch"}},
		{"no quotes", "ID=alpine\n", map[string]string{"ID": "alpine"}},
		{"comments and blank lines", "# comment\n\nID=debian\n", map[string]string{"ID": "debian"}},
		{"value with equals sign", "HOME_URL=\"https://example.org/?a=b\"\n", map[string]string{"HOME_URL": "https://example.org/?a=b"}},
		{"carriage returns", "ID=debian\r\nVERSION_ID=\"12\"\r\n", map[string]string{"ID": "debian", "VERSION_ID": "12"}},
		{"mismatched quotes are kept", "ID=\"debian'\n", map[string]string{"ID": "\"debian'"}},
		{"line without equals sign", "garbage\nID=x\n", map[string]string{"ID": "x"}},
		{"empty", "", map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOSRelease(tc.content)
			if len(got) != len(tc.want) {
				t.Fatalf("parsed %v, want %v", got, tc.want)
			}
			for key, value := range tc.want {
				if got[key] != value {
					t.Errorf("%s = %q, want %q", key, got[key], value)
				}
			}
		})
	}
}

func TestClassify(t *testing.T) {
	present := func(content string) osRelease { return osRelease{Path: "/etc/os-release", Content: content} }
	none := osRelease{Note: "no /etc/os-release and no /usr/lib/os-release in the final filesystem"}

	cases := []struct {
		name     string
		osr      osRelease
		markers  map[string]string
		hasShell bool
		want     string
		ruleHas  string
	}{
		{"alpine", present(alpineOSRelease), nil, true, familyAlpine, "ID alpine"},
		{"debian", present(debianOSRelease), nil, true, familyDebian, "ID debian"},
		{"ubuntu wins over its ID_LIKE debian", present(ubuntuOSRelease), nil, true, familyUbuntu, "ID ubuntu"},
		{"oracle linux through ID_LIKE", present("ID=\"ol\"\nID_LIKE=\"fedora\"\n"), nil, true, familyFedoraRHEL, "ID_LIKE token fedora"},
		{"amazon linux 2 through ID_LIKE", present("ID=\"amzn\"\nID_LIKE=\"centos rhel fedora\"\n"), nil, true, familyFedoraRHEL, "ID_LIKE token centos"},
		{"red hat universal base image", present("ID=\"rhel\"\n"), nil, true, familyFedoraRHEL, "ID rhel"},
		{"fedora", present("ID=fedora\n"), nil, true, familyFedoraRHEL, "ID fedora"},
		{"first matching ID_LIKE token decides", present("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"), nil, true, familyUbuntu, "ID_LIKE token ubuntu"},
		{"ID is compared without regard to case", present("ID=\"Debian\"\n"), nil, true, familyDebian, "ID Debian"},
		{"wolfi is another family", present("ID=wolfi\n"), nil, false, familyOther, "not in a listed family"},
		{"arch is another family", present("ID=arch\n"), nil, true, familyOther, "not in a listed family"},
		{"photon is another family", present("ID=photon\n"), nil, true, familyOther, "not in a listed family"},
		{"suse is another family", present("ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\n"), nil, true, familyOther, "not in a listed family"},
		{"os-release without ID", present("NAME=Something\n"), nil, true, familyUnknown, "no ID"},
		{"empty os-release", present(""), map[string]string{"/etc/alpine-release": "3.22"}, true, familyUnknown, "no ID"},
		{"alpine marker without os-release", none, map[string]string{"/etc/alpine-release": "3.22.0"}, true, familyAlpine, "/etc/alpine-release"},
		{"debian marker without os-release", none, map[string]string{"/etc/debian_version": "12.5"}, true, familyDebian, "/etc/debian_version"},
		{"redhat marker without os-release", none, map[string]string{"/etc/redhat-release": "CentOS"}, true, familyFedoraRHEL, "/etc/redhat-release"},
		{"system release marker without os-release", none, map[string]string{"/etc/system-release": "Amazon Linux"}, true, familyFedoraRHEL, "/etc/system-release"},
		{"no release data and no shell", none, nil, false, familyScratch, "no shell"},
		{"no release data but a shell", none, nil, true, familyUnknown, "has a shell"},
		{"unresolved os-release is never guessed from markers", osRelease{Note: "link /etc/os-release leads to /x, which is not a captured path"}, map[string]string{"/etc/alpine-release": "3.22"}, true, familyUnknown, "could not be resolved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.osr, tc.markers, tc.hasShell)
			if got.Family != tc.want {
				t.Errorf("family = %q (%s), want %q", got.Family, got.Rule, tc.want)
			}
			if !strings.Contains(got.Rule, tc.ruleHas) {
				t.Errorf("rule = %q, want it to contain %q", got.Rule, tc.ruleHas)
			}
		})
	}
}
