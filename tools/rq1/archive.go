package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// maxConfigBytes bounds the JSON members that are held in memory while the
// archive is scanned. An image config is a few kilobytes.
const maxConfigBytes = 16 << 20

// ArchiveRecord is what the raw run file keeps about the docker-archive that
// Trivy and Dockle read. ConfigDigest is the sha256 of the image config as
// stored in the archive, in the form ConUnit reports as config_digest, so the
// archive can be tied to a study record. MatchesImageID compares it with the
// image ID the engine reported after the build; it is nil when either is
// unknown.
type ArchiveRecord struct {
	Format         string `json:"format"` // docker-archive
	ConfigName     string `json:"config_name,omitempty"`
	ConfigDigest   string `json:"config_digest,omitempty"`
	ImageID        string `json:"image_id,omitempty"`
	MatchesImageID *bool  `json:"matches_image_id,omitempty"`
	SizeBytes      int64  `json:"size_bytes,omitempty"`
	ExportError    string `json:"export_error,omitempty"`
	DigestError    string `json:"digest_error,omitempty"`
	// NameMismatch is set when the config member is named by a digest that
	// differs from the digest of its content.
	NameMismatch string `json:"name_mismatch,omitempty"`
}

var hexName = regexp.MustCompile(`^([0-9a-f]{64})(\.json)?$`)

// ReadArchiveConfigDigest scans a docker-archive and returns the digest of
// the single image config it holds. The archive must contain manifest.json
// with exactly one entry, as `podman save --format docker-archive` and
// `docker save` of one image produce. The digest is computed from the config
// bytes, not taken from the member name.
func ReadArchiveConfigDigest(archivePath string) (ArchiveRecord, error) {
	rec := ArchiveRecord{Format: "docker-archive"}
	f, err := os.Open(archivePath)
	if err != nil {
		return rec, err
	}
	defer f.Close()
	if st, statErr := f.Stat(); statErr == nil {
		rec.SizeBytes = st.Size()
	}

	manifest, found, err := readTarMember(f, "manifest.json")
	if err != nil {
		return rec, err
	}
	if !found {
		return rec, errors.New("no manifest.json in the archive, it is not a docker-archive")
	}
	var entries []struct {
		Config string `json:"Config"`
	}
	if err := json.Unmarshal(manifest, &entries); err != nil {
		return rec, fmt.Errorf("manifest.json is not valid: %w", err)
	}
	switch len(entries) {
	case 0:
		return rec, errors.New("manifest.json lists no image")
	case 1:
	default:
		return rec, fmt.Errorf("manifest.json lists %d images, expected exactly one", len(entries))
	}
	if entries[0].Config == "" {
		return rec, errors.New("manifest.json names no config member")
	}
	name := cleanMemberName(entries[0].Config)
	body, found, err := readTarMember(f, name)
	if err != nil {
		return rec, err
	}
	if !found {
		return rec, fmt.Errorf("config member %q named by manifest.json is not in the archive", entries[0].Config)
	}
	sum := sha256.Sum256(body)
	rec.ConfigName = name
	rec.ConfigDigest = "sha256:" + hex.EncodeToString(sum[:])
	if m := hexName.FindStringSubmatch(path.Base(name)); m != nil && m[1] != hex.EncodeToString(sum[:]) {
		rec.NameMismatch = fmt.Sprintf("the config member is named %s but its content hashes to %s", path.Base(name), hex.EncodeToString(sum[:]))
	}
	return rec, nil
}

// cleanMemberName gives the name of a tar member a canonical form.
func cleanMemberName(name string) string {
	return path.Clean(strings.TrimPrefix(name, "./"))
}

// readTarMember returns the content of the regular member with the given name,
// scanning the archive from its start. A member that is larger than the limit
// for JSON members is an error, because manifest.json and the image config are
// small and anything larger is not one of them.
func readTarMember(f *os.File, name string) ([]byte, bool, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, false, fmt.Errorf("rewinding the archive: %w", err)
	}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("reading the archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || cleanMemberName(hdr.Name) != name {
			continue
		}
		if hdr.Size > maxConfigBytes {
			return nil, false, fmt.Errorf("member %s is %d bytes, more than the %d byte limit for a JSON member", name, hdr.Size, maxConfigBytes)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, false, fmt.Errorf("reading member %s: %w", name, err)
		}
		return body, true, nil
	}
}

// normalizeDigest returns a digest in the form sha256:<hex> from a bare hex
// string or an already prefixed one, or "" for anything else.
func normalizeDigest(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) == 64 {
		if _, err := hex.DecodeString(s); err == nil {
			return "sha256:" + strings.ToLower(s)
		}
	}
	return ""
}
