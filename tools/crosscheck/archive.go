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
	"strings"
)

// maxConfigBytes bounds the size of a file that is hashed as a candidate
// image config. Layers are far larger and are never hashed.
const maxConfigBytes = 16 << 20

// ArchiveConfigDigest returns the digest of the image config of a
// docker-archive: sha256 over the bytes of the config file that
// manifest.json names, written as "sha256:<hex>". For an image that podman or
// docker saved it equals the image ID and the config digest that ConUnit
// records in the study.
//
// The archive must hold exactly one image. The digest is computed from the
// bytes, not read from a file name, so a renamed or altered config cannot pass.
func ArchiveConfigDigest(archivePath string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var manifest []byte
	digests := map[string]string{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read the archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := cleanName(hdr.Name)
		switch {
		case name == "manifest.json":
			if hdr.Size > maxConfigBytes {
				return "", fmt.Errorf("manifest.json is %d bytes, over the limit", hdr.Size)
			}
			if manifest, err = io.ReadAll(tr); err != nil {
				return "", fmt.Errorf("read manifest.json: %w", err)
			}
		case hdr.Size <= maxConfigBytes && isConfigCandidate(name):
			h := sha256.New()
			if _, err := io.Copy(h, tr); err != nil {
				return "", fmt.Errorf("read %s: %w", name, err)
			}
			digests[name] = "sha256:" + hex.EncodeToString(h.Sum(nil))
		}
	}
	if manifest == nil {
		return "", errors.New("the archive has no manifest.json, so it is not a docker-archive")
	}
	var entries []struct {
		Config string `json:"Config"`
	}
	if err := json.Unmarshal(manifest, &entries); err != nil {
		return "", fmt.Errorf("manifest.json is not valid: %w", err)
	}
	switch len(entries) {
	case 0:
		return "", errors.New("manifest.json lists no image")
	case 1:
	default:
		return "", fmt.Errorf("the archive holds %d images, expected exactly one", len(entries))
	}
	cfg := cleanName(entries[0].Config)
	if cfg == "" {
		return "", errors.New("manifest.json names no config file")
	}
	d, ok := digests[cfg]
	if !ok {
		return "", fmt.Errorf("the config file %q named by manifest.json is not in the archive", cfg)
	}
	return d, nil
}

// isConfigCandidate selects the files that can be an image config: a JSON file
// at the top level (docker save) or a blob (OCI layout inside a docker save).
func isConfigCandidate(name string) bool {
	return strings.HasSuffix(name, ".json") || strings.HasPrefix(name, "blobs/")
}

func cleanName(name string) string {
	name = path.Clean(strings.TrimPrefix(name, "./"))
	if name == "." {
		return ""
	}
	return name
}

// NormalizeDigest lower-cases a digest and adds the sha256 prefix to a bare
// hex string.
func NormalizeDigest(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	if !strings.Contains(v, ":") {
		return "sha256:" + v
	}
	return v
}
