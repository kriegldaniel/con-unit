package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type testLayerEntry struct {
	name     string
	mode     int64
	uid      int
	typeflag byte
	linkname string
	data     []byte
}

func makeTestLayer(t *testing.T, entries ...testLayerEntry) v1.Layer {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Uid:      entry.uid,
			Size:     int64(len(entry.data)),
			Typeflag: typeflag,
			Linkname: entry.linkname,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("Failed writing test layer header for %q: %v", entry.name, err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatalf("Failed writing test layer data for %q: %v", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Failed closing test layer: %v", err)
	}

	layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Failed creating test layer: %v", err)
	}
	return layer
}

func makeTestImage(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()

	if len(layers) == 0 {
		return empty.Image
	}
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatalf("Failed appending test layers: %v", err)
	}
	return img
}

func TestFilesystemIndexStreamingAndWhiteouts(t *testing.T) {
	// Build an in-memory test tar layer with files and SUID permissions
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add normal file
	_ = tw.WriteHeader(&tar.Header{
		Name:     "var/cache/apt/pkgcache.bin",
		Mode:     0644,
		Size:     4,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write([]byte("data"))

	// Add SUID binary
	_ = tw.WriteHeader(&tar.Header{
		Name:     "usr/bin/passwd",
		Mode:     04755, // SUID bit
		Size:     4,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write([]byte("suid"))

	// Add compiler binary
	_ = tw.WriteHeader(&tar.Header{
		Name:     "usr/bin/gcc",
		Mode:     0755,
		Size:     4,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write([]byte("comp"))

	_ = tw.Close()

	layer, err := tarball.LayerFromReader(&buf)
	if err != nil {
		t.Fatalf("Failed creating test layer: %v", err)
	}

	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("Failed appending layer: %v", err)
	}

	reader := &ImageReader{Image: img}
	idx, err := reader.StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem failed: %v", err)
	}

	// 1. Verify path detection
	if !idx.HasPath("/var/cache/apt/pkgcache.bin") {
		t.Error("Expected /var/cache/apt/pkgcache.bin to be detected")
	}

	// 2. Verify binary detection
	if !idx.HasBinary("gcc") {
		t.Error("Expected gcc to be detected via HasBinary")
	}

	// 3. Verify SUID detection
	suids := idx.GetSuidBinaries()
	if len(suids) != 1 || suids[0] != "/usr/bin/passwd" {
		t.Errorf("Expected 1 SUID binary (/usr/bin/passwd), got: %v", suids)
	}

	// 4. Test Whiteout deletion layer
	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	_ = tw2.WriteHeader(&tar.Header{
		Name:     "usr/bin/.wh.gcc", // whiteout deletes gcc!
		Mode:     0644,
		Size:     0,
		Typeflag: tar.TypeReg,
	})
	_ = tw2.Close()

	layer2, err := tarball.LayerFromReader(&buf2)
	if err != nil {
		t.Fatalf("Failed creating whiteout layer: %v", err)
	}

	imgWithWhiteout, err := mutate.AppendLayers(img, layer2)
	if err != nil {
		t.Fatalf("Failed appending whiteout layer: %v", err)
	}

	reader2 := &ImageReader{Image: imgWithWhiteout}
	idx2, err := reader2.StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem with whiteout failed: %v", err)
	}

	if idx2.HasBinary("gcc") {
		t.Error("Expected gcc to be removed by whiteout layer, but it was still detected")
	}

	// 5. Test Recursive Directory Whiteout (.wh.cache deletes /var/cache and all children)
	var buf3 bytes.Buffer
	tw3 := tar.NewWriter(&buf3)
	_ = tw3.WriteHeader(&tar.Header{
		Name:     "var/.wh.cache", // whiteout deletes entire /var/cache tree!
		Mode:     0644,
		Size:     0,
		Typeflag: tar.TypeReg,
	})
	_ = tw3.Close()

	layer3, err := tarball.LayerFromReader(&buf3)
	if err != nil {
		t.Fatalf("Failed creating dir whiteout layer: %v", err)
	}

	imgWithDirWhiteout, err := mutate.AppendLayers(imgWithWhiteout, layer3)
	if err != nil {
		t.Fatalf("Failed appending dir whiteout layer: %v", err)
	}

	reader3 := &ImageReader{Image: imgWithDirWhiteout}
	idx3, err := reader3.StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem with dir whiteout failed: %v", err)
	}

	if idx3.HasPath("/var/cache/apt/pkgcache.bin") {
		t.Error("Expected recursive child /var/cache/apt/pkgcache.bin to be purged by var/.wh.cache whiteout")
	}

	// 6. Test World-Writable, Private Keys, Shells, Package Managers, and Non-Root Binaries
	var buf4 bytes.Buffer
	tw4 := tar.NewWriter(&buf4)
	privateKeyPEM := []byte("-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----\n")
	certificatePEM := []byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n")

	// World writable file
	_ = tw4.WriteHeader(&tar.Header{
		Name:     "app/config.json",
		Mode:     0777, // World writable
		Size:     2,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw4.Write([]byte("{}"))

	// Private key
	_ = tw4.WriteHeader(&tar.Header{
		Name:     "etc/ssl/server.key",
		Mode:     0600,
		Size:     int64(len(privateKeyPEM)),
		Typeflag: tar.TypeReg,
	})
	_, _ = tw4.Write(privateKeyPEM)

	// Public CA cert bundle (should NOT be flagged as private key)
	_ = tw4.WriteHeader(&tar.Header{
		Name:     "etc/ssl/cacert.pem",
		Mode:     0644,
		Size:     int64(len(certificatePEM)),
		Typeflag: tar.TypeReg,
	})
	_, _ = tw4.Write(certificatePEM)

	// Shell & Package manager
	_ = tw4.WriteHeader(&tar.Header{
		Name:     "bin/bash",
		Mode:     0755,
		Size:     4,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw4.Write([]byte("bash"))

	_ = tw4.WriteHeader(&tar.Header{
		Name:     "usr/bin/apt",
		Mode:     0755,
		Size:     4,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw4.Write([]byte("apt!"))

	// Non-root system binary
	_ = tw4.WriteHeader(&tar.Header{
		Name:     "bin/hijacked",
		Mode:     0755,
		Uid:      10001, // Owned by unprivileged user!
		Size:     4,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw4.Write([]byte("root"))

	// /etc/shadow with blank password
	shadowData := []byte("root::19000:0:99999:7:::\n")
	_ = tw4.WriteHeader(&tar.Header{
		Name:     "etc/shadow",
		Mode:     0640,
		Size:     int64(len(shadowData)),
		Typeflag: tar.TypeReg,
	})
	_, _ = tw4.Write(shadowData)

	// Test harness directory
	_ = tw4.WriteHeader(&tar.Header{
		Name:     "app/tests/phpunit/TestCase.php",
		Mode:     0644,
		Size:     5,
		Typeflag: tar.TypeReg,
	})
	_, _ = tw4.Write([]byte("<?php"))

	_ = tw4.Close()

	layer4, err := tarball.LayerFromReader(&buf4)
	if err != nil {
		t.Fatalf("Failed creating layer4: %v", err)
	}

	img4, err := mutate.AppendLayers(empty.Image, layer4)
	if err != nil {
		t.Fatalf("Failed appending layer4: %v", err)
	}

	reader4 := &ImageReader{Image: img4}
	idx4, err := reader4.StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem layer4 failed: %v", err)
	}

	if len(idx4.GetWorldWritableFiles()) != 1 {
		t.Errorf("Expected 1 world writable file, got: %v", idx4.GetWorldWritableFiles())
	}
	if len(idx4.GetPrivateKeyFiles()) != 1 {
		t.Errorf("Expected 1 private key (ignoring cacert.pem), got: %v", idx4.GetPrivateKeyFiles())
	}
	if len(idx4.GetInstalledShells()) != 1 || idx4.GetInstalledShells()[0] != "bash" {
		t.Errorf("Expected bash shell, got: %v", idx4.GetInstalledShells())
	}
	if len(idx4.GetInstalledPackageManagers()) != 1 || idx4.GetInstalledPackageManagers()[0] != "apt" {
		t.Errorf("Expected apt package manager, got: %v", idx4.GetInstalledPackageManagers())
	}
	if len(idx4.GetEmptyPasswordAccounts()) != 1 || idx4.GetEmptyPasswordAccounts()[0] != "root" {
		t.Errorf("Expected root with empty password in /etc/shadow, got: %v", idx4.GetEmptyPasswordAccounts())
	}
	if len(idx4.GetNonRootSystemBinaries()) != 1 {
		t.Errorf("Expected 1 non-root system binary, got: %v", idx4.GetNonRootSystemBinaries())
	}
	if len(idx4.GetTestHarnessPaths()) != 1 {
		t.Errorf("Expected 1 test harness path, got: %v", idx4.GetTestHarnessPaths())
	}
}

func TestWhiteoutsAndReplacementsReflectFinalFilesystemFindings(t *testing.T) {
	privateKeyPEM := []byte("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n")
	certificatePEM := []byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n")
	baseLayer := makeTestLayer(t,
		testLayerEntry{
			name: "opt/keys/server.pem",
			mode: 0600,
			data: privateKeyPEM,
		},
		testLayerEntry{
			name: "opt/opaque/old.key",
			mode: 0600,
			data: privateKeyPEM,
		},
		testLayerEntry{
			name: "opt/world.txt",
			mode: 0666,
			data: []byte("world-writable"),
		},
		testLayerEntry{
			name: "usr/bin/owned-by-app",
			mode: 04755,
			uid:  10001,
			data: []byte("binary"),
		},
		testLayerEntry{
			name: "etc/shadow",
			mode: 0640,
			data: []byte("root::19000:0:99999:7:::\nservice:*:19000:0:99999:7:::\n"),
		},
	)
	upperLayer := makeTestLayer(t,
		testLayerEntry{
			name: "opt/keys/server.pem",
			mode: 0644,
			data: certificatePEM,
		},
		testLayerEntry{
			name: "opt/opaque/new.txt",
			mode: 0644,
			data: []byte("same-layer addition"),
		},
		testLayerEntry{
			name: "opt/opaque/.wh..wh..opq",
			mode: 0644,
		},
		testLayerEntry{
			name: "opt/world.txt",
			mode: 0644,
			data: []byte("replacement"),
		},
		testLayerEntry{
			name: "opt/.wh.world.txt",
			mode: 0644,
		},
		testLayerEntry{
			name: "usr/bin/.wh.owned-by-app",
			mode: 0644,
		},
		testLayerEntry{
			name: "etc/.wh.shadow",
			mode: 0644,
		},
	)

	img := makeTestImage(t, baseLayer, upperLayer)
	idx, err := (&ImageReader{Image: img}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem failed: %v", err)
	}

	if !idx.HasPath("/opt/keys/server.pem") {
		t.Error("Expected replacement key-bearing path to remain in the index")
	}
	if len(idx.GetPrivateKeyFiles()) != 0 {
		t.Errorf("Expected certificate replacement to clear private-key finding, got: %v", idx.GetPrivateKeyFiles())
	}
	if idx.HasPath("/opt/opaque/old.key") || !idx.HasPath("/opt/opaque/new.txt") {
		t.Errorf("Expected opaque whiteout to remove lower-layer children but preserve same-layer additions; paths: %v", idx.Paths)
	}
	if !idx.HasPath("/opt/world.txt") || len(idx.GetWorldWritableFiles()) != 0 {
		t.Errorf("Expected same-layer replacement to survive its whiteout without retaining the world-writable finding; paths: %v", idx.GetWorldWritableFiles())
	}
	if len(idx.GetSuidBinaries()) != 0 {
		t.Errorf("Expected whiteout to remove SUID finding, got: %v", idx.GetSuidBinaries())
	}
	if len(idx.GetNonRootSystemBinaries()) != 0 {
		t.Errorf("Expected whiteout to remove non-root ownership finding, got: %v", idx.GetNonRootSystemBinaries())
	}
	if len(idx.GetEmptyPasswordAccounts()) != 0 {
		t.Errorf("Expected shadow whiteout to remove empty-password findings, got: %v", idx.GetEmptyPasswordAccounts())
	}

	privateKeyLayer := makeTestLayer(t, testLayerEntry{
		name: "opt/keys/server.pem",
		mode: 0600,
		data: privateKeyPEM,
	})
	imgWithPrivateKey := makeTestImage(t, baseLayer, upperLayer, privateKeyLayer)
	idxWithPrivateKey, err := (&ImageReader{Image: imgWithPrivateKey}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem with replacement private key failed: %v", err)
	}
	if keys := idxWithPrivateKey.GetPrivateKeyFiles(); len(keys) != 1 || keys[0] != "/opt/keys/server.pem" {
		t.Errorf("Expected private-key finding to reflect the latest replacement, got: %v", keys)
	}
}

func TestStreamAndIndexFilesystemEnforcesConfiguredLimit(t *testing.T) {
	t.Run("accepts an index exactly at the limit", func(t *testing.T) {
		layer := makeTestLayer(t,
			testLayerEntry{name: "opt/one", mode: 0644},
			testLayerEntry{name: "opt/two", mode: 0644},
		)
		idx, err := (&ImageReader{Image: makeTestImage(t, layer)}).streamAndIndexFilesystem(2)
		if err != nil {
			t.Fatalf("Expected index at configured limit to succeed: %v", err)
		}
		if len(idx.Paths) != 2 {
			t.Errorf("Expected 2 indexed paths, got %d", len(idx.Paths))
		}
	})

	t.Run("rejects an index over the limit without returning a partial result", func(t *testing.T) {
		layer := makeTestLayer(t,
			testLayerEntry{name: "opt/one", mode: 0644},
			testLayerEntry{name: "opt/two", mode: 0644},
			testLayerEntry{name: "opt/three", mode: 0644},
		)
		idx, err := (&ImageReader{Image: makeTestImage(t, layer)}).streamAndIndexFilesystem(2)
		if err == nil {
			t.Fatal("Expected index exceeding configured limit to fail")
		}
		if idx != nil {
			t.Errorf("Expected no partial index on limit error, got %d paths", len(idx.Paths))
		}
		if !strings.Contains(err.Error(), "configured limit of 2 entries") {
			t.Errorf("Expected configured-limit error, got: %v", err)
		}
	})

	t.Run("allows a replacement at the limit", func(t *testing.T) {
		baseLayer := makeTestLayer(t,
			testLayerEntry{name: "opt/one", mode: 04755, data: []byte("old")},
			testLayerEntry{name: "opt/two", mode: 0644},
		)
		upperLayer := makeTestLayer(t, testLayerEntry{name: "opt/one", mode: 0600, data: []byte("new")})
		idx, err := (&ImageReader{Image: makeTestImage(t, baseLayer, upperLayer)}).streamAndIndexFilesystem(2)
		if err != nil {
			t.Fatalf("Expected replacement at configured limit to succeed: %v", err)
		}
		if len(idx.Paths) != 2 || len(idx.SuidMap) != 0 {
			t.Errorf("Expected final index to contain two paths without stale SUID data, got paths=%v suid=%v", idx.Paths, idx.SuidMap)
		}
	})
}

func imageWithHistory(t *testing.T, image v1.Image, history []v1.History) v1.Image {
	t.Helper()
	config, err := image.ConfigFile()
	if err != nil {
		t.Fatalf("read image config: %v", err)
	}
	config.History = history
	image, err = mutate.ConfigFile(image, config)
	if err != nil {
		t.Fatalf("write image history: %v", err)
	}
	return image
}

func TestAddInstructionEvidenceRequiresUsableHistory(t *testing.T) {
	t.Run("missing history is incomplete evidence", func(t *testing.T) {
		index, err := (&ImageReader{Image: makeTestImage(t)}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		adds, err := index.AddInstructionEvidence()
		if err == nil || !strings.Contains(err.Error(), "no history entries") {
			t.Fatalf("AddInstructionEvidence error = %v, want missing-history error", err)
		}
		if len(adds) != 0 {
			t.Fatalf("unexpected ADD findings without history: %v", adds)
		}
	})

	t.Run("empty history command is malformed evidence", func(t *testing.T) {
		image := imageWithHistory(t, makeTestImage(t), []v1.History{{CreatedBy: "  "}})
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		_, err = index.AddInstructionEvidence()
		if err == nil || !strings.Contains(err.Error(), "empty CreatedBy") {
			t.Fatalf("AddInstructionEvidence error = %v, want malformed-history error", err)
		}
	})

	t.Run("usable history distinguishes an observed ADD", func(t *testing.T) {
		image := imageWithHistory(t, makeTestImage(t), []v1.History{{CreatedBy: "ADD local.txt /app/"}})
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		adds, err := index.AddInstructionEvidence()
		if err != nil {
			t.Fatalf("AddInstructionEvidence: %v", err)
		}
		if len(adds) != 1 || adds[0] != "ADD local.txt /app/" {
			t.Fatalf("ADD findings = %v, want the recorded instruction", adds)
		}
	})

	t.Run("arbitrary archive is not mistaken for base rootfs import", func(t *testing.T) {
		image := imageWithHistory(t, makeTestImage(t), []v1.History{{CreatedBy: "ADD local.tar /app/"}})
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		adds, err := index.AddInstructionEvidence()
		if err != nil {
			t.Fatalf("AddInstructionEvidence: %v", err)
		}
		if len(adds) != 1 || adds[0] != "ADD local.tar /app/" {
			t.Fatalf("ADD findings = %v, want arbitrary archive flagged", adds)
		}
	})

	t.Run("only first generated rootfs import is exempt", func(t *testing.T) {
		image := imageWithHistory(t, makeTestImage(t), []v1.History{
			{CreatedBy: "ADD file:base-image-digest in /"},
			{CreatedBy: "ADD file:later-import in /"},
		})
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		adds, err := index.AddInstructionEvidence()
		if err != nil {
			t.Fatalf("AddInstructionEvidence: %v", err)
		}
		if len(adds) != 1 || adds[0] != "ADD file:later-import in /" {
			t.Fatalf("ADD findings = %v, want only later import flagged", adds)
		}
	})
}

func TestPasswdEvidenceUsesFinalLayerAndWhiteouts(t *testing.T) {
	baseLayer := makeTestLayer(t, testLayerEntry{
		name: "etc/passwd",
		mode: 0644,
		data: []byte("root:x:0:0:root:/root:/bin/sh\napp:x:10001:10001:app:/app:/sbin/nologin\n"),
	})
	replacementLayer := makeTestLayer(t, testLayerEntry{
		name: "etc/passwd",
		mode: 0644,
		data: []byte("root:x:0:0:root:/root:/bin/sh\napp:x:0:10001:app:/app:/sbin/nologin\n"),
	})
	t.Run("replacement controls UID resolution", func(t *testing.T) {
		image := makeTestImage(t, baseLayer, replacementLayer)
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		uid, err := index.ResolveUserUID("app")
		if err != nil {
			t.Fatalf("ResolveUserUID: %v", err)
		}
		if uid != 0 {
			t.Fatalf("final-layer app UID = %d, want 0", uid)
		}
	})

	t.Run("whiteout makes named-user evidence unavailable", func(t *testing.T) {
		whiteoutLayer := makeTestLayer(t, testLayerEntry{
			name: "etc/.wh.passwd",
			mode: 0644,
		})
		image := makeTestImage(t, baseLayer, whiteoutLayer)
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		if _, err := index.ResolveUserUID("app"); err == nil {
			t.Fatal("ResolveUserUID succeeded after /etc/passwd was whiteouted")
		}
		if index.PasswdEvidenceIssue == "" {
			t.Fatal("missing /etc/passwd did not mark passwd evidence incomplete")
		}
	})
}

func TestAccountAndPrivateKeyScanLimitsMarkEvidenceIncomplete(t *testing.T) {
	t.Run("oversized passwd file", func(t *testing.T) {
		passwd := bytes.Repeat([]byte("a"), MaxAccountFileBytes+1)
		image := makeTestImage(t, makeTestLayer(t, testLayerEntry{
			name: "etc/passwd",
			mode: 0644,
			data: passwd,
		}))
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		if !strings.Contains(index.PasswdEvidenceIssue, "complete-scan limit") {
			t.Fatalf("PasswdEvidenceIssue = %q, want scan-limit detail", index.PasswdEvidenceIssue)
		}
		if _, err := index.ResolveUserUID("app"); err == nil {
			t.Fatal("ResolveUserUID succeeded with truncated passwd evidence")
		}
	})

	t.Run("oversized shadow file", func(t *testing.T) {
		passwd := []byte("root:x:0:0:root:/root:/bin/sh\n")
		shadow := bytes.Repeat([]byte("a"), MaxAccountFileBytes+1)
		image := makeTestImage(t, makeTestLayer(t,
			testLayerEntry{name: "etc/passwd", mode: 0644, data: passwd},
			testLayerEntry{name: "etc/shadow", mode: 0640, data: shadow},
		))
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		_, err = index.EmptyPasswordAccountsEvidence()
		if err == nil || !strings.Contains(err.Error(), "complete-scan limit") {
			t.Fatalf("EmptyPasswordAccountsEvidence error = %v, want scan-limit error", err)
		}
	})

	t.Run("oversized key candidate", func(t *testing.T) {
		key := bytes.Repeat([]byte("A"), MaxPrivateKeyFileBytes+1)
		image := makeTestImage(t, makeTestLayer(t, testLayerEntry{
			name: "etc/ssl/server.key",
			mode: 0600,
			data: key,
		}))
		index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
		if err != nil {
			t.Fatalf("StreamAndIndexFilesystem: %v", err)
		}
		_, err = index.PrivateKeyEvidence()
		if err == nil || !strings.Contains(err.Error(), "complete-scan limit") {
			t.Fatalf("PrivateKeyEvidence error = %v, want scan-limit error", err)
		}
	})
}

func TestLegacyRegularTarEntriesAreIndexed(t *testing.T) {
	layer := makeTestLayer(t,
		testLayerEntry{
			name:     "usr/bin/legacy-suid",
			mode:     04755,
			uid:      10001,
			typeflag: tar.TypeRegA,
			data:     []byte("binary"),
		},
		testLayerEntry{
			name:     "var/legacy-world-writable",
			mode:     0666,
			typeflag: tar.TypeRegA,
			data:     []byte("data"),
		},
		testLayerEntry{
			name:     "etc/passwd",
			mode:     0644,
			typeflag: tar.TypeRegA,
			data:     []byte("root:x:0:0:root:/root:/bin/sh\napp:x:10001:10001:app:/app:/sbin/nologin\n"),
		},
	)
	index, err := (&ImageReader{Image: makeTestImage(t, layer)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem: %v", err)
	}
	if len(index.GetSuidBinaries()) != 1 || len(index.GetNonRootSystemBinaries()) != 1 {
		t.Fatalf("legacy regular binary findings = suid:%v non-root:%v", index.GetSuidBinaries(), index.GetNonRootSystemBinaries())
	}
	if len(index.GetWorldWritableFiles()) != 1 || index.GetWorldWritableFiles()[0] != "/var/legacy-world-writable" {
		t.Fatalf("legacy regular world-writable findings = %v", index.GetWorldWritableFiles())
	}
	uid, err := index.ResolveUserUID("app")
	if err != nil || uid != 10001 {
		t.Fatalf("legacy regular passwd evidence = uid:%d error:%v, want UID 10001", uid, err)
	}
}

func TestCertificateSymlinksDoNotTriggerPrivateKeyEvidenceIssues(t *testing.T) {
	certContent := []byte("-----BEGIN CERTIFICATE-----\nMIIB...PUBLIC...CERT...\n-----END CERTIFICATE-----\n")
	layer := makeTestLayer(t,
		testLayerEntry{
			name:     "etc/ssl/certs/ca-certificates.crt",
			mode:     0644,
			typeflag: tar.TypeReg,
			data:     certContent,
		},
		testLayerEntry{
			name:     "etc/ssl/cert.pem",
			mode:     0777,
			typeflag: tar.TypeSymlink,
			linkname: "certs/ca-certificates.crt",
		},
		testLayerEntry{
			name:     "etc/ssl1.1/cert.pem",
			mode:     0777,
			typeflag: tar.TypeSymlink,
			linkname: "../ssl/cert.pem",
		},
		testLayerEntry{
			name:     "etc/ssl/certs.pem",
			mode:     0755,
			typeflag: tar.TypeDir,
		},
	)

	image := makeTestImage(t, layer)
	index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem: %v", err)
	}

	keys, err := index.PrivateKeyEvidence()
	if err != nil {
		t.Fatalf("PrivateKeyEvidence returned unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("PrivateKeyEvidence detected keys = %v, want none", keys)
	}
	if index.PrivateKeyEvidenceIssue != "" {
		t.Fatalf("PrivateKeyEvidenceIssue = %q, want empty", index.PrivateKeyEvidenceIssue)
	}
}

func TestVerifyChildManifestInIndexLive(t *testing.T) {
	if os.Getenv("CONUNIT_INTEGRATION") != "1" {
		t.Skip("set CONUNIT_INTEGRATION=1 to run tests that contact a real registry")
	}
	ref, err := name.ParseReference("docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	digestRef, ok := ref.(name.Digest)
	if !ok {
		t.Fatalf("expected name.Digest, got %T", ref)
	}
	reader, err := ResolveImageForPlatform(context.Background(), ref.Name(), v1.Platform{OS: "linux", Architecture: "arm64"})
	if err != nil {
		t.Skipf("network or daemon unavailable: %v", err)
	}
	err = verifyDigestMatch(context.Background(), digestRef, reader.Image, v1.Platform{OS: "linux", Architecture: "arm64"})
	if err != nil {
		t.Fatalf("verifyDigestMatch failed: %v", err)
	}
}

func TestNonCertKeySymlinkOrFifoTriggersEvidenceIssue(t *testing.T) {
	layer := makeTestLayer(t,
		testLayerEntry{
			name:     "etc/ssl/server.key",
			mode:     0600,
			typeflag: tar.TypeFifo,
		},
	)
	image := makeTestImage(t, layer)
	index, err := (&ImageReader{Image: image}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem: %v", err)
	}

	_, err = index.PrivateKeyEvidence()
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("PrivateKeyEvidence error = %v, want non-regular file evidence issue", err)
	}
}
