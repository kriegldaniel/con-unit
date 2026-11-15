package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/runenv"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

// oversizedImageError is what the runner returns for an image that broke the
// index limit: the typed limit error wrapped in an ImageError that carries the
// identity and the size read so far.
func oversizedImageError() error {
	limit := &oci.IndexTooLargeError{
		Dimension: oci.IndexLimitEntries, Limit: 1000, Entries: 1001,
		Layer: 4, Layers: 9, ScannedBytes: 3 << 30,
	}
	return &runner.ImageError{
		Stage:       "index",
		ImageSource: spec.SourceLocalStore,
		Partial: &spec.SuiteResult{
			ImageSource:  spec.SourceLocalStore,
			ImageDigest:  "sha256:" + strings.Repeat("a", 64),
			ConfigDigest: "sha256:" + strings.Repeat("b", 64),
			Platform:     "linux/amd64",
			Resources:    spec.ResourceTelemetry{LayerCount: 9, UncompressedBytes: 3 << 30, IndexedEntries: 1001},
		},
		Err: fmt.Errorf("failed indexing OCI filesystem for image 'big:1': %w", limit),
	}
}

func TestEvalRecordsAnIndexLimitExclusionWithIdentityAndSize(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "results")
	fake := &fakePackRunner{errors: map[string]error{"big:1": oversizedImageError()}}
	code := runEvalCommandWithDeps([]string{"--images", writeImageListFile(t, "big:1\nsmall:1\n"), "--out-dir", outDir, "--max-index-entries", "1000"}, offlineCommandDeps(fake))
	if code != spec.ExitIncomplete {
		t.Fatalf("exit code = %d, want %d: an excluded image is not a completed one", code, spec.ExitIncomplete)
	}
	study := readStudy(t, outDir)
	big := study.Images[0]
	if big.Status != spec.StatusIndexLimit || big.Reason != spec.ReasonIndexTooLarge {
		t.Fatalf("status/reason = %s/%s, want INDEX_LIMIT/INDEX_TOO_LARGE", big.Status, big.Reason)
	}
	if big.ImageSource != spec.SourceLocalStore || big.Platform != "linux/amd64" ||
		big.ImageDigest != "sha256:"+strings.Repeat("a", 64) || big.ConfigDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Errorf("the exclusion lost the image identity: %+v", big)
	}
	if big.Resources.LayerCount != 9 || big.Resources.UncompressedBytes != 3<<30 || big.Resources.IndexedEntries != 1001 {
		t.Errorf("the exclusion lost the size read: %+v", big.Resources)
	}
	if !strings.Contains(big.ErrorMessage, "configured limit of 1000 entries") || !strings.Contains(big.ErrorMessage, "in layer 4 of 9") {
		t.Errorf("error message lacks the limit details: %q", big.ErrorMessage)
	}
	if small := study.Images[1]; small.Status != spec.StatusCompleted {
		t.Errorf("the image after an exclusion must still be evaluated, got %s", small.Status)
	}

	attrition, err := os.ReadFile(filepath.Join(outDir, "ATTRITION_REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"## 4. Tool-Limit Exclusions (INDEX_LIMIT)",
		"limit belongs to the tool, not to the image",
		"| `big:1` | 9 | 1,001 | n/a | 3.0 GiB | `" + shortDigest("sha256:"+strings.Repeat("b", 64)) + "` |",
		"INDEX_LIMIT / INDEX_TOO_LARGE: 1",
	} {
		if !strings.Contains(string(attrition), want) {
			t.Errorf("attrition report lacks %q:\n%s", want, attrition)
		}
	}

	logData, err := os.ReadFile(filepath.Join(outDir, "logs", "big_1.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"STATUS: INDEX_LIMIT", "CONFIG DIGEST: sha256:" + strings.Repeat("b", 64), "SIZE READ: layers=9, entries=1,001, compressed=n/a, content=3.0 GiB (lower bounds)"} {
		if !strings.Contains(string(logData), want) {
			t.Errorf("diagnostic log lacks %q:\n%s", want, logData)
		}
	}
}

func TestAttritionReportHasNoIndexLimitSectionWithoutExclusions(t *testing.T) {
	report := renderAttritionReport(sampleStudy())
	if strings.Contains(report, "Tool-Limit") || strings.Contains(report, "INDEX_LIMIT") {
		t.Errorf("a study without INDEX_LIMIT images must not mention the exclusion section:\n%s", report)
	}
}

func TestIndexLimitSectionIsDeterministicAndOrdered(t *testing.T) {
	study := &spec.Study{Images: []*spec.SuiteResult{
		{ImageName: "z:1", Status: spec.StatusIndexLimit, Reason: spec.ReasonIndexTooLarge, ConfigDigest: "sha256:" + strings.Repeat("1", 64)},
		{ImageName: "a:1", Status: spec.StatusIndexLimit, Reason: spec.ReasonIndexTooLarge, Resources: spec.ResourceTelemetry{LayerCount: 2, CompressedBytes: 5 << 20}},
	}}
	first := renderAttritionReport(study)
	for i := 0; i < 20; i++ {
		if renderAttritionReport(study) != first {
			t.Fatal("the report changed between renders")
		}
	}
	section := renderIndexLimitSection(study)
	unknown := "| `z:1` | n/a | n/a | n/a | n/a | `" + shortDigest("sha256:"+strings.Repeat("1", 64)) + "` |"
	known := "| `a:1` | 2 | n/a | 5.0 MiB | n/a | `n/a` |"
	zAt, aAt := strings.Index(section, unknown), strings.Index(section, known)
	if zAt < 0 || aAt < 0 {
		t.Fatalf("rows must show unknown sizes as n/a and known ones in binary units:\n%s", section)
	}
	if zAt > aAt {
		t.Errorf("rows must follow the image list order, not the alphabet:\n%s", section)
	}
}

func TestWithEffectiveFlagsStatesTheDefaultsThatWereUsed(t *testing.T) {
	effective := []namedFlag{{"image-timeout", "5m0s"}, {"max-index-entries", "1000000"}}
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"defaults are appended", []string{"eval", "--images", "x.txt"}, []string{"eval", "--images", "x.txt", "--image-timeout=5m0s", "--max-index-entries=1000000"}},
		{"explicit value with equals is kept", []string{"eval", "--max-index-entries=500"}, []string{"eval", "--max-index-entries=500", "--image-timeout=5m0s"}},
		{"explicit value with a space is kept", []string{"eval", "--max-index-entries", "500", "--image-timeout", "1m"}, []string{"eval", "--max-index-entries", "500", "--image-timeout", "1m"}},
		{"single dash form is recognized", []string{"eval", "-max-index-entries=500"}, []string{"eval", "-max-index-entries=500", "--image-timeout=5m0s"}},
		{"a value that merely resembles a flag name is not a flag", []string{"eval", "--out-dir", "max-index-entries"}, []string{"eval", "--out-dir", "max-index-entries", "--image-timeout=5m0s", "--max-index-entries=1000000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]string(nil), tc.args...)
			got := withEffectiveFlags(tc.args, effective)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("flags = %q, want %q", got, tc.want)
			}
			if !reflect.DeepEqual(tc.args, original) {
				t.Errorf("the input slice was modified: %q", tc.args)
			}
		})
	}
}

func TestEvalRecordsTheEffectiveIndexLimitInTheRunMetadata(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want []string
		not  []string
	}{
		"default": {
			args: nil,
			want: []string{"--max-index-entries=" + fmt.Sprint(oci.MaxIndexedFiles), "--image-timeout=5m0s"},
		},
		"explicit": {
			args: []string{"--max-index-entries", "1234"},
			want: []string{"1234", "--image-timeout=5m0s"},
			not:  []string{"--max-index-entries=" + fmt.Sprint(oci.MaxIndexedFiles)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var recorded []string
			deps := offlineCommandDeps(&fakePackRunner{})
			deps.detectRun = func(_ context.Context, options runenv.Options) spec.RunMetadata {
				recorded = options.Flags
				return spec.RunMetadata{StartedAt: fixedClock}
			}
			args := append([]string{"--images", writeImageListFile(t, "x:1\n"), "--out-dir", t.TempDir()}, tc.args...)
			if code := runEvalCommandWithDeps(args, deps); code != spec.ExitOK {
				t.Fatalf("exit code = %d", code)
			}
			joined := strings.Join(recorded, " ")
			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Errorf("recorded flags %q lack %q", joined, want)
				}
			}
			for _, not := range tc.not {
				if strings.Contains(joined, not) {
					t.Errorf("recorded flags %q must not contain %q", joined, not)
				}
			}
		})
	}
}

func TestFormatCount(t *testing.T) {
	for n, want := range map[int]string{0: "0", 7: "7", 999: "999", 1000: "1,000", 54321: "54,321", 1000000: "1,000,000", -1234567: "-1,234,567"} {
		if got := formatCount(n); got != want {
			t.Errorf("formatCount(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestEvalLogsTheIndexSizeOfEveryImage(t *testing.T) {
	fake := &fakePackRunner{}
	_, _, stderr := captureCLIStreams(t, func() int {
		code := runEvalCommandWithDeps([]string{"--images", writeImageListFile(t, "x:1\n"), "--out-dir", t.TempDir()}, offlineCommandDeps(fake))
		if fake.options.OnIndexed == nil {
			t.Error("eval must pass an index observer to the runner")
		} else {
			fake.options.OnIndexed(runner.IndexReport{
				Image: "x:1", Source: spec.SourceLocalStore,
				Stats:    oci.IndexStats{Entries: 54321, Layers: 7, ScannedBytes: 12 << 20, EstimatedBytes: 31 << 20},
				Duration: 1234 * time.Millisecond,
			})
		}
		return code
	})
	want := "  INDEXED        54,321 entries | 7 layers | 12.0 MiB read | est. 31.0 MiB index memory | 1.234s"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr lacks the index line %q:\n%s", want, stderr)
	}
}
