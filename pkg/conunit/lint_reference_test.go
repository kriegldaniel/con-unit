package conunit

import (
	"strings"
	"testing"
)

func TestClassifyReference(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		ref      string
		wantKind referenceKind
		wantTag  string
		wantErr  bool
	}{
		{"alpine", referenceUntagged, "", false},
		{"alpine:3.20", referenceTag, "3.20", false},
		{"alpine:latest", referenceTag, "latest", false},
		{"docker.io/library/alpine:3.20", referenceTag, "3.20", false},
		{"localhost:5000/app", referenceUntagged, "", false},
		{"localhost:5000/app:v1", referenceTag, "v1", false},
		{"127.0.0.1:5000/team/app:v1", referenceTag, "v1", false},
		{"alpine@" + digest, referenceDigest, "", false},
		{"alpine:3.20@" + digest, referenceDigest, "3.20", false},
		{"alpine:latest@" + digest, referenceDigest, "latest", false},
		{digest, referenceImageID, "", false},
		{strings.Repeat("b", 64), referenceImageID, "", false},
		{"alpine:", "", "", true},
		{"alpine::3", "", "", true},
		{"", "", "", true},
		{"@" + digest, "", "", true},
		{"alpine@sha256:short", "", "", true},
		{"alpine@" + digest + "0", referenceDigest, "", false},
		{"Alpine", "", "", true},
		{"alpine:a b", "", "", true},
		{"alpine\t:1", "", "", true},
		{"alpine:" + strings.Repeat("t", 129), "", "", true},
		{"alpine:" + strings.Repeat("t", 128), referenceTag, strings.Repeat("t", 128), false},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			kind, tag, err := classifyReference(tc.ref)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if err == nil && (kind != tc.wantKind || tag != tc.wantTag) {
				t.Errorf("classifyReference(%q) = (%q, %q), want (%q, %q)", tc.ref, kind, tag, tc.wantKind, tc.wantTag)
			}
		})
	}
}

func FuzzClassifyReference(f *testing.F) {
	for _, seed := range []string{"", "a", "a:b", "a@b", "a:b@c", "@", ":", "a:b:c", "localhost:5000/x", "sha256:" + strings.Repeat("a", 64), "\x00", strings.Repeat("a/", 300)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, ref string) {
		kind, tag, err := classifyReference(ref)
		if err == nil && kind == "" {
			t.Fatalf("classifyReference(%q) gave neither a kind nor an error", ref)
		}
		if err == nil && kind == referenceUntagged && tag != "" {
			t.Fatalf("an untagged reference has no tag, got %q for %q", tag, ref)
		}
	})
}
