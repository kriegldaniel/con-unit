package main

import (
	"os"
	"regexp"
	"testing"
)

func TestRepositoryName(t *testing.T) {
	cases := map[string]string{
		"nginx":                        "nginx",
		"nginx:1.25":                   "nginx",
		"docker.io/library/nginx:1.25": "nginx",
		"index.docker.io/library/nginx@sha256:abc":      "nginx",
		"index.docker.io/library/python@sha256:abc":     "python",
		"python:3.12-alpine":                            "python",
		"bitnami/nginx:latest":                          "bitnami/nginx",
		"mcr.microsoft.com/dotnet/runtime:8.0":          "dotnet/runtime",
		"localhost/conunit-rq1/user-defect:rq1":         "conunit-rq1/user-defect",
		"registry.example.com:5000/team/app@sha256:abc": "team/app",
		"  alpine  ": "alpine",
	}
	for ref, want := range cases {
		if got := RepositoryName(ref); got != want {
			t.Errorf("RepositoryName(%q) = %q, want %q", ref, got, want)
		}
	}
}

var lettersOnly = regexp.MustCompile(`^[A-Za-z]+$`)

func TestMacroKey(t *testing.T) {
	cases := map[string]string{
		"index.docker.io/library/nginx@sha256:abc": "Nginx",
		"alpine:latest":                        "AlpineLatest",
		"python:3.12-alpine":                   "PythonThreeOneTwoAlpine",
		"docker.io/library/python3":            "PythonThree",
		"mcr.microsoft.com/dotnet/runtime:8.0": "DotnetRuntimeEightZero",
		"foo_bar-baz":                          "FooBarBaz",
	}
	for ref, want := range cases {
		got := MacroKey(ref)
		if got != want {
			t.Errorf("MacroKey(%q) = %q, want %q", ref, got, want)
		}
		if !lettersOnly.MatchString(got) {
			t.Errorf("MacroKey(%q) = %q contains characters other than letters", ref, got)
		}
	}
}

func TestAssignMacroKeysAreUniqueAndOrderIndependent(t *testing.T) {
	refs := []string{"foo-bar", "foo_bar", "foo.bar", "nginx@sha256:1", "nginx@sha256:2", "alpine"}
	a := AssignMacroKeys(refs)
	rev := []string{refs[5], refs[4], refs[3], refs[2], refs[1], refs[0]}
	b := AssignMacroKeys(rev)
	seen := map[string]string{}
	for _, ref := range refs {
		key := a[ref]
		if !lettersOnly.MatchString(key) {
			t.Errorf("key %q for %q is not letters only", key, ref)
		}
		if other, dup := seen[key]; dup {
			t.Errorf("key %q assigned to both %q and %q", key, other, ref)
		}
		seen[key] = ref
		if b[ref] != key {
			t.Errorf("key for %q depends on input order: %q versus %q", ref, key, b[ref])
		}
	}
	if len(a) != len(refs) {
		t.Errorf("keys = %d, want %d", len(a), len(refs))
	}
}

func TestArchetypeLookupIsExplicitNotInferred(t *testing.T) {
	a, err := LoadArchetypes("testdata/archetypes.json")
	if err != nil {
		t.Fatal(err)
	}
	// The old substring inference labeled every -alpine image "Minimal OS".
	got := a.Lookup("docker.io/library/python:3.12-alpine")
	if got.Archetype != "language-runtime" || got.BaseFamily != "debian" {
		t.Errorf("python:3.12-alpine = %+v, want the python entry", got)
	}
	if got := a.Lookup("index.docker.io/library/alpine@sha256:abc"); got.Archetype != "base-os" {
		t.Errorf("alpine = %+v", got)
	}
	for _, ref := range []string{"myalpine-tool:1", "slim-thing", "unknown/postgres-fork"} {
		got := a.Lookup(ref)
		if got.Archetype != Unclassified || got.BaseFamily != Unclassified {
			t.Errorf("Lookup(%q) = %+v, want unclassified", ref, got)
		}
	}
}

func TestArchetypesAbsentFileLabelsUnclassified(t *testing.T) {
	_, err := LoadArchetypes("testdata/does-not-exist.json")
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("a missing file must report not-exist, got %v", err)
	}
	var none Archetypes
	if got := none.Lookup("nginx"); got.Archetype != Unclassified {
		t.Errorf("nil table lookup = %+v", got)
	}
}

func TestArchetypeEntryWithEmptyFieldsIsUnclassified(t *testing.T) {
	a := Archetypes{"x": {Archetype: "", BaseFamily: "alpine"}}
	got := a.Lookup("x")
	if got.Archetype != Unclassified || got.BaseFamily != "alpine" {
		t.Errorf("got %+v", got)
	}
}
