package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Unclassified labels an image that has no entry in fixtures/archetypes.json.
const Unclassified = "unclassified"

// ArchetypeEntry is one value of fixtures/archetypes.json.
type ArchetypeEntry struct {
	Archetype  string `json:"archetype"`
	BaseFamily string `json:"base_family"`
}

// Archetypes maps a repository name without registry (for example "nginx") to
// its archetype and base family.
type Archetypes map[string]ArchetypeEntry

// LoadArchetypes reads fixtures/archetypes.json. A missing file returns an
// error that satisfies os.IsNotExist, so the caller can fall back to labeling
// every image as unclassified and say so.
func LoadArchetypes(path string) (Archetypes, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a Archetypes
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return a, nil
}

// Lookup returns the entry for an image reference. Unknown images, and a nil
// map, yield the unclassified label. There is no substring inference.
func (a Archetypes) Lookup(ref string) ArchetypeEntry {
	if e, ok := a[RepositoryName(ref)]; ok {
		if e.Archetype == "" {
			e.Archetype = Unclassified
		}
		if e.BaseFamily == "" {
			e.BaseFamily = Unclassified
		}
		return e
	}
	return ArchetypeEntry{Archetype: Unclassified, BaseFamily: Unclassified}
}

// splitRef splits an image reference into repository name and tag. The
// registry host, a leading "library/" and the digest are dropped.
//
//	index.docker.io/library/nginx@sha256:abc -> nginx, ""
//	docker.io/library/nginx:1.25             -> nginx, 1.25
//	mcr.microsoft.com/dotnet/runtime:8.0     -> dotnet/runtime, 8.0
//	bitnami/nginx                            -> bitnami/nginx, ""
func splitRef(ref string) (name, tag string) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	parts := strings.Split(ref, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		parts = parts[1:]
	}
	last := len(parts) - 1
	if i := strings.LastIndex(parts[last], ":"); i >= 0 {
		tag = parts[last][i+1:]
		parts[last] = parts[last][:i]
	}
	if len(parts) > 1 && parts[0] == "library" {
		parts = parts[1:]
	}
	return strings.Join(parts, "/"), tag
}

// RepositoryName returns the key used in fixtures/archetypes.json.
func RepositoryName(ref string) string {
	name, _ := splitRef(ref)
	return name
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]+`)

var digitWords = [...]string{"Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"}

// letterKey converts text into a letters-only CamelCase key. Every digit is
// spelled out, so "python3" becomes "PythonThree". LaTeX macro names may
// contain letters only.
func letterKey(text string) string {
	var sb strings.Builder
	for _, part := range nonAlnum.Split(text, -1) {
		first := true
		for _, r := range part {
			switch {
			case r >= '0' && r <= '9':
				sb.WriteString(digitWords[r-'0'])
			case unicode.IsLetter(r) && r < unicode.MaxASCII:
				if first {
					sb.WriteRune(unicode.ToUpper(r))
				} else {
					sb.WriteRune(unicode.ToLower(r))
				}
			}
			first = false
		}
	}
	return sb.String()
}

// MacroKey returns the letters-only key of an image reference: its repository
// name followed by its tag, when it has one.
func MacroKey(ref string) string {
	name, tag := splitRef(ref)
	return letterKey(name) + letterKey(tag)
}

// AssignMacroKeys returns a unique key per reference. When two references map
// to the same key, the later one in lexical order of the reference gets the
// spelled-out occurrence number appended ("Two", "Three", ...). The result
// does not depend on the order of refs.
func AssignMacroKeys(refs []string) map[string]string {
	sorted := append([]string(nil), refs...)
	sort.Strings(sorted)
	keys := make(map[string]string, len(refs))
	used := map[string]bool{}
	for _, ref := range sorted {
		if _, done := keys[ref]; done {
			continue
		}
		base := MacroKey(ref)
		if base == "" {
			base = "Image"
		}
		key := base
		for n := 2; used[key]; n++ {
			key = base + letterKey(fmt.Sprint(n))
		}
		used[key] = true
		keys[ref] = key
	}
	return keys
}
