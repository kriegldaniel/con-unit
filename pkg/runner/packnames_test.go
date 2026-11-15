package runner_test

import (
	"sort"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/runner"
)

// The rule reference and the help text name the values that --pack accepts.
// Every one of them must resolve to the pack it is documented for. "hardening"
// was advertised before ResolvePack accepted it.
func TestEveryDocumentedPackNameResolvesToItsPack(t *testing.T) {
	documented := conunit.PackFlagNames
	if len(documented) != len(conunit.AllPacks()) {
		t.Fatalf("%d packs have documented names, but %d packs ship", len(documented), len(conunit.AllPacks()))
	}
	for packID, names := range documented {
		for _, name := range names {
			pack, err := runner.ResolvePack(name)
			if err != nil {
				t.Errorf("--pack %s (documented for %s) does not resolve: %v", name, packID, err)
				continue
			}
			if pack.ID() != packID {
				t.Errorf("--pack %s resolves to %s, documented for %s", name, pack.ID(), packID)
			}
		}
	}
}

func TestResolvePackErrorListsTheDocumentedNames(t *testing.T) {
	_, err := runner.ResolvePack("nope")
	if err == nil {
		t.Fatal("an unknown pack must be rejected")
	}
	var primary []string
	for _, names := range conunit.PackFlagNames {
		primary = append(primary, names[0])
	}
	sort.Strings(primary)
	for _, name := range primary {
		if !contains(err.Error(), name) {
			t.Errorf("the error %q does not offer %q", err.Error(), name)
		}
	}
}

func contains(text, part string) bool {
	for i := 0; i+len(part) <= len(text); i++ {
		if text[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
