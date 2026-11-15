package main

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// contractMapping is the mapping of docs/INTERFACE_V2.md section 5, in the
// order of that text.
var contractMapping = []struct {
	check string
	codes []string
}{
	{"SPEC-01", []string{"CIS-DI-0001"}},
	{"CIS-4.6", []string{"CIS-DI-0006"}},
	{"FS-04", []string{"CIS-DI-0008"}},
	{"SPEC-07", []string{"CIS-DI-0009"}},
	{"SPEC-03", []string{"CIS-DI-0010"}},
	{"FS-06", []string{"CIS-DI-0010"}},
	{"FS-12", []string{"CIS-DI-0010"}},
	{"FS-08", []string{"DKL-LI-0001"}},
	{"SPEC-09", []string{"CIS-DI-0007"}},
	{"SPEC-10", []string{"DKL-DI-0001"}},
	{"SPEC-11", []string{"DKL-DI-0003"}},
	{"SPEC-12", []string{"DKL-DI-0002"}},
	{"SPEC-13", []string{"DKL-DI-0006"}},
	{"FS-10", []string{"DKL-LI-0002"}},
	{"FS-11", []string{"DKL-LI-0003"}},
	{"FS-01", []string{"DKL-DI-0004", "DKL-DI-0005"}},
}

func TestMappingMatchesTheContract(t *testing.T) {
	got := Mappings()
	if len(got) != len(contractMapping) {
		t.Fatalf("%d mappings, the contract fixes %d", len(got), len(contractMapping))
	}
	for i, want := range contractMapping {
		if got[i].Check != want.check || !reflect.DeepEqual(got[i].Codes, want.codes) {
			t.Errorf("mapping %d = %s -> %v, want %s -> %v", i, got[i].Check, got[i].Codes, want.check, want.codes)
		}
	}
}

func TestMappingKeysAreLettersOnlyAndUnique(t *testing.T) {
	letters := regexp.MustCompile(`^[A-Za-z]+$`)
	seen := map[string]string{}
	for _, m := range Mappings() {
		k := m.Key()
		if !letters.MatchString(k) {
			t.Errorf("key %q of %s is not letters only", k, m.Check)
		}
		if other, dup := seen[k]; dup {
			t.Errorf("%s and %s share the key %q", m.Check, other, k)
		}
		seen[k] = m.Check
	}
	for check, want := range map[string]string{"SPEC-09": "SPECZeroNine", "FS-10": "FSOneZero", "CIS-4.6": "CISFourSix", "SPEC-13": "SPECOneThree"} {
		m, ok := MappingFor(check)
		if !ok || m.Key() != want {
			t.Errorf("key of %s = %q, want %q", check, m.Key(), want)
		}
	}
}

func TestOnlyLatestTagIsNotComparable(t *testing.T) {
	for _, m := range Mappings() {
		if m.Check == "SPEC-13" {
			if m.Comparable() || !strings.Contains(m.NotComparable, "DKL-DI-0006") || !strings.Contains(m.NotComparable, "--input") {
				t.Errorf("SPEC-13 must be not comparable with the reason: %+v", m)
			}
			continue
		}
		if !m.Comparable() {
			t.Errorf("%s must be comparable", m.Check)
		}
	}
}

func TestMappedCodesAreImageLevelCatalogCodes(t *testing.T) {
	catalog := map[string]Checkpoint{}
	for _, c := range DockleCatalog() {
		catalog[c.Code] = c
	}
	for _, m := range Mappings() {
		for _, code := range m.Codes {
			c, ok := catalog[code]
			if !ok {
				t.Errorf("%s maps to %s, which is not in the Dockle catalog", m.Check, code)
				continue
			}
			if c.Status != StatusImage {
				t.Errorf("%s maps to %s, whose status is %s, not an image-level checkpoint", m.Check, code, c.Status)
			}
			if IsExcluded(code) {
				t.Errorf("%s maps to the excluded code %s", m.Check, code)
			}
		}
	}
}

func TestEveryImageLevelCheckpointHasAMappedCheck(t *testing.T) {
	mapped := MappedCodes()
	for _, c := range DockleCatalog() {
		if c.Status == StatusImage && !mapped[c.Code] {
			t.Errorf("the image-level checkpoint %s has no ConUnit check in the mapping", c.Code)
		}
	}
}

func TestCatalogHasTheDocumentedCheckpoints(t *testing.T) {
	var cis, di, li int
	var codes []string
	for _, c := range DockleCatalog() {
		codes = append(codes, c.Code)
		switch {
		case strings.HasPrefix(c.Code, "CIS-DI-"):
			cis++
		case strings.HasPrefix(c.Code, "DKL-DI-"):
			di++
		case strings.HasPrefix(c.Code, "DKL-LI-"):
			li++
		default:
			t.Errorf("unexpected code %s", c.Code)
		}
		if c.Short == "" || c.Note == "" {
			t.Errorf("%s needs a descriptor and a source note", c.Code)
		}
		if (c.Status == StatusImage || c.Status == StatusHostEnvironment) && c.Default == "" {
			t.Errorf("%s is emitted, so it needs a default level", c.Code)
		}
		if (c.Status == StatusNoCodePath || c.Status == StatusNotSupported) && c.Default != "" {
			t.Errorf("%s is never emitted, so it has no default level", c.Code)
		}
	}
	if cis != 11 || di != 6 || li != 3 {
		t.Errorf("catalog holds %d CIS-DI, %d DKL-DI, %d DKL-LI; Dockle v%s documents 11, 6 and 3", cis, di, li, VerifiedDockleVersion)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("code %s is listed twice", c)
		}
		seen[c] = true
	}
}

// TestCatalogLevelsAreThoseOfTheSource compares the default levels with
// DefaultLevelMap of pkg/types/checkpoint.go of Dockle v0.4.15.
func TestCatalogLevelsAreThoseOfTheSource(t *testing.T) {
	source := map[string]string{
		"CIS-DI-0001": "WARN", "CIS-DI-0005": "INFO", "CIS-DI-0006": "INFO", "CIS-DI-0007": "FATAL",
		"CIS-DI-0008": "INFO", "CIS-DI-0009": "FATAL", "CIS-DI-0010": "FATAL",
		"DKL-DI-0001": "FATAL", "DKL-DI-0002": "FATAL", "DKL-DI-0003": "WARN",
		"DKL-DI-0004": "FATAL", "DKL-DI-0005": "FATAL", "DKL-DI-0006": "WARN",
		"DKL-LI-0001": "FATAL", "DKL-LI-0002": "FATAL", "DKL-LI-0003": "INFO",
	}
	emitted := 0
	for _, c := range DockleCatalog() {
		if c.Default == "" {
			continue
		}
		emitted++
		if source[c.Code] != c.Default {
			t.Errorf("%s: default level %s, source says %s", c.Code, c.Default, source[c.Code])
		}
	}
	if emitted != len(source) {
		t.Errorf("%d emitted checkpoints, the source has %d", emitted, len(source))
	}
}

func TestExcludedAndUncoveredCodes(t *testing.T) {
	var excluded []string
	for _, e := range ExcludedCodes() {
		excluded = append(excluded, e.Code)
		if e.Reason == "" {
			t.Errorf("%s is excluded without a reason", e.Code)
		}
	}
	if !reflect.DeepEqual(excluded, []string{"CIS-DI-0002", "CIS-DI-0005"}) {
		t.Errorf("excluded = %v, want CIS-DI-0002 and CIS-DI-0005", excluded)
	}
	var uncovered []string
	for _, u := range UncoveredCodes() {
		uncovered = append(uncovered, u.Code)
		if u.Reason == "" {
			t.Errorf("%s is listed without a reason", u.Code)
		}
	}
	want := []string{"CIS-DI-0002", "CIS-DI-0003", "CIS-DI-0004", "CIS-DI-0005", "CIS-DI-0011"}
	if !reflect.DeepEqual(uncovered, want) {
		t.Errorf("codes without a ConUnit counterpart = %v, want %v", uncovered, want)
	}
	if !IsExcluded("CIS-DI-0005") || IsExcluded("CIS-DI-0001") || IsExcluded("") {
		t.Error("IsExcluded is wrong")
	}
	if !KnownCode("DKL-DI-0006") || KnownCode("DKL-DI-0099") {
		t.Error("KnownCode is wrong")
	}
}

func TestIntendedDifferencesAreWellFormed(t *testing.T) {
	for _, m := range Mappings() {
		explained := 0
		for dir, d := range map[string]Difference{"only ConUnit": m.OnlyConUnit, "only Dockle": m.OnlyDockle} {
			if d.Text == "" && d.Short == "" {
				continue
			}
			explained++
			if d.Text == "" || d.Short == "" {
				t.Errorf("%s %s: both the short and the full text are needed", m.Check, dir)
			}
			if len(d.Short) > 48 {
				t.Errorf("%s %s: the short text has %d characters, the table column is narrow", m.Check, dir, len(d.Short))
			}
			if !strings.HasSuffix(d.Text, ".") {
				t.Errorf("%s %s: the text must be a full sentence ending with a period", m.Check, dir)
			}
			for _, r := range d.Text + d.Short {
				if r > 126 {
					t.Errorf("%s %s: non-ASCII character %q", m.Check, dir, r)
					break
				}
			}
			// A flag such as --no-cache is fine; a double dash used as punctuation is not.
			if strings.Contains(d.Text, " -- ") || strings.Contains(d.Short, " -- ") {
				t.Errorf("%s %s: no sentences built around double dashes", m.Check, dir)
			}
		}
		if m.Comparable() && explained == 0 {
			t.Errorf("%s has no intended difference in either direction", m.Check)
		}
		if !m.Comparable() && explained != 0 {
			t.Errorf("%s is not comparable, so it cannot have discordances to explain", m.Check)
		}
	}
}

func TestFacetOfAlert(t *testing.T) {
	cases := []struct {
		alert string
		want  string
	}{
		{"Suspicious ENV key found : DB_PASSWORD on /bin/sh -c #(nop) ENV DB_PASSWORD=******* (You can suppress it with --accept-key)", FacetEnv},
		{"Suspicious filename found : app/id_rsa (You can suppress it with \"-af id_rsa\")", FacetFile},
		{"Suspicious file extension found : x/y.ovpn (You can suppress it with \"-ae ovpn\")", FacetFile},
		{"  Suspicious filename found : x", FacetFile},
		{"something else", FacetNone},
		{"", FacetNone},
	}
	for _, tc := range cases {
		if got := FacetOfAlert(tc.alert); got != tc.want {
			t.Errorf("FacetOfAlert(%q) = %q, want %q", tc.alert, got, tc.want)
		}
	}
}

func TestOnlyCredentialChecksCarryAFacet(t *testing.T) {
	for _, m := range Mappings() {
		hasFacet := m.Facet != FacetNone
		shared := len(m.Codes) == 1 && m.Codes[0] == "CIS-DI-0010"
		if hasFacet != shared {
			t.Errorf("%s: facet %q with codes %v; exactly the checks of CIS-DI-0010 need a facet", m.Check, m.Facet, m.Codes)
		}
	}
	for check, want := range map[string]string{"SPEC-03": FacetEnv, "FS-06": FacetFile, "FS-12": FacetFile} {
		if m, _ := MappingFor(check); m.Facet != want {
			t.Errorf("%s facet = %q, want %q", check, m.Facet, want)
		}
	}
}

func TestApplicabilityOfDocumentedDifferences(t *testing.T) {
	fileAlert := func(path string) string {
		return "CIS-DI-0010 FATAL: Suspicious filename found : " + path + " (You can suppress it with \"-af x\")"
	}
	cases := []struct {
		name string
		fn   func(conunit, dockle string) bool
		in   string
		want bool
	}{
		{"FS-11 below node_modules", underDependencyDirectory, "DKL-LI-0003 INFO: unnecessary file : app/node_modules/x/Dockerfile ", true},
		{"FS-11 below vendor", underDependencyDirectory, "DKL-LI-0003 INFO: unnecessary file : go/vendor/y/Dockerfile ", true},
		{"FS-11 in an ordinary directory is not explained", underDependencyDirectory, "DKL-LI-0003 INFO: unnecessary file : app/Dockerfile ", false},
		{"FS-11 with no alert", underDependencyDirectory, "", false},

		{"FS-12 below tests", onlyFixtureLikeCredentialPaths, fileAlert("/opt/app/tests/id_rsa"), true},
		{"FS-12 below testdata, relative path", onlyFixtureLikeCredentialPaths, fileAlert("lib/testdata/id_rsa"), true},
		{"FS-12 below fixtures and example", onlyFixtureLikeCredentialPaths, fileAlert("a/fixtures/b/example/id_dsa"), true},
		{"FS-12 outside any fixture directory is not explained", onlyFixtureLikeCredentialPaths, fileAlert("app/id_rsa"), false},
		{"FS-12 at the root is not explained", onlyFixtureLikeCredentialPaths, fileAlert("id_rsa"), false},
		{"FS-12 one fixture path and one real path is not explained", onlyFixtureLikeCredentialPaths, fileAlert("t/tests/id_rsa") + "; " + fileAlert("home/app/id_rsa"), false},
		{"FS-12 two fixture paths", onlyFixtureLikeCredentialPaths, fileAlert("t/tests/id_rsa") + "; " + fileAlert("x/examples/id_ecdsa"), true},
		{"FS-12 a similar component name is not a fixture directory", onlyFixtureLikeCredentialPaths, fileAlert("app/latest/id_rsa"), false},
		{"FS-12 a file that is named test is not a fixture directory", onlyFixtureLikeCredentialPaths, fileAlert("app/test"), false},
		{"FS-12 an extension alert is read the same way", onlyFixtureLikeCredentialPaths, "CIS-DI-0010 FATAL: Suspicious file extension found : src/tests/vpn.ovpn (You can suppress it with \"-ae ovpn\")", true},
		{"FS-12 an alert that names no path is not explained", onlyFixtureLikeCredentialPaths, "CIS-DI-0010 FATAL: Suspicious ENV key found : X on y", false},

		{"SPEC-07 a real legacy ADD is not explained", notAnADDInstruction, "CIS-DI-0009 FATAL: Use COPY : /bin/sh -c #(nop) ADD file:abc in /file.txt   ", false},
		{"SPEC-07 a real BuildKit ADD is not explained", notAnADDInstruction, "CIS-DI-0009 FATAL: Use COPY : ADD file:abc in /x # buildkit", false},
		{"SPEC-07 a RUN line with the words is explained", notAnADDInstruction, "CIS-DI-0009 FATAL: Use COPY : /bin/sh -c echo ADD in the log", true},
		{"SPEC-07 a BuildKit RUN line with the words is explained", notAnADDInstruction, "CIS-DI-0009 FATAL: Use COPY : RUN /bin/sh -c echo ADD in x # buildkit", true},
		{"SPEC-07 no alert", notAnADDInstruction, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn("", tc.in); got != tc.want {
				t.Errorf("applies = %v, want %v for %q", got, tc.want, tc.in)
			}
		})
	}
}

func TestOnlyThreeDifferencesCarryAnApplicabilityCheck(t *testing.T) {
	want := map[string]string{"SPEC-07": "only dockle", "FS-12": "only dockle", "FS-11": "only dockle"}
	got := map[string]string{}
	for _, m := range Mappings() {
		if m.OnlyConUnit.Applies != nil {
			got[m.Check] = "only conunit"
		}
		if m.OnlyDockle.Applies != nil {
			got[m.Check] = "only dockle"
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("checks with an applicability check = %v, want %v", got, want)
	}
}
