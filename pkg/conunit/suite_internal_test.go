package conunit

import "testing"

func TestSuiteHasAssertions(t *testing.T) {
	tests := []struct {
		name  string
		suite *Suite
		want  bool
	}{
		{name: "empty suite", suite: &Suite{}, want: false},
		{name: "custom test", suite: &Suite{tests: []TestCaseDefinition{{ID: "TEST-01"}}}, want: true},
		{name: "rule pack", suite: &Suite{packs: []RulePack{&basePack{}}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.suite.hasAssertions(); got != test.want {
				t.Fatalf("hasAssertions() = %t, want %t", got, test.want)
			}
		})
	}
}
