package conunit_test

import (
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

func envContainer(env ...string) *conunit.Container {
	return &conunit.Container{Inspect: &engine.ImageInspect{Config: engine.ImageConfig{Env: env}}}
}

// lintDisallowed and lintAccepted are the lists the lint pack gives SPEC-03.
var (
	lintDisallowed = []string{"PASS", "PASSWD", "PASSWORD", "SECRET", "KEY", "ACCESS", "TOKEN"}
	lintAccepted   = []string{"GPG_KEY", "GPG_KEYS"}
)

func TestSpec03AcceptedKeysParameter(t *testing.T) {
	const pemValue = "-----BEGIN RSA PRIVATE KEY-----"
	cases := []struct {
		name       string
		env        []string
		disallowed []string
		accepted   []string
		want       spec.Outcome
	}{
		// Backward compatibility: with no accepted keys the behavior is the
		// one DisallowedEnvKeys always had.
		{"default list flags PASSWORD", []string{"DB_PASSWORD=x"}, []string{"PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY"}, nil, spec.OutcomeFail},
		{"default list ignores a harmless variable", []string{"PATH=/usr/bin", "LANG=C"}, []string{"PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY"}, nil, spec.OutcomePass},
		{"name match is a case-insensitive substring", []string{"my_api_token=x"}, []string{"TOKEN"}, nil, spec.OutcomeFail},
		{"value pattern fails whatever the name", []string{"NOTE=AKIAABCDEFGHIJKLMNOP"}, []string{"PASSWORD"}, nil, spec.OutcomeFail},
		{"no environment passes", nil, lintDisallowed, nil, spec.OutcomePass},

		// The broader lint list.
		{"lint list flags KEY as a substring", []string{"SSH_KEY_PATH=/x"}, lintDisallowed, nil, spec.OutcomeFail},
		{"lint list flags ACCESS", []string{"ACCESS_LOG=/var/log/a"}, lintDisallowed, nil, spec.OutcomeFail},
		{"lint list flags PASS", []string{"PASSPHRASE=x"}, lintDisallowed, nil, spec.OutcomeFail},

		// Accepted keys.
		{"GPG_KEY is flagged without an accepted list", []string{"GPG_KEY=ABCDEF"}, lintDisallowed, nil, spec.OutcomeFail},
		{"GPG_KEY is accepted", []string{"GPG_KEY=ABCDEF"}, lintDisallowed, lintAccepted, spec.OutcomePass},
		{"GPG_KEYS is accepted", []string{"GPG_KEYS=A B C"}, lintDisallowed, lintAccepted, spec.OutcomePass},
		{"an accepted key does not exempt its neighbours", []string{"GPG_KEY=ABCDEF", "API_KEY=x"}, lintDisallowed, lintAccepted, spec.OutcomeFail},
		{"acceptance is exact: a longer name is still flagged", []string{"MY_GPG_KEY=ABCDEF"}, lintDisallowed, lintAccepted, spec.OutcomeFail},
		{"acceptance keeps the case", []string{"gpg_key=ABCDEF"}, lintDisallowed, lintAccepted, spec.OutcomeFail},
		{"an accepted key is still checked for credential values", []string{"GPG_KEY=" + pemValue}, lintDisallowed, lintAccepted, spec.OutcomeFail},
		{"an accepted key with an AWS access key value still fails", []string{"GPG_KEY=AKIAABCDEFGHIJKLMNOP"}, lintDisallowed, lintAccepted, spec.OutcomeFail},
		{"accepting a key that is not present changes nothing", []string{"DB_PASSWORD=x"}, lintDisallowed, lintAccepted, spec.OutcomeFail},
		{"an empty accepted slice behaves like nil", []string{"GPG_KEY=ABCDEF"}, lintDisallowed, []string{}, spec.OutcomeFail},
		{"variable without a value", []string{"GPG_KEY"}, lintDisallowed, lintAccepted, spec.OutcomePass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := envContainer(tc.env...)
			c.AssertSpec().DisallowedEnvKeysExcept(tc.accepted, tc.disallowed...)
			r := onlyResult(t, c)
			if r.TestID != "SPEC-03" || r.EffectiveOutcome() != tc.want {
				t.Fatalf("result = %s %s (%s), want %s", r.TestID, r.EffectiveOutcome(), r.Message, tc.want)
			}
		})
	}
}

// DisallowedEnvKeys is the entry point of every pack that existed before the
// accepted keys. It must give the same result as the new method with no
// accepted keys, for every input of the table.
func TestSpec03OldEntryPointEqualsTheNewOneWithoutAcceptedKeys(t *testing.T) {
	inputs := [][]string{
		nil,
		{"PATH=/usr/bin"},
		{"DB_PASSWORD=x"},
		{"GPG_KEY=ABCDEF"},
		{"A_TOKEN=1", "B_SECRET=2", "PATH=/bin"},
		{"X=ghp_" + strings.Repeat("a", 36)},
		{"Y=xoxb-" + strings.Repeat("1", 12)},
	}
	for _, env := range inputs {
		for _, keys := range [][]string{{"PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY"}, {"PASSWORD", "SECRET", "TOKEN", "AWS_SECRET"}, lintDisallowed, nil} {
			old, fresh := envContainer(env...), envContainer(env...)
			old.AssertSpec().DisallowedEnvKeys(keys...)
			fresh.AssertSpec().DisallowedEnvKeysExcept(nil, keys...)
			a, b := onlyResult(t, old), onlyResult(t, fresh)
			if a.EffectiveOutcome() != b.EffectiveOutcome() || a.Message != b.Message {
				t.Errorf("env %v keys %v: old %q, new %q", env, keys, a.Message, b.Message)
			}
		}
	}
}

func TestSpec03WithoutInspectDataIsUnverified(t *testing.T) {
	c := &conunit.Container{}
	c.AssertSpec().DisallowedEnvKeysExcept(lintAccepted, lintDisallowed...)
	r := onlyResult(t, c)
	if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonEvidenceIncomplete {
		t.Fatalf("result = %+v, want UNVERIFIED with EVIDENCE_INCOMPLETE", r)
	}
}

// The packs that existed before the accepted keys keep their lists. Their
// parameter text in the rule reference must not mention accepted keys.
func TestPreexistingPacksKeepTheirSpec03Lists(t *testing.T) {
	want := map[string]string{
		"PACK-CONUNIT-HARDENING": "disallowed keys: PASSWORD, SECRET, TOKEN, PRIVATE_KEY",
		"PACK-PROD-HYGIENE":      "disallowed keys: PASSWORD, SECRET, TOKEN, PRIVATE_KEY",
		"PACK-NIST-800-190":      "disallowed keys: PASSWORD, SECRET, TOKEN, AWS_SECRET",
	}
	for _, pack := range conunit.AllPacks() {
		expected, ok := want[pack.ID()]
		if !ok {
			continue
		}
		found := false
		for _, check := range pack.Checks() {
			if check.ID == "SPEC-03" {
				found = true
				if check.Params != expected {
					t.Errorf("%s SPEC-03 parameters = %q, want %q", pack.ID(), check.Params, expected)
				}
			}
		}
		if !found {
			t.Errorf("%s lost its SPEC-03 check", pack.ID())
		}
	}
}
