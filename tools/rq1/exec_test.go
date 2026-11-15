package main

import (
	"reflect"
	"testing"
)

func TestBuildEnv(t *testing.T) {
	base := []string{"PATH=/bin", "DOCKLE_IGNORES=CIS-DI-0001", "DOCKLE_ACCEPT_KEYS=GPG_KEY", "DOCKER_HOST=unix:///x", "HOME=/h", "NODOCKLE_X=1", "DOCKLE=1"}
	cases := []struct {
		name          string
		unsetPrefixes []string
		extra         []string
		want          []string
	}{
		{
			name:          "removes every variable with the prefix",
			unsetPrefixes: []string{"DOCKLE_"},
			want:          []string{"PATH=/bin", "DOCKER_HOST=unix:///x", "HOME=/h", "NODOCKLE_X=1", "DOCKLE=1"},
		},
		{
			name:          "a prefix needs the underscore, DOCKLE and NODOCKLE_X stay",
			unsetPrefixes: []string{"DOCKLE_"},
			extra:         nil,
			want:          []string{"PATH=/bin", "DOCKER_HOST=unix:///x", "HOME=/h", "NODOCKLE_X=1", "DOCKLE=1"},
		},
		{
			name:          "extra entries are added after the removal",
			unsetPrefixes: []string{"DOCKLE_"},
			extra:         []string{"DOCKLE_IGNORES=again"},
			want:          []string{"PATH=/bin", "DOCKER_HOST=unix:///x", "HOME=/h", "NODOCKLE_X=1", "DOCKLE=1", "DOCKLE_IGNORES=again"},
		},
		{
			name:          "several prefixes",
			unsetPrefixes: []string{"DOCKLE_", "DOCKER_"},
			want:          []string{"PATH=/bin", "HOME=/h", "NODOCKLE_X=1", "DOCKLE=1"},
		},
		{
			name:          "an empty prefix removes nothing",
			unsetPrefixes: []string{""},
			want:          base,
		},
		{name: "no prefixes", want: base},
		{name: "extra only", extra: []string{"A=1"}, want: append(append([]string{}, base...), "A=1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string{}, base...)
			got := buildEnv(base, tc.unsetPrefixes, tc.extra)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("env = %v, want %v", got, tc.want)
			}
			if !reflect.DeepEqual(base, before) {
				t.Error("buildEnv must not modify its input")
			}
		})
	}
	// An entry without an equals sign is a name only.
	if got := buildEnv([]string{"DOCKLE_BARE", "KEEP"}, []string{"DOCKLE_"}, nil); !reflect.DeepEqual(got, []string{"KEEP"}) {
		t.Errorf("bare names: %v", got)
	}
}

func TestEnvNamesWithPrefix(t *testing.T) {
	env := []string{"DOCKLE_TIMEOUT=5s", "PATH=/bin", "DOCKLE_ACCEPT_KEYS=SECRET_VALUE", "DOCKLE_BARE", "XDOCKLE_A=1"}
	got := envNamesWithPrefix(env, "DOCKLE_")
	want := []string{"DOCKLE_ACCEPT_KEYS", "DOCKLE_BARE", "DOCKLE_TIMEOUT"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("names = %v, want %v", got, want)
	}
	for _, name := range got {
		if name != "DOCKLE_ACCEPT_KEYS" && name != "DOCKLE_BARE" && name != "DOCKLE_TIMEOUT" {
			t.Errorf("unexpected entry %q: values must never be returned", name)
		}
	}
	if got := envNamesWithPrefix(env, ""); got != nil {
		t.Errorf("an empty prefix matches nothing, got %v", got)
	}
	if got := envNamesWithPrefix(nil, "DOCKLE_"); got != nil {
		t.Errorf("no environment: %v", got)
	}
}
