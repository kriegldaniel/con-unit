package engine

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestImageConfigDecodesDeclaredVolumes(t *testing.T) {
	cases := []struct {
		name string
		json string
		want []string
	}{
		{"two volumes", `{"Config":{"Volumes":{"/data":{},"/var/log":{}}}}`, []string{"/data", "/var/log"}},
		{"null volumes as podman and docker print them", `{"Config":{"Volumes":null}}`, nil},
		{"no volumes key", `{"Config":{"User":"1000"}}`, nil},
		{"empty object", `{"Config":{"Volumes":{}}}`, nil},
		{"a volume path with a trailing slash is kept as given", `{"Config":{"Volumes":{"/proc/":{}}}}`, []string{"/proc/"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var inspect ImageInspect
			if err := json.Unmarshal([]byte(tc.json), &inspect); err != nil {
				t.Fatalf("decode: %v", err)
			}
			var got []string
			for volume := range inspect.Config.Volumes {
				got = append(got, volume)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("volumes = %v, want %v", got, tc.want)
			}
		})
	}
}
