package server

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestShimPathsMatchRoutes pins ExternalRoutePaths against
// tinfoil-config.yml#shim.paths. The Tinfoil CVM shim blocks any
// path not listed in the YAML, so a drift between the two lists
// either silently 404s a real handler in production (path in code
// but not YAML) or advertises a non-existent path (path in YAML
// but not code). Catching this at test time turns a deploy-only
// failure mode into a compile-time-equivalent check.
func TestShimPathsMatchRoutes(t *testing.T) {
	cfgPath := repoRelative(t, "tinfoil-config.yml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read %s: %v", cfgPath, err)
	}
	yamlPaths := parseShimPaths(t, raw)

	have := ExternalRoutePaths()
	sort.Strings(have)
	got := append([]string(nil), yamlPaths...)
	sort.Strings(got)

	if !equalStrings(have, got) {
		t.Fatalf("shim.paths drift\n  in code only:  %v\n  in yaml only:  %v\n  code: %v\n  yaml: %v",
			diffSorted(have, got), diffSorted(got, have), have, got)
	}
}

// shimConfig captures only the fields this test cares about.
// Unknown keys are ignored by yaml.v3's Unmarshal, so adding new
// top-level sections to tinfoil-config.yml won't break the parser.
type shimConfig struct {
	Shim struct {
		Paths []string `yaml:"paths"`
	} `yaml:"shim"`
}

func parseShimPaths(t *testing.T, body []byte) []string {
	t.Helper()
	var cfg shimConfig
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal tinfoil-config.yml: %v", err)
	}
	if len(cfg.Shim.Paths) == 0 {
		t.Fatal("tinfoil-config.yml has empty shim.paths")
	}
	return cfg.Shim.Paths
}

func repoRelative(t *testing.T, rel string) string {
	t.Helper()
	// internal/server -> repo root is two parents up.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..", rel)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func diffSorted(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	var only []string
	for _, s := range a {
		if _, ok := set[s]; !ok {
			only = append(only, s)
		}
	}
	return only
}
