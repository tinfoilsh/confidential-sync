package server

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
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
	yamlPaths := parseShimPaths(t, string(raw))

	have := ExternalRoutePaths()
	sort.Strings(have)
	got := append([]string(nil), yamlPaths...)
	sort.Strings(got)

	if !equalStrings(have, got) {
		t.Fatalf("shim.paths drift\n  in code only:  %v\n  in yaml only:  %v\n  code: %v\n  yaml: %v",
			diffSorted(have, got), diffSorted(got, have), have, got)
	}
}

func parseShimPaths(t *testing.T, body string) []string {
	t.Helper()
	lines := strings.Split(body, "\n")
	var (
		inShim  bool
		inPaths bool
		out     []string
	)
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !inShim {
			if trimmed == "shim:" {
				inShim = true
			}
			continue
		}
		if !inPaths {
			if trimmed == "paths:" {
				inPaths = true
			}
			continue
		}
		// A non-list line at any indentation ends the paths block.
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		out = append(out, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
	}
	if !inPaths {
		t.Fatal("could not find shim.paths block in tinfoil-config.yml")
	}
	return out
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
