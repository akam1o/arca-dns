package main

import (
	"errors"
	"strings"
	"testing"
)

func TestReexecSelf_UsesExecutableAsArgv0(t *testing.T) {
	origExec := execFn
	t.Cleanup(func() { execFn = origExec })

	var gotPath string
	var gotArgv []string
	execFn = func(path string, argv []string, env []string) error {
		gotPath = path
		gotArgv = append([]string(nil), argv...)
		return errors.New("exec called")
	}

	err := reexecSelf()
	if err == nil || !strings.Contains(err.Error(), "exec called") {
		t.Fatalf("expected injected exec error, got %v", err)
	}
	if gotPath == "" {
		t.Fatalf("expected exec path to be set")
	}
	if len(gotArgv) == 0 {
		t.Fatalf("expected argv to be set")
	}
	if gotArgv[0] != gotPath {
		t.Fatalf("expected argv[0]==path, got argv[0]=%q path=%q", gotArgv[0], gotPath)
	}
}

func TestMetricPath(t *testing.T) {
	tests := map[string]string{
		"":                "/metrics",
		"metrics":         "/metrics",
		"/custom-metrics": "/custom-metrics",
		"  scrape  ":      "/scrape",
	}

	for input, want := range tests {
		if got := metricPath(input); got != want {
			t.Fatalf("metricPath(%q)=%q, want %q", input, got, want)
		}
	}
}
