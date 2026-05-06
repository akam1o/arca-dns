package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/health"
	zonesync "github.com/akam1o/arca-dns/internal/agent/sync"
	"github.com/akam1o/arca-dns/pkg/config"
	"go.uber.org/zap"
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

func TestStatusRouter_HealthAvailableWhenMetricsDisabled(t *testing.T) {
	router := newTestStatusRouter(config.MetricsConfig{
		Enabled: false,
		Path:    "/metrics",
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /health status=%d, want %d", resp.Code, http.StatusOK)
	}

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics status=%d, want %d", resp.Code, http.StatusNotFound)
	}
}

func TestStatusRouter_MetricsEnabledUsesConfiguredPath(t *testing.T) {
	router := newTestStatusRouter(config.MetricsConfig{
		Enabled: true,
		Path:    "/scrape",
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/scrape", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /scrape status=%d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "arca_dns_agent_sync_has_success") {
		t.Fatalf("GET /scrape response did not contain agent metrics")
	}

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics status=%d, want %d", resp.Code, http.StatusNotFound)
	}
}

func newTestStatusRouter(metrics config.MetricsConfig) http.Handler {
	logger := zap.NewNop()
	cfg := &config.AgentConfig{
		Metrics: metrics,
	}
	syncer := zonesync.NewSyncer(nil, nil, config.SyncConfig{
		MaxStaleness: time.Hour,
	}, logger)
	checker := health.NewCheckerWithOptions(config.HealthConfig{
		QueryTimeout: time.Millisecond,
	}, health.CheckerOptions{}, logger)
	return newStatusRouter(cfg, syncer, checker, nil, nil, logger)
}
