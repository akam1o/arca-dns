package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/health"
	"github.com/akam1o/arca-dns/internal/agent/plugin"
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

func TestNewStatusServer_HasTimeouts(t *testing.T) {
	server := newTestStatusServer(config.MetricsConfig{
		Listen:  "127.0.0.1:0",
		Enabled: true,
		Path:    "/metrics",
	})

	if server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout=%s, want 5s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 15*time.Second {
		t.Fatalf("ReadTimeout=%s, want 15s", server.ReadTimeout)
	}
	if server.WriteTimeout != 15*time.Second {
		t.Fatalf("WriteTimeout=%s, want 15s", server.WriteTimeout)
	}
	if server.IdleTimeout != 60*time.Second {
		t.Fatalf("IdleTimeout=%s, want 60s", server.IdleTimeout)
	}
}

func TestStartStatusServer_ReturnsBindError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test socket: %v", err)
	}
	defer listener.Close()

	logger := zap.NewNop()
	cfg := &config.AgentConfig{
		Metrics: config.MetricsConfig{
			Listen:  listener.Addr().String(),
			Enabled: true,
			Path:    "/metrics",
		},
	}
	syncer := zonesync.NewSyncer(nil, nil, config.SyncConfig{
		MaxStaleness: time.Hour,
	}, logger)
	checker := health.NewCheckerWithOptions(config.HealthConfig{
		QueryTimeout: time.Millisecond,
	}, health.CheckerOptions{}, logger)

	server, err := startStatusServer(cfg, syncer, checker, nil, nil, logger)
	if err == nil {
		if server != nil {
			_ = server.Close()
		}
		t.Fatalf("expected bind error")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Fatalf("expected listen error, got %v", err)
	}
}

func TestDeleteZoneServiceReferences_RollsBackWhenResolverReloadFails(t *testing.T) {
	authServer := newFakeAuthoritativeServer()
	resolver := newFakeResolver()
	resolver.failAt["reload"] = 1
	resolver.failErr["reload"] = errors.New("reload failed")

	err := deleteZoneServiceReferences(context.Background(), "example.com.", authServer, resolver, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("expected resolver reload error, got %v", err)
	}

	wantAuthCalls := "delete,ensure,reload-zone"
	if got := strings.Join(authServer.calls, ","); got != wantAuthCalls {
		t.Fatalf("auth calls = %s, want %s", got, wantAuthCalls)
	}

	wantResolverCalls := "delete-stub,check,reload,update-stub,check,reload"
	if got := strings.Join(resolver.calls, ","); got != wantResolverCalls {
		t.Fatalf("resolver calls = %s, want %s", got, wantResolverCalls)
	}
}

func TestDeleteZoneServiceReferences_RollsBackAuthoritativeWhenStubDeleteFails(t *testing.T) {
	authServer := newFakeAuthoritativeServer()
	resolver := newFakeResolver()
	resolver.failAt["delete-stub"] = 1
	resolver.failErr["delete-stub"] = errors.New("delete stub failed")

	err := deleteZoneServiceReferences(context.Background(), "example.com.", authServer, resolver, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "delete stub failed") {
		t.Fatalf("expected resolver delete error, got %v", err)
	}

	wantAuthCalls := "delete,ensure,reload-zone"
	if got := strings.Join(authServer.calls, ","); got != wantAuthCalls {
		t.Fatalf("auth calls = %s, want %s", got, wantAuthCalls)
	}

	wantResolverCalls := "delete-stub"
	if got := strings.Join(resolver.calls, ","); got != wantResolverCalls {
		t.Fatalf("resolver calls = %s, want %s", got, wantResolverCalls)
	}
}

func TestDeleteZoneServiceReferences_RollsBackAuthoritativeWhenDeleteFails(t *testing.T) {
	authServer := newFakeAuthoritativeServer()
	resolver := newFakeResolver()
	authServer.failAt["delete"] = 1
	authServer.failErr["delete"] = errors.New("delete authoritative failed")

	err := deleteZoneServiceReferences(context.Background(), "example.com.", authServer, resolver, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "delete authoritative failed") {
		t.Fatalf("expected authoritative delete error, got %v", err)
	}

	wantAuthCalls := "delete,ensure,reload-zone"
	if got := strings.Join(authServer.calls, ","); got != wantAuthCalls {
		t.Fatalf("auth calls = %s, want %s", got, wantAuthCalls)
	}
	if got := strings.Join(resolver.calls, ","); got != "" {
		t.Fatalf("resolver calls = %s, want empty", got)
	}
}

type fakeAuthoritativeServer struct {
	calls   []string
	counts  map[string]int
	failAt  map[string]int
	failErr map[string]error
}

func newFakeAuthoritativeServer() *fakeAuthoritativeServer {
	return &fakeAuthoritativeServer{
		counts:  map[string]int{},
		failAt:  map[string]int{},
		failErr: map[string]error{},
	}
}

func (f *fakeAuthoritativeServer) call(method string) error {
	f.calls = append(f.calls, method)
	f.counts[method]++
	if f.failAt[method] == f.counts[method] {
		return f.failErr[method]
	}
	return nil
}

func (f *fakeAuthoritativeServer) EnsureZone(context.Context, string) error { return f.call("ensure") }
func (f *fakeAuthoritativeServer) ReloadZone(context.Context, string) error {
	return f.call("reload-zone")
}
func (f *fakeAuthoritativeServer) CheckZone(context.Context, string, string) error {
	return f.call("check-zone")
}
func (f *fakeAuthoritativeServer) DeleteZone(context.Context, string) error { return f.call("delete") }
func (f *fakeAuthoritativeServer) Reload(context.Context) error             { return f.call("reload") }
func (f *fakeAuthoritativeServer) Status(context.Context) (plugin.ServerStatus, error) {
	return plugin.ServerStatus{}, nil
}
func (f *fakeAuthoritativeServer) Type() string { return "fake" }

type fakeResolver struct {
	calls   []string
	counts  map[string]int
	failAt  map[string]int
	failErr map[string]error
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		counts:  map[string]int{},
		failAt:  map[string]int{},
		failErr: map[string]error{},
	}
}

func (f *fakeResolver) call(method string) error {
	f.calls = append(f.calls, method)
	f.counts[method]++
	if f.failAt[method] == f.counts[method] {
		return f.failErr[method]
	}
	return nil
}

func (f *fakeResolver) Reload(context.Context) error                 { return f.call("reload") }
func (f *fakeResolver) CheckConfig(context.Context) error            { return f.call("check") }
func (f *fakeResolver) FlushZone(context.Context, string) error      { return f.call("flush") }
func (f *fakeResolver) UpdateStubZone(context.Context, string) error { return f.call("update-stub") }
func (f *fakeResolver) DeleteStubZone(context.Context, string) error { return f.call("delete-stub") }
func (f *fakeResolver) Status(context.Context) (plugin.ServerStatus, error) {
	return plugin.ServerStatus{}, nil
}
func (f *fakeResolver) Type() string { return "fake" }

func newTestStatusRouter(metrics config.MetricsConfig) http.Handler {
	return newTestStatusServer(metrics).Handler
}

func newTestStatusServer(metrics config.MetricsConfig) *http.Server {
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
	return newStatusServer(cfg, syncer, checker, nil, nil, logger)
}
