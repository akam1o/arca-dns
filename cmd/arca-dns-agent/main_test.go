package main

import (
	"context"
	"encoding/json"
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
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

func TestStatusRouter_StatusRequiresAuthTokenWhenConfigured(t *testing.T) {
	const token = "status-token-32-byte-test-secret"
	router := newTestStatusRouter(config.MetricsConfig{
		Enabled:   true,
		Path:      "/metrics",
		AuthToken: token,
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /health status=%d, want %d", resp.Code, http.StatusOK)
	}

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/status", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("GET /status without token status=%d, want %d", resp.Code, http.StatusUnauthorized)
	}

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("GET /status with wrong token status=%d, want %d", resp.Code, http.StatusUnauthorized)
	}

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /status with token status=%d, want %d", resp.Code, http.StatusOK)
	}
}

func TestStatusRouter_MetricsRequiresAuthTokenWhenConfigured(t *testing.T) {
	const token = "status-token-32-byte-test-secret"
	router := newTestStatusRouter(config.MetricsConfig{
		Enabled:   true,
		Path:      "/metrics",
		AuthToken: token,
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("GET /metrics without token status=%d, want %d", resp.Code, http.StatusUnauthorized)
	}

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /metrics with token status=%d, want %d", resp.Code, http.StatusOK)
	}
	if !strings.Contains(resp.Body.String(), "arca_dns_agent_sync_has_success") {
		t.Fatalf("GET /metrics response did not contain agent metrics")
	}
}

func TestStatusAuthTokenMatches(t *testing.T) {
	const token = "status-token-32-byte-test-secret"
	tests := map[string]struct {
		header string
		want   bool
	}{
		"valid bearer token": {
			header: "Bearer " + token,
			want:   true,
		},
		"case insensitive bearer prefix": {
			header: "bearer " + token,
			want:   true,
		},
		"trims surrounding whitespace": {
			header: "  Bearer " + token + "  ",
			want:   true,
		},
		"missing bearer prefix": {
			header: token,
			want:   false,
		},
		"empty bearer token": {
			header: "Bearer ",
			want:   false,
		},
		"wrong same length token": {
			header: "Bearer status-token-32-byte-test-wrong!",
			want:   false,
		},
		"wrong shorter token": {
			header: "Bearer short",
			want:   false,
		},
		"wrong longer token": {
			header: "Bearer " + token + "-suffix",
			want:   false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := statusAuthTokenMatches(tt.header, token); got != tt.want {
				t.Fatalf("statusAuthTokenMatches(%q)=%t, want %t", tt.header, got, tt.want)
			}
		})
	}
}

func TestStatusRouter_DoesNotExposeZoneDetails(t *testing.T) {
	router := newTestStatusRouter(config.MetricsConfig{
		Enabled: true,
		Path:    "/metrics",
	})

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /status status=%d, want %d", resp.Code, http.StatusOK)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /status response: %v", err)
	}
	if _, ok := body["zones"]; ok {
		t.Fatalf("GET /status exposed per-zone details")
	}
	if _, ok := body["zone_count"]; !ok {
		t.Fatalf("GET /status missing zone_count")
	}
	if _, ok := body["failed_zones"]; !ok {
		t.Fatalf("GET /status missing failed_zones")
	}
}

func TestStatusRouter_ExposesBIRDConfigFallback(t *testing.T) {
	status := birdConfigRuntimeStatus{
		Enabled:     true,
		Status:      birdConfigStatusUsingExisting,
		Path:        "/etc/bird/arca-dns.conf",
		Error:       "render failed",
		LastAttempt: time.Unix(123, 0),
	}
	router := newTestStatusRouterWithBIRDConfigStatus(config.MetricsConfig{
		Enabled: true,
		Path:    "/metrics",
	}, status)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /status status=%d, want %d", resp.Code, http.StatusOK)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /status response: %v", err)
	}
	birdConfig, ok := body["bird_config"].(map[string]interface{})
	if !ok {
		t.Fatalf("GET /status missing bird_config")
	}
	if got := birdConfig["status"]; got != birdConfigStatusUsingExisting {
		t.Fatalf("bird_config.status=%v, want %s", got, birdConfigStatusUsingExisting)
	}
	if got := birdConfig["error"]; got != status.Error {
		t.Fatalf("bird_config.error=%v, want %s", got, status.Error)
	}
	if got := body["bgp_control_status"]; got != bgpControlStatusUnknown {
		t.Fatalf("bgp_control_status=%v, want %s", got, bgpControlStatusUnknown)
	}
	if got, ok := body["bgp_announced"]; !ok || got != nil {
		t.Fatalf("bgp_announced=%v, want null", got)
	}

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET /metrics status=%d, want %d", resp.Code, http.StatusOK)
	}
	metrics := resp.Body.String()
	if !strings.Contains(metrics, `arca_dns_agent_bird_config_status{status="using_existing"} 1`) {
		t.Fatalf("GET /metrics missing current BIRD config status:\n%s", metrics)
	}
	if !strings.Contains(metrics, `arca_dns_agent_bgp_control_status{status="unknown"} 1`) {
		t.Fatalf("GET /metrics missing unknown BGP control status:\n%s", metrics)
	}
	if !strings.Contains(metrics, "arca_dns_agent_bgp_routes_announced -1") {
		t.Fatalf("GET /metrics should report unknown BGP announcement state:\n%s", metrics)
	}
	if !strings.Contains(metrics, "arca_dns_agent_bird_config_last_attempt_timestamp_seconds 123") {
		t.Fatalf("GET /metrics missing BIRD config attempt timestamp:\n%s", metrics)
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

func TestWarnPlaintextAPIKeyTransport(t *testing.T) {
	tests := []struct {
		name     string
		cfg      config.ControllerClientConfig
		wantWarn bool
	}{
		{
			name: "http with api key",
			cfg: config.ControllerClientConfig{
				URL:    "http://controller:8080",
				APIKey: "secret",
			},
			wantWarn: true,
		},
		{
			name: "https with api key",
			cfg: config.ControllerClientConfig{
				URL:    "https://controller.example.com",
				APIKey: "secret",
			},
		},
		{
			name: "http without api key",
			cfg: config.ControllerClientConfig{
				URL: "http://controller:8080",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.WarnLevel)
			logger := zap.New(core)

			warnPlaintextAPIKeyTransport(tc.cfg, logger)

			if tc.wantWarn {
				if logs.Len() != 1 {
					t.Fatalf("expected one warning, got %d", logs.Len())
				}
				entry := logs.All()[0]
				if entry.Message != "Controller API key will be sent over plaintext HTTP" {
					t.Fatalf("unexpected warning message %q", entry.Message)
				}
				if got := entry.ContextMap()["url"]; got != tc.cfg.URL {
					t.Fatalf("warning url field = %v, want %s", got, tc.cfg.URL)
				}
				if _, ok := entry.ContextMap()["api_key"]; ok {
					t.Fatalf("warning must not log api_key")
				}
				return
			}

			if logs.Len() != 0 {
				t.Fatalf("expected no warnings, got %d", logs.Len())
			}
		})
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

	server, err := startStatusServer(cfg, syncer, checker, nil, nil, birdConfigRuntimeStatus{}, logger)
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

func TestApplyZoneServiceReferences_FlushesAfterReload(t *testing.T) {
	authServer := newFakeAuthoritativeServer()
	resolver := newFakeResolver()

	err := applyZoneServiceReferences(context.Background(), "example.com.", authServer, resolver)
	if err != nil {
		t.Fatalf("applyZoneServiceReferences failed: %v", err)
	}

	wantAuthCalls := "ensure,reload-zone"
	if got := strings.Join(authServer.calls, ","); got != wantAuthCalls {
		t.Fatalf("auth calls = %s, want %s", got, wantAuthCalls)
	}

	wantResolverCalls := "update-stub,check,reload,flush"
	if got := strings.Join(resolver.calls, ","); got != wantResolverCalls {
		t.Fatalf("resolver calls = %s, want %s", got, wantResolverCalls)
	}
}

func TestApplyZoneServiceReferences_ReturnsFlushError(t *testing.T) {
	authServer := newFakeAuthoritativeServer()
	resolver := newFakeResolver()
	resolver.failAt["flush"] = 1
	resolver.failErr["flush"] = errors.New("flush failed")

	err := applyZoneServiceReferences(context.Background(), "example.com.", authServer, resolver)
	if err == nil || !strings.Contains(err.Error(), "flush failed") {
		t.Fatalf("expected flush error, got %v", err)
	}
}

func TestRestoreZoneServiceReferences_FlushesAfterReload(t *testing.T) {
	authServer := newFakeAuthoritativeServer()
	resolver := newFakeResolver()

	err := restoreZoneServiceReferences(context.Background(), "example.com.", authServer, resolver, true, true)
	if err != nil {
		t.Fatalf("restoreZoneServiceReferences failed: %v", err)
	}

	wantAuthCalls := "ensure,reload-zone"
	if got := strings.Join(authServer.calls, ","); got != wantAuthCalls {
		t.Fatalf("auth calls = %s, want %s", got, wantAuthCalls)
	}

	wantResolverCalls := "update-stub,check,reload,flush"
	if got := strings.Join(resolver.calls, ","); got != wantResolverCalls {
		t.Fatalf("resolver calls = %s, want %s", got, wantResolverCalls)
	}
}

func TestRestoreZoneServiceReferences_ReturnsFlushError(t *testing.T) {
	authServer := newFakeAuthoritativeServer()
	resolver := newFakeResolver()
	resolver.failAt["flush"] = 1
	resolver.failErr["flush"] = errors.New("flush failed")

	err := restoreZoneServiceReferences(context.Background(), "example.com.", authServer, resolver, true, true)
	if err == nil || !strings.Contains(err.Error(), "flush failed") {
		t.Fatalf("expected flush error, got %v", err)
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

	wantResolverCalls := "delete-stub,check,reload,update-stub,check,reload,flush"
	if got := strings.Join(resolver.calls, ","); got != wantResolverCalls {
		t.Fatalf("resolver calls = %s, want %s", got, wantResolverCalls)
	}
}

func TestDeleteZoneServiceReferences_FlushesAfterReload(t *testing.T) {
	authServer := newFakeAuthoritativeServer()
	resolver := newFakeResolver()

	err := deleteZoneServiceReferences(context.Background(), "example.com.", authServer, resolver, zap.NewNop())
	if err != nil {
		t.Fatalf("deleteZoneServiceReferences failed: %v", err)
	}

	wantAuthCalls := "delete"
	if got := strings.Join(authServer.calls, ","); got != wantAuthCalls {
		t.Fatalf("auth calls = %s, want %s", got, wantAuthCalls)
	}

	wantResolverCalls := "delete-stub,check,reload,flush"
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

func newTestStatusRouterWithBIRDConfigStatus(metrics config.MetricsConfig, status birdConfigRuntimeStatus) http.Handler {
	return newTestStatusServerWithBIRDConfigStatus(metrics, status).Handler
}

func newTestStatusServer(metrics config.MetricsConfig) *http.Server {
	return newTestStatusServerWithBIRDConfigStatus(metrics, birdConfigRuntimeStatus{})
}

func newTestStatusServerWithBIRDConfigStatus(metrics config.MetricsConfig, status birdConfigRuntimeStatus) *http.Server {
	logger := zap.NewNop()
	cfg := &config.AgentConfig{
		Metrics: metrics,
		BIRD: config.BIRDConfig{
			Enabled: status.Enabled,
		},
	}
	syncer := zonesync.NewSyncer(nil, nil, config.SyncConfig{
		MaxStaleness: time.Hour,
	}, logger)
	checker := health.NewCheckerWithOptions(config.HealthConfig{
		QueryTimeout: time.Millisecond,
	}, health.CheckerOptions{}, logger)
	return newStatusServer(cfg, syncer, checker, nil, nil, status, logger)
}
