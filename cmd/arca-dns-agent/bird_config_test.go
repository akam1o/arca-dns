package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/bird"
	"github.com/akam1o/arca-dns/pkg/config"
	"go.uber.org/zap"
)

func TestApplyBIRDConfigOnStartRestoresExistingConfigOnConfigureError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arca-dns.conf")
	previous := []byte("previous bird config\n")
	if err := os.WriteFile(path, previous, 0o644); err != nil {
		t.Fatalf("write previous config: %v", err)
	}

	client := &fakeBIRDClient{
		responses: map[string][]*bird.Response{
			"configure": {
				{Code: 9001, RawText: "9001 syntax error"},
				{Code: 0, RawText: "0000"},
			},
		},
	}

	result := applyBIRDConfigOnStart(testBIRDConfig(path), client, zap.NewNop())
	if result.Status.Status != birdConfigStatusUsingExisting {
		t.Fatalf("status=%s, want %s", result.Status.Status, birdConfigStatusUsingExisting)
	}
	if result.Status.Error == "" {
		t.Fatalf("expected status error")
	}
	if len(result.ProtocolNames) != 1 || result.ProtocolNames[0] != "anycast_1" {
		t.Fatalf("protocol names=%v, want [anycast_1]", result.ProtocolNames)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	if string(got) != string(previous) {
		t.Fatalf("restored config mismatch\nwant: %q\n got: %q", previous, got)
	}
	if got, want := strings.Join(client.commands, ","), "configure,configure"; got != want {
		t.Fatalf("commands=%s, want %s", got, want)
	}
}

func TestApplyBIRDConfigOnStartRemovesNewConfigOnConfigureError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arca-dns.conf")
	client := &fakeBIRDClient{
		responses: map[string][]*bird.Response{
			"configure": {
				{Code: 9001, RawText: "9001 syntax error"},
			},
		},
	}

	result := applyBIRDConfigOnStart(testBIRDConfig(path), client, zap.NewNop())
	if result.Status.Status != birdConfigStatusUsingExisting {
		t.Fatalf("status=%s, want %s", result.Status.Status, birdConfigStatusUsingExisting)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generated config should be removed, stat err=%v", err)
	}
	if got, want := strings.Join(client.commands, ","), "configure"; got != want {
		t.Fatalf("commands=%s, want %s", got, want)
	}
}

func TestApplyBIRDConfigOnStartMarksAppliedOnConfigureSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arca-dns.conf")
	client := &fakeBIRDClient{}

	result := applyBIRDConfigOnStart(testBIRDConfig(path), client, zap.NewNop())
	if result.Status.Status != birdConfigStatusApplied {
		t.Fatalf("status=%s, want %s", result.Status.Status, birdConfigStatusApplied)
	}
	if result.Status.LastSuccess.IsZero() {
		t.Fatalf("expected last success timestamp")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if !strings.Contains(string(got), "protocol bgp anycast_1") {
		t.Fatalf("generated config missing protocol:\n%s", got)
	}
	if got, want := strings.Join(client.commands, ","), "configure"; got != want {
		t.Fatalf("commands=%s, want %s", got, want)
	}
}

type fakeBIRDClient struct {
	responses map[string][]*bird.Response
	errs      map[string][]error
	commands  []string
}

func (f *fakeBIRDClient) Exec(ctx context.Context, cmd string) (*bird.Response, error) {
	f.commands = append(f.commands, cmd)
	if errs := f.errs[cmd]; len(errs) > 0 {
		err := errs[0]
		f.errs[cmd] = errs[1:]
		return nil, err
	}
	if responses := f.responses[cmd]; len(responses) > 0 {
		resp := responses[0]
		f.responses[cmd] = responses[1:]
		return resp, nil
	}
	return &bird.Response{Code: 0, RawText: "0000"}, nil
}

func (f *fakeBIRDClient) Close() error {
	return nil
}

func testBIRDConfig(path string) config.BIRDConfig {
	return config.BIRDConfig{
		Enabled:         true,
		CommandTimeout:  time.Second,
		AnycastPrefixes: []string{"192.0.2.53/32", "2001:db8::53/128"},
		Protocols: []config.BIRDProtocolConfig{
			{
				Name:            "anycast_1",
				NeighborAddress: "192.0.2.1",
				NeighborASN:     65001,
			},
		},
		ConfigureOnStart: config.BIRDConfigGenerationConfig{
			Enabled:  true,
			Path:     path,
			RouterID: "192.0.2.53",
			LocalAS:  65000,
			SourceIP: "192.0.2.53",
		},
	}
}
