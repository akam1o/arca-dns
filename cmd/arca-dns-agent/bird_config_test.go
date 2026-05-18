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

func TestApplyBIRDConfigOnStartRejectsSymlinkedConfigDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "target")
	configDir := filepath.Join(tmpDir, "bird.d")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatalf("create target dir: %v", err)
	}
	if err := os.Symlink(targetDir, configDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	path := filepath.Join(configDir, "arca-dns.conf")
	client := &fakeBIRDClient{}
	result := applyBIRDConfigOnStart(testBIRDConfig(path), client, zap.NewNop())

	if result.Status.Status != birdConfigStatusUsingExisting {
		t.Fatalf("status=%s, want %s", result.Status.Status, birdConfigStatusUsingExisting)
	}
	if !strings.Contains(result.Status.Error, "config directory") || !strings.Contains(result.Status.Error, "symlink") {
		t.Fatalf("status error=%q, want symlinked config directory error", result.Status.Error)
	}
	if len(client.commands) != 0 {
		t.Fatalf("configure should not be called, commands=%v", client.commands)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "arca-dns.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config should not be written through symlink, stat err=%v", err)
	}
}

func TestApplyBIRDConfigOnStartRejectsSymlinkedConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "arca-dns.conf")
	sentinelPath := filepath.Join(tmpDir, "sentinel.conf")
	sentinel := []byte("keep\n")
	if err := os.WriteFile(sentinelPath, sentinel, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	if err := os.Symlink(sentinelPath, configPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	client := &fakeBIRDClient{}
	result := applyBIRDConfigOnStart(testBIRDConfig(configPath), client, zap.NewNop())

	if result.Status.Status != birdConfigStatusUsingExisting {
		t.Fatalf("status=%s, want %s", result.Status.Status, birdConfigStatusUsingExisting)
	}
	if !strings.Contains(result.Status.Error, "BIRD config file") || !strings.Contains(result.Status.Error, "symlink") {
		t.Fatalf("status error=%q, want symlinked BIRD config file error", result.Status.Error)
	}
	if len(client.commands) != 0 {
		t.Fatalf("configure should not be called, commands=%v", client.commands)
	}
	got, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("sentinel = %q, want %q", got, sentinel)
	}
	linkInfo, err := os.Lstat(configPath)
	if err != nil {
		t.Fatalf("config symlink should remain: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected config path to remain a symlink, mode=%v", linkInfo.Mode())
	}
}

func TestWriteFileAtomicCreatesConfigDirectoryAndCleansTemp(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "missing", "nested", "arca-dns.conf")

	if err := writeFileAtomic(path, []byte("bird config\n"), 0o640); err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(got) != "bird config\n" {
		t.Fatalf("config content = %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%v, want 0640", info.Mode().Perm())
	}

	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected temp files to be removed, got %v", matches)
	}
}

func TestWriteFileAtomicRejectsSymlinkedConfigDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "target")
	configDir := filepath.Join(tmpDir, "bird.d")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatalf("create target dir: %v", err)
	}
	if err := os.Symlink(targetDir, configDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	path := filepath.Join(configDir, "arca-dns.conf")
	err := writeFileAtomic(path, []byte("bird config\n"), 0o644)
	if err == nil {
		t.Fatal("writeFileAtomic should reject symlinked config directory")
	}
	if !strings.Contains(err.Error(), "config directory") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("writeFileAtomic error=%v, want symlinked config directory error", err)
	}
	if _, statErr := os.Stat(filepath.Join(targetDir, "arca-dns.conf")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("config should not be written through symlink, stat err=%v", statErr)
	}
}

func TestWriteFileAtomicDoesNotFollowPredictableTempSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "arca-dns.conf")
	sentinelPath := filepath.Join(tmpDir, "sentinel")
	sentinel := []byte("keep")
	if err := os.WriteFile(sentinelPath, sentinel, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	predictableTemp := filepath.Join(tmpDir, "."+filepath.Base(path)+".tmp-predictable")
	if err := os.Symlink(sentinelPath, predictableTemp); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if err := writeFileAtomic(path, []byte("bird config\n"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
	}

	got, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	if string(got) != string(sentinel) {
		t.Fatalf("sentinel = %q, want %q", got, sentinel)
	}

	linkInfo, err := os.Lstat(predictableTemp)
	if err != nil {
		t.Fatalf("predictable temp symlink should remain untouched: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected predictable temp path to remain a symlink, mode=%v", linkInfo.Mode())
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
