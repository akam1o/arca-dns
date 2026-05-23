package plugin

import (
	"context"
	"strings"
	"testing"
)

func TestNoopAuthoritativeServer(t *testing.T) {
	ctx := context.Background()
	server := &NoopAuthoritativeServer{}

	if server.Type() != "noop" {
		t.Fatalf("Type() = %q, want noop", server.Type())
	}
	if err := server.EnsureZone(ctx, "example.com."); err != nil {
		t.Fatalf("EnsureZone() error = %v", err)
	}
	if err := server.ReloadZone(ctx, "example.com."); err != nil {
		t.Fatalf("ReloadZone() error = %v", err)
	}
	if err := server.CheckZone(ctx, "example.com.", "/zones/example.com.zone"); err != nil {
		t.Fatalf("CheckZone() error = %v", err)
	}
	if err := server.DeleteZone(ctx, "example.com."); err != nil {
		t.Fatalf("DeleteZone() error = %v", err)
	}
	if err := server.Reload(ctx); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	status, err := server.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.Running {
		t.Fatalf("Status().Running = true, want false")
	}
	if status.StatusText != "disabled" {
		t.Fatalf("Status().StatusText = %q, want disabled", status.StatusText)
	}
}

func TestNoopResolver(t *testing.T) {
	ctx := context.Background()
	resolver := &NoopResolver{}

	if resolver.Type() != "noop" {
		t.Fatalf("Type() = %q, want noop", resolver.Type())
	}
	if err := resolver.Reload(ctx); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if err := resolver.CheckConfig(ctx); err != nil {
		t.Fatalf("CheckConfig() error = %v", err)
	}
	if err := resolver.FlushZone(ctx, "example.com."); err != nil {
		t.Fatalf("FlushZone() error = %v", err)
	}
	if err := resolver.UpdateStubZone(ctx, "example.com."); err != nil {
		t.Fatalf("UpdateStubZone() error = %v", err)
	}
	if err := resolver.DeleteStubZone(ctx, "example.com."); err != nil {
		t.Fatalf("DeleteStubZone() error = %v", err)
	}
	status, err := resolver.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.Running {
		t.Fatalf("Status().Running = true, want false")
	}
	if status.StatusText != "disabled" {
		t.Fatalf("Status().StatusText = %q, want disabled", status.StatusText)
	}
}

func TestNewAuthoritativeServerRequiresRegistration(t *testing.T) {
	server, err := NewAuthoritativeServer("nsd", nil)
	if err == nil {
		t.Fatalf("NewAuthoritativeServer() error = nil, want registration error")
	}
	if server != nil {
		t.Fatalf("NewAuthoritativeServer() server = %#v, want nil", server)
	}
	if !strings.Contains(err.Error(), "use RegisterAuthoritativeServer") {
		t.Fatalf("NewAuthoritativeServer() error = %q, want registration guidance", err.Error())
	}
}
