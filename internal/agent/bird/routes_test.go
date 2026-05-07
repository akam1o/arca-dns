package bird

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type recordingClient struct {
	responses map[string]*Response
	commands  []string
}

func (c *recordingClient) Exec(ctx context.Context, cmd string) (*Response, error) {
	c.commands = append(c.commands, cmd)
	if resp, ok := c.responses[cmd]; ok {
		return resp, nil
	}
	return &Response{Code: 0, RawText: "0000"}, nil
}

func (c *recordingClient) Close() error {
	return nil
}

func mustNewRouteManager(t *testing.T, client Client, protocolNames []string) *RouteManager {
	t.Helper()
	manager, err := NewRouteManager(client, protocolNames)
	if err != nil {
		t.Fatalf("NewRouteManager failed: %v", err)
	}
	return manager
}

func TestRouteManagerWithdrawsAllProtocolsAfterPartialReconcile(t *testing.T) {
	client := &recordingClient{
		responses: map[string]*Response{
			"show protocols anycast_1": {Code: 0, RawText: "anycast_1 BGP master up"},
			"show protocols anycast_2": {Code: 0, RawText: "anycast_2 BGP master Disabled"},
		},
	}
	manager := mustNewRouteManager(t, client, []string{"anycast_1", "anycast_2"})

	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if manager.IsAnnounced() {
		t.Fatal("expected partial protocol state to be treated as not fully announced")
	}

	if err := manager.WithdrawRoutes(context.Background()); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}

	want := []string{
		"show protocols anycast_1",
		"show protocols anycast_2",
		"disable anycast_1",
		"disable anycast_2",
	}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch\nwant: %v\n got: %v", want, client.commands)
	}
}

func TestRouteManagerWithdrawsAfterPartialAnnounceFailure(t *testing.T) {
	client := &recordingClient{
		responses: map[string]*Response{
			"enable anycast_2": {Code: 9001, RawText: "9001 syntax error"},
		},
	}
	manager := mustNewRouteManager(t, client, []string{"anycast_1", "anycast_2"})

	if err := manager.AnnounceRoutes(context.Background()); err == nil {
		t.Fatal("expected announce to fail")
	}
	if manager.IsAnnounced() {
		t.Fatal("expected failed announce not to mark routes as announced")
	}

	if err := manager.WithdrawRoutes(context.Background()); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}

	want := []string{
		"enable anycast_1",
		"enable anycast_2",
		"disable anycast_1",
		"disable anycast_2",
	}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch\nwant: %v\n got: %v", want, client.commands)
	}
}

func TestRouteManagerWithdrawReturnsProtocolErrors(t *testing.T) {
	client := &recordingClient{
		responses: map[string]*Response{
			"disable anycast_1": {Code: 9001, RawText: "9001 syntax error"},
		},
	}
	manager := mustNewRouteManager(t, client, []string{"anycast_1"})

	err := manager.WithdrawRoutes(context.Background())
	if err == nil {
		t.Fatal("expected withdraw error")
	}
	if got, want := err.Error(), fmt.Sprintf("BIRD error disabling anycast_1 (%d): %s", 9001, "9001 syntax error"); got != want {
		t.Fatalf("unexpected error\nwant: %s\n got: %s", want, got)
	}
}

func TestNewRouteManagerRejectsInvalidProtocolNames(t *testing.T) {
	client := &recordingClient{}

	_, err := NewRouteManager(client, []string{"anycast_1", "anycast; disable all;"})
	if err == nil {
		t.Fatal("expected invalid protocol name error")
	}
	if got := err.Error(); !strings.Contains(got, "bird.protocol_names") {
		t.Fatalf("expected protocol name validation error, got %v", err)
	}
	if len(client.commands) != 0 {
		t.Fatalf("expected no commands, got %v", client.commands)
	}
}

func TestNewRouteManagerCopiesProtocolNames(t *testing.T) {
	client := &recordingClient{}
	names := []string{"anycast_1"}
	manager := mustNewRouteManager(t, client, names)

	names[0] = "anycast; disable all;"
	if err := manager.AnnounceRoutes(context.Background()); err != nil {
		t.Fatalf("announce failed: %v", err)
	}

	want := []string{"enable anycast_1"}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch\nwant: %v\n got: %v", want, client.commands)
	}
}
