package bird

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type recordingClient struct {
	responses map[string]*Response
	errs      map[string]error
	commands  []string
}

func (c *recordingClient) Exec(ctx context.Context, cmd string) (*Response, error) {
	c.commands = append(c.commands, cmd)
	if err, ok := c.errs[cmd]; ok {
		return nil, err
	}
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

	changed, err := manager.WithdrawRoutesChanged(context.Background())
	if err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	if !changed {
		t.Fatal("expected partial reconcile to require a withdraw")
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

func TestRouteManagerAnnounceRoutesChangedSkipsNoop(t *testing.T) {
	client := &recordingClient{}
	manager := mustNewRouteManager(t, client, []string{"anycast_1"})

	changed, err := manager.AnnounceRoutesChanged(context.Background())
	if err != nil {
		t.Fatalf("announce failed: %v", err)
	}
	if !changed {
		t.Fatal("expected first announce to change routes")
	}

	changed, err = manager.AnnounceRoutesChanged(context.Background())
	if err != nil {
		t.Fatalf("second announce failed: %v", err)
	}
	if changed {
		t.Fatal("expected second announce to be a no-op")
	}

	want := []string{"enable anycast_1"}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch\nwant: %v\n got: %v", want, client.commands)
	}
}

func TestRouteManagerWithdrawRoutesChangedSkipsFullyWithdrawn(t *testing.T) {
	client := &recordingClient{
		responses: map[string]*Response{
			"show protocols anycast_1": {Code: 0, RawText: "anycast_1 BGP master Disabled"},
		},
	}
	manager := mustNewRouteManager(t, client, []string{"anycast_1"})

	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	changed, err := manager.WithdrawRoutesChanged(context.Background())
	if err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	if changed {
		t.Fatal("expected already withdrawn route to be a no-op")
	}

	want := []string{"show protocols anycast_1"}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch\nwant: %v\n got: %v", want, client.commands)
	}
}

func TestRouteManagerForceWithdrawRoutesAlwaysDisablesProtocols(t *testing.T) {
	client := &recordingClient{}
	manager := mustNewRouteManager(t, client, []string{"anycast_1", "anycast_2"})

	if err := manager.ForceWithdrawRoutes(context.Background()); err != nil {
		t.Fatalf("force withdraw failed: %v", err)
	}
	if manager.IsAnnounced() {
		t.Fatal("expected forced withdraw to mark routes withdrawn")
	}

	want := []string{
		"disable anycast_1",
		"disable anycast_2",
	}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch\nwant: %v\n got: %v", want, client.commands)
	}
}

func TestRouteManagerForceWithdrawRoutesAttemptsAllProtocolsOnErrors(t *testing.T) {
	client := &recordingClient{
		errs: map[string]error{
			"disable anycast_1": errors.New("socket closed"),
		},
		responses: map[string]*Response{
			"disable anycast_2": {Code: 9001, RawText: "9001 syntax error"},
		},
	}
	manager := mustNewRouteManager(t, client, []string{"anycast_1", "anycast_2", "anycast_3"})
	manager.announced = true

	err := manager.ForceWithdrawRoutes(context.Background())
	if err == nil {
		t.Fatal("expected force withdraw error")
	}
	for _, want := range []string{
		"disable protocol anycast_1: socket closed",
		"BIRD error disabling anycast_2",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to contain %q, got %v", want, err)
		}
	}
	if manager.IsAnnounced() {
		t.Fatal("expected failed forced withdraw not to leave manager fully announced")
	}
	if !manager.needsWithdraw {
		t.Fatal("expected failed forced withdraw to require another withdraw")
	}

	wantCommands := []string{
		"disable anycast_1",
		"disable anycast_2",
		"disable anycast_3",
	}
	if !reflect.DeepEqual(client.commands, wantCommands) {
		t.Fatalf("commands mismatch\nwant: %v\n got: %v", wantCommands, client.commands)
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

	want := []string{
		"enable anycast_1",
		"enable anycast_2",
		"disable anycast_1",
		"disable anycast_2",
	}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch after failed announce\nwant: %v\n got: %v", want, client.commands)
	}

	changed, err := manager.WithdrawRoutesChanged(context.Background())
	if err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	if changed {
		t.Fatal("expected rollback to leave no pending withdraw")
	}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch after no-op withdraw\nwant: %v\n got: %v", want, client.commands)
	}
}

func TestRouteManagerAnnounceFailureKeepsPendingWithdrawWhenRollbackFails(t *testing.T) {
	client := &recordingClient{
		responses: map[string]*Response{
			"enable anycast_2":  {Code: 9001, RawText: "9001 syntax error"},
			"disable anycast_1": {Code: 9002, RawText: "9002 disable error"},
		},
	}
	manager := mustNewRouteManager(t, client, []string{"anycast_1", "anycast_2"})

	err := manager.AnnounceRoutes(context.Background())
	if err == nil {
		t.Fatal("expected announce to fail")
	}
	if got := err.Error(); !strings.Contains(got, "rollback partial announce") {
		t.Fatalf("expected rollback error, got %v", err)
	}

	changed, err := manager.WithdrawRoutesChanged(context.Background())
	if err == nil {
		t.Fatal("expected pending withdraw to retry and fail")
	}
	if changed {
		t.Fatal("expected failed withdraw not to report a completed change")
	}

	want := []string{
		"enable anycast_1",
		"enable anycast_2",
		"disable anycast_1",
		"disable anycast_1",
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
	manager.announced = true

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
