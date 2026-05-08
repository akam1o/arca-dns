package bird

import (
	"context"
	"reflect"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestStateMachine_ProcessSignal_HardFailBeforeThresholdDoesNotAnnounce(t *testing.T) {
	sm := NewStateMachine(StateMachineConfig{
		FailureThreshold:  3,
		RecoveryThreshold: 2,
	}, zap.NewNop())

	shouldAnnounce, shouldWithdraw := sm.ProcessSignal(HealthSignal{
		HardFail: true,
		Reason:   "sync unhealthy",
	})

	if shouldAnnounce {
		t.Fatal("expected hard failure before threshold not to announce routes")
	}
	if shouldWithdraw {
		t.Fatal("expected hard failure before threshold not to withdraw routes")
	}
	if got := sm.GetState(); got != StateHealthy {
		t.Fatalf("expected state to remain healthy before threshold, got %s", got)
	}
}

func TestStateMachine_ProcessSignal_HardFailAtThresholdWithdraws(t *testing.T) {
	sm := NewStateMachine(StateMachineConfig{
		FailureThreshold:  3,
		RecoveryThreshold: 2,
	}, zap.NewNop())

	for i := 0; i < 2; i++ {
		shouldAnnounce, shouldWithdraw := sm.ProcessSignal(HealthSignal{
			HardFail: true,
			Reason:   "sync unhealthy",
		})
		if shouldAnnounce || shouldWithdraw {
			t.Fatalf("failure %d before threshold returned announce=%v withdraw=%v", i+1, shouldAnnounce, shouldWithdraw)
		}
	}

	shouldAnnounce, shouldWithdraw := sm.ProcessSignal(HealthSignal{
		HardFail: true,
		Reason:   "sync unhealthy",
	})

	if shouldAnnounce {
		t.Fatal("expected threshold hard failure not to announce routes")
	}
	if !shouldWithdraw {
		t.Fatal("expected threshold hard failure to withdraw routes")
	}
	if got := sm.GetState(); got != StateUnhealthy {
		t.Fatalf("expected state to be unhealthy at threshold, got %s", got)
	}
}

func TestStateMachine_ProcessSignal_SuccessStillAnnouncesFromHealthy(t *testing.T) {
	sm := NewStateMachine(StateMachineConfig{
		FailureThreshold:  3,
		RecoveryThreshold: 2,
	}, zap.NewNop())

	shouldAnnounce, shouldWithdraw := sm.ProcessSignal(HealthSignal{
		Reason: "healthy",
	})

	if !shouldAnnounce {
		t.Fatal("expected healthy signal to announce routes")
	}
	if shouldWithdraw {
		t.Fatal("expected healthy signal not to withdraw routes")
	}
}

func TestControlLoop_DoesNotDebounceWithdrawAfterNoopAnnounce(t *testing.T) {
	client := &recordingClient{
		responses: map[string]*Response{
			"show protocols anycast_1": {Code: 0, RawText: "anycast_1 BGP master up"},
		},
	}
	manager := mustNewRouteManager(t, client, []string{"anycast_1"})
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	stateMachine := NewStateMachine(StateMachineConfig{
		FailureThreshold:  1,
		RecoveryThreshold: 1,
		MinStateDuration:  time.Hour,
	}, zap.NewNop())
	controlLoop := NewControlLoop(stateMachine, manager, zap.NewNop())

	controlLoop.processSignal(context.Background(), HealthSignal{Reason: "healthy"})
	controlLoop.processSignal(context.Background(), HealthSignal{HardFail: true, Reason: "sync unhealthy"})

	want := []string{
		"show protocols anycast_1",
		"disable anycast_1",
	}
	if !reflect.DeepEqual(client.commands, want) {
		t.Fatalf("commands mismatch\nwant: %v\n got: %v", want, client.commands)
	}
}
