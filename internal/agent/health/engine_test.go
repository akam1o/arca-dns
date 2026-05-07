package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/internal/agent/bird"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestEngine_processHealthStatus_AggregateUnhealthyWithoutFailedChecksHardFails(t *testing.T) {
	engine := NewEngine(nil, EngineConfig{
		FailureThreshold:  1,
		RecoveryThreshold: 1,
	}, zap.NewNop())

	status := HealthStatus{
		Healthy: false,
		Checks: map[CheckType]CheckResult{
			CheckTypeSync: {
				Type:      CheckTypeSync,
				Success:   true,
				Timestamp: time.Now(),
			},
		},
		LastCheck: time.Now(),
	}

	signal, shouldSend := engine.processHealthStatus(status)

	assert.True(t, shouldSend)
	assert.True(t, signal.HardFail)
	assert.False(t, signal.LatencyDegraded)
	assert.Equal(t, "Health status is unhealthy", signal.Reason)
}

func TestEngine_processHealthStatus_LatencyFailureRemainsDegraded(t *testing.T) {
	engine := NewEngine(nil, EngineConfig{
		FailureThreshold:  1,
		RecoveryThreshold: 1,
	}, zap.NewNop())

	status := HealthStatus{
		Healthy: false,
		Checks: map[CheckType]CheckResult{
			CheckTypeQuery: {
				Type:      CheckTypeQuery,
				Success:   true,
				Timestamp: time.Now(),
			},
			CheckTypeFullPath: {
				Type:      CheckTypeFullPath,
				Success:   true,
				Timestamp: time.Now(),
			},
			CheckTypeLatency: {
				Type:      CheckTypeLatency,
				Success:   false,
				Timestamp: time.Now(),
			},
		},
		LastCheck: time.Now(),
	}

	signal, shouldSend := engine.processHealthStatus(status)

	assert.True(t, shouldSend)
	assert.False(t, signal.HardFail)
	assert.True(t, signal.LatencyDegraded)
	assert.Equal(t, "Latency threshold exceeded", signal.Reason)
}

func TestEngine_RunWithStatusProcessesExistingChannel(t *testing.T) {
	engine := NewEngine(nil, EngineConfig{
		FailureThreshold:  1,
		RecoveryThreshold: 1,
	}, zap.NewNop())

	statusChan := make(chan HealthStatus, 1)
	signalChan := make(chan bird.HealthSignal, 1)
	statusChan <- HealthStatus{
		Healthy: false,
		Checks: map[CheckType]CheckResult{
			CheckTypeQuery: {
				Type:      CheckTypeQuery,
				Success:   false,
				Error:     errors.New("query failed"),
				Timestamp: time.Now(),
			},
		},
		LastCheck: time.Now(),
	}
	close(statusChan)

	err := engine.RunWithStatus(context.Background(), statusChan, signalChan)
	require.NoError(t, err)

	select {
	case signal := <-signalChan:
		assert.True(t, signal.HardFail)
		assert.Equal(t, "query failed", signal.Reason)
	default:
		t.Fatal("expected health signal")
	}
}
