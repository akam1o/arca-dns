package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
