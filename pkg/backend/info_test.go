package backend

import "testing"

type backendInfoProvider interface {
	Info() BackendInfo
}

func TestBackendInfoCapabilitiesMatchImplementedInterfaces(t *testing.T) {
	sqlite, err := NewSQLiteBackend(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteBackend failed: %v", err)
	}
	defer sqlite.Close()

	tests := []struct {
		name  string
		store backendInfoProvider
	}{
		{name: "memory", store: NewMemoryBackend()},
		{name: "sqlite", store: sqlite},
		{name: "postgres", store: &PostgresBackend{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.store.Info()
			capabilities := capabilitySet(info.Capabilities)

			assertCapability(t, capabilities, CapabilityZoneStore, true)
			_, hasSummary := tt.store.(ZoneSummaryStore)
			assertCapability(t, capabilities, CapabilityZoneSummaryStore, hasSummary)
			_, hasHealth := tt.store.(HealthStore)
			assertCapability(t, capabilities, CapabilityHealthStore, hasHealth)
			_, hasDNSSECMetadata := tt.store.(DNSSECMetadataStore)
			assertCapability(t, capabilities, CapabilityDNSSECMetadataStore, hasDNSSECMetadata)
			_, hasConditionalDelete := tt.store.(ConditionalDeleteStore)
			assertCapability(t, capabilities, CapabilityConditionalDeleteStore, hasConditionalDelete)
			_, hasTransactional := tt.store.(TransactionalStore)
			assertCapability(t, capabilities, CapabilityTransactionalStore, hasTransactional)
		})
	}
}

func capabilitySet(capabilities []string) map[string]struct{} {
	set := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		set[capability] = struct{}{}
	}
	return set
}

func assertCapability(t *testing.T, capabilities map[string]struct{}, capability string, want bool) {
	t.Helper()

	_, got := capabilities[capability]
	if got != want {
		t.Fatalf("capability %s presence = %v, want %v", capability, got, want)
	}
}
