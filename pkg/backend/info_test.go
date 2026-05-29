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
		{name: "mysql", store: &MySQLBackend{}},
		{name: "git", store: &GitBackend{}},
		{name: "etcd", store: &EtcdBackend{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.store.Info()
			capabilities := capabilitySet(info.Capabilities)

			_, hasZoneStore := tt.store.(ZoneStore)
			assertCapability(t, capabilities, CapabilityZoneStore, hasZoneStore)
			_, hasSummary := tt.store.(ZoneSummaryStore)
			assertCapability(t, capabilities, CapabilityZoneSummaryStore, hasSummary)
			_, hasCount := tt.store.(ZoneCountStore)
			assertCapability(t, capabilities, CapabilityZoneCountStore, hasCount)
			_, hasHealth := tt.store.(HealthStore)
			assertCapability(t, capabilities, CapabilityHealthStore, hasHealth)
			_, hasDNSSECMetadata := tt.store.(DNSSECMetadataStore)
			assertCapability(t, capabilities, CapabilityDNSSECMetadataStore, hasDNSSECMetadata)
			_, hasConditionalDelete := tt.store.(ConditionalDeleteStore)
			assertCapability(t, capabilities, CapabilityConditionalDeleteStore, hasConditionalDelete)
			_, hasRevision := tt.store.(RevisionStore)
			assertCapability(t, capabilities, CapabilityRevisionStore, hasRevision)
			_, hasWatchable := tt.store.(WatchableStore)
			assertCapability(t, capabilities, CapabilityWatchableStore, hasWatchable)
			_, hasTransactional := tt.store.(TransactionalStore)
			assertCapability(t, capabilities, CapabilityTransactionalStore, hasTransactional)

			for capability := range capabilities {
				if _, ok := knownCapabilities()[capability]; !ok {
					t.Fatalf("unknown capability %s", capability)
				}
			}
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

func knownCapabilities() map[string]struct{} {
	return map[string]struct{}{
		CapabilityZoneStore:              {},
		CapabilityZoneSummaryStore:       {},
		CapabilityZoneCountStore:         {},
		CapabilityHealthStore:            {},
		CapabilityDNSSECMetadataStore:    {},
		CapabilityConditionalDeleteStore: {},
		CapabilityRevisionStore:          {},
		CapabilityWatchableStore:         {},
		CapabilityTransactionalStore:     {},
	}
}

func assertCapability(t *testing.T, capabilities map[string]struct{}, capability string, want bool) {
	t.Helper()

	_, got := capabilities[capability]
	if got != want {
		t.Fatalf("capability %s presence = %v, want %v", capability, got, want)
	}
}
