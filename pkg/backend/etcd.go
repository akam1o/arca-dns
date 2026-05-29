package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// EtcdBackend implements ZoneStore, RevisionStore, and WatchableStore using etcd.
type EtcdBackend struct {
	client  *clientv3.Client
	prefix  string
	timeout time.Duration

	// Mutexes for per-zone locking
	zoneMutex sync.Map // map[string]*sync.Mutex

	// Watch management
	watchMu  sync.RWMutex
	watchers map[string][]chan ZoneEvent
}

const (
	defaultEtcdPrefix       = "/arca-dns"
	defaultEtcdTimeout      = 10 * time.Second
	defaultHistoryRetention = 100
	etcdZonesPrefix         = "zones"
	etcdVersionsPrefix      = "versions"
	etcdHistoryPrefix       = "history"
)

// NewEtcdBackend creates a new etcd backend.
func NewEtcdBackend(endpoints []string, prefix, username, password string, dialTimeout, requestTimeout time.Duration) (*EtcdBackend, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("at least one etcd endpoint is required")
	}

	if prefix == "" {
		prefix = defaultEtcdPrefix
	}

	if requestTimeout == 0 {
		requestTimeout = defaultEtcdTimeout
	}

	config := clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: dialTimeout,
		Username:    username,
		Password:    password,
	}

	client, err := clientv3.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	_, err = client.Status(ctx, endpoints[0])
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to etcd: %w", err)
	}

	return &EtcdBackend{
		client:   client,
		prefix:   strings.TrimSuffix(prefix, "/"),
		timeout:  requestTimeout,
		watchers: make(map[string][]chan ZoneEvent),
	}, nil
}

// init registers the etcd backend factory.
func init() {
	RegisterBackend("etcd", func(cfg map[string]interface{}) (ZoneStore, error) {
		// Handle both []string (from config.EtcdBackendConfig) and []interface{} (from generic map)
		var endpointStrs []string

		if endpoints, ok := cfg["endpoints"].([]string); ok {
			endpointStrs = endpoints
		} else if endpoints, ok := cfg["endpoints"].([]interface{}); ok {
			endpointStrs = make([]string, len(endpoints))
			for i, ep := range endpoints {
				endpointStrs[i] = fmt.Sprint(ep)
			}
		} else {
			return nil, fmt.Errorf("etcd endpoints required (must be []string or []interface{})")
		}

		if len(endpointStrs) == 0 {
			return nil, fmt.Errorf("etcd endpoints cannot be empty")
		}

		prefix, _ := cfg["prefix"].(string)
		username, _ := cfg["username"].(string)
		password, _ := cfg["password"].(string)

		dialTimeout, _ := cfg["dial_timeout"].(time.Duration)
		if dialTimeout == 0 {
			dialTimeout = 5 * time.Second
		}

		requestTimeout, _ := cfg["request_timeout"].(time.Duration)
		if requestTimeout == 0 {
			requestTimeout = 10 * time.Second
		}

		return NewEtcdBackend(endpointStrs, prefix, username, password, dialTimeout, requestTimeout)
	})
}

// Key path helpers
func (e *EtcdBackend) zoneKey(name string) string {
	return fmt.Sprintf("%s/%s/%s", e.prefix, etcdZonesPrefix, model.NormalizeZoneName(name))
}

func (e *EtcdBackend) versionKey(name string) string {
	return fmt.Sprintf("%s/%s/%s", e.prefix, etcdVersionsPrefix, model.NormalizeZoneName(name))
}

func (e *EtcdBackend) versionPrefix() string {
	return fmt.Sprintf("%s/%s/", e.prefix, etcdVersionsPrefix)
}

func (e *EtcdBackend) historyKey(name, version string) string {
	return fmt.Sprintf("%s/%s/%s/%s", e.prefix, etcdHistoryPrefix, model.NormalizeZoneName(name), version)
}

func (e *EtcdBackend) historyPrefixForZone(name string) string {
	return fmt.Sprintf("%s/%s/%s/", e.prefix, etcdHistoryPrefix, model.NormalizeZoneName(name))
}

// HealthCheck verifies that etcd is reachable without scanning zone data.
func (e *EtcdBackend) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	if _, err := e.client.Get(ctx, e.prefix, clientv3.WithLimit(1)); err != nil {
		return fmt.Errorf("etcd health check failed: %w", err)
	}
	return nil
}

// CountZones returns the number of zone keys without loading zone payloads.
func (e *EtcdBackend) CountZones(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	prefix := fmt.Sprintf("%s/%s/", e.prefix, etcdZonesPrefix)
	resp, err := e.client.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil {
		return 0, fmt.Errorf("failed to count zones: %w", err)
	}
	return int(resp.Count), nil
}

// Per-zone mutex helpers
func (e *EtcdBackend) acquireZoneLock(zoneName string) *sync.Mutex {
	normalized := model.NormalizeZoneName(zoneName)
	mu, _ := e.zoneMutex.LoadOrStore(normalized, &sync.Mutex{})
	zoneMu := mu.(*sync.Mutex)
	zoneMu.Lock()
	return zoneMu
}

func (e *EtcdBackend) releaseZoneLock(mu *sync.Mutex) {
	if mu != nil {
		mu.Unlock()
	}
}

// GetZone retrieves a zone by name.
func (e *EtcdBackend) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	key := e.zoneKey(name)
	resp, err := e.client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone: %w", err)
	}

	if resp.Count == 0 {
		return nil, model.ErrZoneNotFound
	}

	var zone model.Zone
	if err := json.Unmarshal(resp.Kvs[0].Value, &zone); err != nil {
		return nil, fmt.Errorf("failed to unmarshal zone: %w", err)
	}

	return &zone, nil
}

// ListZones returns all zones, optionally paginated.
func (e *EtcdBackend) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	prefix := fmt.Sprintf("%s/%s/", e.prefix, etcdZonesPrefix)
	resp, err := e.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to list zones: %w", err)
	}

	zones := make([]*model.Zone, 0, resp.Count)
	for _, kv := range resp.Kvs {
		var zone model.Zone
		if err := json.Unmarshal(kv.Value, &zone); err != nil {
			return nil, fmt.Errorf("failed to unmarshal zone at key %s: %w", string(kv.Key), err)
		}
		zones = append(zones, &zone)
	}

	// Sort deterministically by zone name
	sort.Slice(zones, func(i, j int) bool {
		return zones[i].Name < zones[j].Name
	})

	// Apply pagination
	start := opts.Offset
	if start < 0 {
		start = 0
	}
	if start > len(zones) {
		return make([]*model.Zone, 0), nil
	}

	// Limit==0 means return all (no limit)
	if opts.Limit <= 0 {
		return zones[start:], nil
	}

	end := start + opts.Limit
	if end > len(zones) {
		end = len(zones)
	}

	return zones[start:end], nil
}

// ListZoneSummaries returns zone names and versions without loading zone records.
func (e *EtcdBackend) ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	prefix := e.versionPrefix()
	getOpts := []clientv3.OpOption{
		clientv3.WithPrefix(),
		clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend),
	}
	if opts.Limit > 0 {
		getOpts = append(getOpts, clientv3.WithLimit(int64(offset+opts.Limit)))
	}

	resp, err := e.client.Get(ctx, prefix, getOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to list zone summaries: %w", err)
	}

	if offset > len(resp.Kvs) {
		return make([]*ZoneSummary, 0), nil
	}

	end := len(resp.Kvs)
	if opts.Limit > 0 && offset+opts.Limit < end {
		end = offset + opts.Limit
	}

	summaries := make([]*ZoneSummary, 0, end-offset)
	for _, kv := range resp.Kvs[offset:end] {
		name := strings.TrimPrefix(string(kv.Key), prefix)
		summaries = append(summaries, &ZoneSummary{
			Name:    name,
			Version: string(kv.Value),
		})
	}

	return summaries, nil
}

// CreateZone creates a new zone.
func (e *EtcdBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
	writeZone, err := prepareZoneForCreate(zone, model.NormalizeZoneName)
	if err != nil {
		return err
	}
	normalized := writeZone.Name

	// Acquire zone lock
	zoneMu := e.acquireZoneLock(normalized)
	defer e.releaseZoneLock(zoneMu)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Marshal zone data
	zoneData, err := json.Marshal(writeZone)
	if err != nil {
		return fmt.Errorf("failed to marshal zone: %w", err)
	}

	// Transaction: create zone + version metadata + history snapshot
	zoneKey := e.zoneKey(normalized)
	versionKey := e.versionKey(normalized)
	historyKey := e.historyKey(normalized, writeZone.Version)

	txn := e.client.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(zoneKey), "=", 0)).
		Then(
			clientv3.OpPut(zoneKey, string(zoneData)),
			clientv3.OpPut(versionKey, writeZone.Version),
			clientv3.OpPut(historyKey, string(zoneData)),
		)

	resp, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to create zone: %w", err)
	}

	if !resp.Succeeded {
		return model.ErrZoneAlreadyExists
	}

	// Watch events will be triggered by etcd's watch mechanism
	copyZoneInto(zone, writeZone)
	return nil
}

// UpdateZone updates an existing zone with optimistic locking.
func (e *EtcdBackend) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	normalized := model.NormalizeZoneName(zone.Name)
	zone.Name = normalized

	// Acquire zone lock
	zoneMu := e.acquireZoneLock(normalized)
	defer e.releaseZoneLock(zoneMu)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Get current zone for CreatedAt, existence check, and ModRevision compare.
	zoneKey := e.zoneKey(normalized)
	resp, err := e.client.Get(ctx, zoneKey)
	if err != nil {
		return fmt.Errorf("failed to get zone: %w", err)
	}
	if resp.Count == 0 {
		return model.ErrZoneNotFound
	}
	modRevision := resp.Kvs[0].ModRevision

	var currentZone model.Zone
	if err := json.Unmarshal(resp.Kvs[0].Value, &currentZone); err != nil {
		return fmt.Errorf("failed to unmarshal zone: %w", err)
	}

	// Check version (optimistic locking) only if expectedVersion is provided
	if expectedVersion != "" && currentZone.Version != expectedVersion {
		return model.ErrConflict
	}

	versionKey := e.versionKey(normalized)

	// Preserve CreatedAt from current zone
	zone.CreatedAt = currentZone.CreatedAt

	// Advance from the stored serial. A caller may provide a precomputed
	// greater serial when another component already used it for a prepared artifact.
	zone.SOA.Serial = updateSOASerial(currentZone.SOA.Serial, zone.SOA.Serial)

	// Update timestamp
	zone.UpdatedAt = time.Now()

	// Ensure version changes on update (normally issued by controller).
	if zone.Version == "" || zone.Version == currentZone.Version {
		newVersion, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = newVersion
	}

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	// Marshal zone data
	zoneData, err := json.Marshal(zone)
	if err != nil {
		return fmt.Errorf("failed to marshal zone: %w", err)
	}

	// Transaction: update zone + version metadata + history snapshot
	historyKey := e.historyKey(normalized, zone.Version)

	cmps := []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(zoneKey), "=", modRevision),
	}
	if expectedVersion != "" {
		cmps = append(cmps, clientv3.Compare(clientv3.Value(versionKey), "=", expectedVersion))
	}

	txn := e.client.Txn(ctx).If(cmps...).Then(
		clientv3.OpPut(zoneKey, string(zoneData)),
		clientv3.OpPut(versionKey, zone.Version),
		clientv3.OpPut(historyKey, string(zoneData)),
	)

	txnResp, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to update zone: %w", err)
	}

	if !txnResp.Succeeded {
		return model.ErrConflict
	}

	// Clean up old history entries (keep last N versions)
	go e.cleanupHistory(context.Background(), normalized)

	// Watch events will be triggered by etcd's watch mechanism
	return nil
}

// UpdateDNSSECMetadata updates DNSSEC metadata without changing zone version or SOA serial.
func (e *EtcdBackend) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	normalized := model.NormalizeZoneName(zoneName)

	zoneMu := e.acquireZoneLock(normalized)
	defer e.releaseZoneLock(zoneMu)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	zoneKey := e.zoneKey(normalized)
	resp, err := e.client.Get(ctx, zoneKey)
	if err != nil {
		return fmt.Errorf("failed to get zone: %w", err)
	}
	if resp.Count == 0 {
		return model.ErrZoneNotFound
	}
	modRevision := resp.Kvs[0].ModRevision

	var zone model.Zone
	if err := json.Unmarshal(resp.Kvs[0].Value, &zone); err != nil {
		return fmt.Errorf("failed to unmarshal zone: %w", err)
	}

	zone.DNSSEC = cloneDNSSECConfig(dnssec)
	zone.UpdatedAt = time.Now()

	zoneData, err := json.Marshal(&zone)
	if err != nil {
		return fmt.Errorf("failed to marshal zone: %w", err)
	}

	txn := e.client.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(zoneKey), "=", modRevision)).
		Then(clientv3.OpPut(zoneKey, string(zoneData)))

	txnResp, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to update DNSSEC metadata: %w", err)
	}
	if !txnResp.Succeeded {
		existsResp, err := e.client.Get(ctx, zoneKey)
		if err != nil {
			return fmt.Errorf("check zone existence after DNSSEC metadata conflict: %w", err)
		}
		if existsResp.Count == 0 {
			return model.ErrZoneNotFound
		}
		return model.ErrConflict
	}
	return nil
}

// DeleteZone removes a zone and all its records.
func (e *EtcdBackend) DeleteZone(ctx context.Context, name string) error {
	normalized := model.NormalizeZoneName(name)

	// Acquire zone lock
	zoneMu := e.acquireZoneLock(normalized)
	defer e.releaseZoneLock(zoneMu)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Check if zone exists
	zoneKey := e.zoneKey(normalized)
	resp, err := e.client.Get(ctx, zoneKey)
	if err != nil {
		return fmt.Errorf("failed to check zone existence: %w", err)
	}

	if resp.Count == 0 {
		return model.ErrZoneNotFound
	}
	modRevision := resp.Kvs[0].ModRevision

	// Delete zone + version metadata (history is kept for audit)
	versionKey := e.versionKey(normalized)

	txn := e.client.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(zoneKey), "=", modRevision)).
		Then(
			clientv3.OpDelete(zoneKey),
			clientv3.OpDelete(versionKey),
		)

	txnResp, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to delete zone: %w", err)
	}
	if !txnResp.Succeeded {
		existsResp, err := e.client.Get(ctx, zoneKey)
		if err != nil {
			return fmt.Errorf("check zone existence after delete conflict: %w", err)
		}
		if existsResp.Count == 0 {
			return model.ErrZoneNotFound
		}
		return model.ErrConflict
	}

	// Watch events will be triggered by etcd's watch mechanism
	return nil
}

// DeleteZoneWithVersion removes a zone only when its current version matches.
func (e *EtcdBackend) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	normalized := model.NormalizeZoneName(name)

	zoneMu := e.acquireZoneLock(normalized)
	defer e.releaseZoneLock(zoneMu)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	zoneKey := e.zoneKey(normalized)
	versionKey := e.versionKey(normalized)

	resp, err := e.client.Get(ctx, zoneKey)
	if err != nil {
		return fmt.Errorf("failed to check zone existence: %w", err)
	}
	if resp.Count == 0 {
		return model.ErrZoneNotFound
	}
	modRevision := resp.Kvs[0].ModRevision

	cmps := []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(zoneKey), "=", modRevision),
	}
	if expectedVersion != "" {
		cmps = append(cmps, clientv3.Compare(clientv3.Value(versionKey), "=", expectedVersion))
	}

	txn := e.client.Txn(ctx).If(cmps...).Then(
		clientv3.OpDelete(zoneKey),
		clientv3.OpDelete(versionKey),
	)

	txnResp, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("failed to delete zone: %w", err)
	}
	if !txnResp.Succeeded {
		existsResp, err := e.client.Get(ctx, zoneKey)
		if err != nil {
			return fmt.Errorf("check zone existence after delete conflict: %w", err)
		}
		if existsResp.Count == 0 {
			return model.ErrZoneNotFound
		}
		return model.ErrConflict
	}

	return nil
}

// Close releases resources.
func (e *EtcdBackend) Close() error {
	// Close the client first to cancel all watches
	if e == nil || e.client == nil {
		return nil
	}
	err := e.client.Close()

	// Note: Watch channels are closed by their respective runWatch goroutines
	// when the context is cancelled. We don't close them here to avoid double-close panics.

	return err
}

// Info returns backend metadata.
func (e *EtcdBackend) Info() BackendInfo {
	return BackendInfo{
		Type: "etcd",
		Capabilities: []string{
			CapabilityZoneStore,
			CapabilityZoneSummaryStore,
			CapabilityZoneCountStore,
			CapabilityHealthStore,
			CapabilityDNSSECMetadataStore,
			CapabilityConditionalDeleteStore,
			CapabilityRevisionStore,
			CapabilityWatchableStore,
		},
		Consistency: "strong",
		Description: "etcd storage with revision history and watch notifications",
	}
}

// RevisionStore implementation

// GetRevision retrieves a specific version of a zone.
func (e *EtcdBackend) GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error) {
	normalized := model.NormalizeZoneName(zoneName)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	historyKey := e.historyKey(normalized, version)
	resp, err := e.client.Get(ctx, historyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get revision: %w", err)
	}

	if resp.Count == 0 {
		return nil, model.ErrVersionNotFound
	}

	var zone model.Zone
	if err := json.Unmarshal(resp.Kvs[0].Value, &zone); err != nil {
		return nil, fmt.Errorf("failed to unmarshal zone: %w", err)
	}

	return &zone, nil
}

// ListRevisions returns all versions of a zone in reverse chronological order.
func (e *EtcdBackend) ListRevisions(ctx context.Context, zoneName string, opts ListOptions) ([]*model.ZoneVersion, error) {
	normalized := model.NormalizeZoneName(zoneName)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	prefix := e.historyPrefixForZone(normalized)
	resp, err := e.client.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, fmt.Errorf("failed to list revisions: %w", err)
	}

	versions := make([]*model.ZoneVersion, 0, resp.Count)
	for _, kv := range resp.Kvs {
		var zone model.Zone
		if err := json.Unmarshal(kv.Value, &zone); err != nil {
			return nil, fmt.Errorf("failed to unmarshal revision at key %s: %w", string(kv.Key), err)
		}

		hashHex, err := ComputeZoneHash(&zone)
		if err != nil {
			hashHex = ""
		}
		hash8 := ""
		if len(hashHex) >= 8 {
			hash8 = hashHex[:8]
		}

		versions = append(versions, &model.ZoneVersion{
			Version:   zone.Version,
			Serial:    zone.SOA.Serial,
			Timestamp: zone.UpdatedAt,
			Hash:      hashHex,
			Hash8:     hash8,
		})
	}

	// Apply pagination
	start := opts.Offset
	if start < 0 {
		start = 0
	}
	if start > len(versions) {
		return make([]*model.ZoneVersion, 0), nil
	}

	// Limit==0 means return all (no limit)
	if opts.Limit <= 0 {
		return versions[start:], nil
	}

	end := start + opts.Limit
	if end > len(versions) {
		end = len(versions)
	}

	return versions[start:end], nil
}

// GetCurrentVersion returns the current version identifier for a zone.
func (e *EtcdBackend) GetCurrentVersion(ctx context.Context, zoneName string) (string, error) {
	normalized := model.NormalizeZoneName(zoneName)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	versionKey := e.versionKey(normalized)
	resp, err := e.client.Get(ctx, versionKey)
	if err != nil {
		return "", fmt.Errorf("failed to get current version: %w", err)
	}

	if resp.Count == 0 {
		return "", model.ErrZoneNotFound
	}

	return string(resp.Kvs[0].Value), nil
}

// WatchableStore implementation

// Watch returns a channel that receives zone change events.
func (e *EtcdBackend) Watch(ctx context.Context, zoneName string) (<-chan ZoneEvent, error) {
	normalized := ""
	if zoneName != "" {
		normalized = model.NormalizeZoneName(zoneName)
	}

	// Create buffered channel
	eventChan := make(chan ZoneEvent, 100)

	// Register watcher
	e.watchMu.Lock()
	e.watchers[normalized] = append(e.watchers[normalized], eventChan)
	e.watchMu.Unlock()

	// Start etcd watch in background
	go e.runWatch(ctx, normalized, eventChan)

	return eventChan, nil
}

// runWatch runs the etcd watch loop.
func (e *EtcdBackend) runWatch(ctx context.Context, zoneName string, eventChan chan ZoneEvent) {
	defer func() {
		// Close channel first to prevent further sends
		close(eventChan)

		// Then unregister watcher
		e.watchMu.Lock()
		watchers := e.watchers[zoneName]
		for i, ch := range watchers {
			if ch == eventChan {
				e.watchers[zoneName] = append(watchers[:i], watchers[i+1:]...)
				break
			}
		}
		e.watchMu.Unlock()
	}()

	// Determine watch key
	var watchKey string
	if zoneName == "" {
		watchKey = fmt.Sprintf("%s/%s/", e.prefix, etcdZonesPrefix)
	} else {
		watchKey = e.zoneKey(zoneName)
	}

	// Start watch
	opts := []clientv3.OpOption{clientv3.WithPrevKV()}
	if zoneName == "" {
		opts = append(opts, clientv3.WithPrefix())
	}

	watchChan := e.client.Watch(ctx, watchKey, opts...)

	// Process watch events
	for {
		select {
		case <-ctx.Done():
			return
		case resp, ok := <-watchChan:
			if !ok {
				return
			}

			if resp.Canceled {
				return
			}

			for _, ev := range resp.Events {
				event := e.convertEtcdEvent(ev)
				if event != nil {
					select {
					case eventChan <- *event:
					case <-ctx.Done():
						return
					default:
						// Channel full, drop event (best effort)
					}
				}
			}
		}
	}
}

// convertEtcdEvent converts an etcd event to a ZoneEvent.
func (e *EtcdBackend) convertEtcdEvent(ev *clientv3.Event) *ZoneEvent {
	// Extract zone name from key
	keyPrefix := fmt.Sprintf("%s/%s/", e.prefix, etcdZonesPrefix)
	if !strings.HasPrefix(string(ev.Kv.Key), keyPrefix) {
		return nil
	}
	zoneName := strings.TrimPrefix(string(ev.Kv.Key), keyPrefix)

	switch ev.Type {
	case clientv3.EventTypePut:
		var zone model.Zone
		if err := json.Unmarshal(ev.Kv.Value, &zone); err != nil {
			return nil
		}

		eventType := EventTypeUpdated
		if ev.PrevKv == nil {
			eventType = EventTypeCreated
		}

		// Deep copy zone to prevent caller mutation
		zoneCopy := zone
		zoneCopy.Records = make([]model.Record, len(zone.Records))
		copy(zoneCopy.Records, zone.Records)

		return &ZoneEvent{
			Type:     eventType,
			ZoneName: zoneName,
			Version:  zone.Version,
			Zone:     &zoneCopy,
		}

	case clientv3.EventTypeDelete:
		return &ZoneEvent{
			Type:     EventTypeDeleted,
			ZoneName: zoneName,
		}

	default:
		return nil
	}
}

// cleanupHistory removes old history entries, keeping only the last N versions.
func (e *EtcdBackend) cleanupHistory(ctx context.Context, zoneName string) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	prefix := e.historyPrefixForZone(zoneName)
	resp, err := e.client.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return
	}

	// Keep only last N versions
	if int(resp.Count) > defaultHistoryRetention {
		for i := defaultHistoryRetention; i < len(resp.Kvs); i++ {
			_, _ = e.client.Delete(ctx, string(resp.Kvs[i].Key))
		}
	}
}
