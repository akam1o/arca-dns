package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	agentsync "github.com/akam1o/arca-dns/internal/agent/sync"
	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupTest(t *testing.T) (*Handler, *backend.MemoryBackend, *httptest.Server) {
	t.Helper()

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)
	store := backend.NewMemoryBackend()
	// Create handler without signing service for backward compatibility
	handler := NewHandler(store, nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = false
	apiCfg.RateLimit.Enabled = false
	router := SetupRouter(handler, &apiCfg, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
	}
	server := httptest.NewUnstartedServer(router)
	server.Listener = ln
	server.Start()
	return handler, store, server
}

func marshalCreateZoneRequest(t *testing.T, zone *model.Zone) []byte {
	t.Helper()

	body, err := json.Marshal(createZoneRequest{
		Name:    zone.Name,
		SOA:     zone.SOA,
		Records: zone.Records,
	})
	require.NoError(t, err)
	return body
}

func marshalUpdateZoneRequest(t *testing.T, zone *model.Zone) []byte {
	t.Helper()

	body, err := json.Marshal(updateZoneRequest{
		Name: zone.Name,
		SOA:  zone.SOA,
	})
	require.NoError(t, err)
	return body
}

func decodeAPIError(t *testing.T, body io.Reader) model.APIError {
	t.Helper()

	var apiErr model.APIError
	require.NoError(t, json.NewDecoder(body).Decode(&apiErr))
	return apiErr
}

type readinessFailingStore struct {
	*backend.MemoryBackend
}

func (s *readinessFailingStore) HealthCheck(ctx context.Context) error {
	return errors.New("dial tcp db.internal:5432: schema path /var/lib/arca-dns")
}

func (s *readinessFailingStore) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	return nil, errors.New("dial tcp db.internal:5432: schema path /var/lib/arca-dns")
}

type readinessHealthStore struct {
	*backend.MemoryBackend
	healthCalls int
	listCalls   int
}

func (s *readinessHealthStore) HealthCheck(ctx context.Context) error {
	s.healthCalls++
	return nil
}

func (s *readinessHealthStore) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	s.listCalls++
	return nil, errors.New("ListZones should not be used for readiness")
}

type zoneStoreWithoutConditionalDelete struct {
	inner backend.ZoneStore
}

func (s *zoneStoreWithoutConditionalDelete) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	return s.inner.GetZone(ctx, name)
}

func (s *zoneStoreWithoutConditionalDelete) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	return s.inner.ListZones(ctx, opts)
}

func (s *zoneStoreWithoutConditionalDelete) CreateZone(ctx context.Context, zone *model.Zone) error {
	return s.inner.CreateZone(ctx, zone)
}

func (s *zoneStoreWithoutConditionalDelete) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	return s.inner.UpdateZone(ctx, zone, expectedVersion)
}

func (s *zoneStoreWithoutConditionalDelete) DeleteZone(ctx context.Context, name string) error {
	return s.inner.DeleteZone(ctx, name)
}

func (s *zoneStoreWithoutConditionalDelete) Close() error {
	return s.inner.Close()
}

type singleZoneStore struct {
	zone *model.Zone
}

func (s *singleZoneStore) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	if s.zone == nil || model.NormalizeZoneName(s.zone.Name) != model.NormalizeZoneName(name) {
		return nil, model.ErrZoneNotFound
	}
	return cloneAPITestZone(s.zone), nil
}

func (s *singleZoneStore) ListZones(ctx context.Context, opts backend.ListOptions) ([]*model.Zone, error) {
	if s.zone == nil {
		return []*model.Zone{}, nil
	}
	return []*model.Zone{cloneAPITestZone(s.zone)}, nil
}

func (s *singleZoneStore) CreateZone(ctx context.Context, zone *model.Zone) error {
	if s.zone != nil {
		return model.ErrZoneAlreadyExists
	}
	s.zone = cloneAPITestZone(zone)
	return nil
}

func (s *singleZoneStore) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	if s.zone == nil || model.NormalizeZoneName(s.zone.Name) != model.NormalizeZoneName(zone.Name) {
		return model.ErrZoneNotFound
	}
	if expectedVersion != "" && expectedVersion != s.zone.Version {
		return model.ErrConflict
	}
	s.zone = cloneAPITestZone(zone)
	return nil
}

func (s *singleZoneStore) DeleteZone(ctx context.Context, name string) error {
	if s.zone == nil || model.NormalizeZoneName(s.zone.Name) != model.NormalizeZoneName(name) {
		return model.ErrZoneNotFound
	}
	s.zone = nil
	return nil
}

func (s *singleZoneStore) Close() error {
	return nil
}

func cloneAPITestZone(zone *model.Zone) *model.Zone {
	if zone == nil {
		return nil
	}
	copied := *zone
	copied.Records = make([]model.Record, len(zone.Records))
	copy(copied.Records, zone.Records)
	for i := range copied.Records {
		if copied.Records[i].Priority != nil {
			priority := *copied.Records[i].Priority
			copied.Records[i].Priority = &priority
		}
	}
	return &copied
}

func apiTestApexNSRecord() model.Record {
	return model.Record{Name: "@", Type: model.RecordTypeNS, TTL: 300, Value: "ns1.example.com."}
}

func apiRecordsExceptType(records []model.Record, recordType string) []model.Record {
	filtered := make([]model.Record, 0, len(records))
	for _, record := range records {
		if record.Type != recordType {
			filtered = append(filtered, record)
		}
	}
	return filtered
}

func apiRecordByNameType(records []model.Record, name, recordType string) *model.Record {
	for i := range records {
		if records[i].Name == name && records[i].Type == recordType {
			return &records[i]
		}
	}
	return nil
}

func TestCreateZone(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	body := marshalCreateZoneRequest(t, zone)
	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))
	assert.Equal(t, "/api/v1/zones/example.com.", resp.Header.Get("Location"))

	var created model.Zone
	err = json.NewDecoder(resp.Body).Decode(&created)
	require.NoError(t, err)
	assert.Equal(t, "example.com.", created.Name)
	assert.NotEmpty(t, created.Version)
	assert.NotZero(t, created.SOA.Serial)
}

func TestCreateZone_RejectsUnknownJSONFields(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	body, err := json.Marshal(map[string]interface{}{
		"name":       "unknown.example.",
		"version":    "client-version",
		"soa":        model.DefaultSOA("ns1.unknown.example.", "admin.unknown.example."),
		"records":    []model.Record{apiTestApexNSRecord()},
		"unexpected": true,
	})
	require.NoError(t, err)

	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	apiErr := decodeAPIError(t, resp.Body)
	assert.Equal(t, model.ErrorCodeInvalidInput, apiErr.Code)
	assert.Equal(t, "Invalid request body", apiErr.Message)
	assert.Equal(t, "invalid_request_body", apiErr.Details["reason"])
	assert.Equal(t, "body", apiErr.Details["field"])
	assert.Contains(t, apiErr.Details["error"], "unknown field")
	_, err = store.GetZone(context.Background(), "unknown.example.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestCreateZone_RejectsMalformedJSONWithSafeDetails(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", strings.NewReader(`{"name":`))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	apiErr := decodeAPIError(t, resp.Body)
	assert.Equal(t, model.ErrorCodeInvalidInput, apiErr.Code)
	assert.Equal(t, "Invalid request body", apiErr.Message)
	assert.Equal(t, "invalid_request_body", apiErr.Details["reason"])
	assert.Equal(t, "body", apiErr.Details["field"])
	assert.NotEqual(t, "internal error", apiErr.Details["error"])
}

func TestCreateZone_IgnoresClientManagedRecordIDs(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	body, err := json.Marshal(map[string]interface{}{
		"name": "managed.example.",
		"soa":  model.DefaultSOA("ns1.managed.example.", "admin.managed.example."),
		"records": []map[string]interface{}{
			{
				"name":  "@",
				"type":  "NS",
				"ttl":   300,
				"value": "ns1.managed.example.",
			},
			{
				"id":    "client-record-id",
				"name":  "@",
				"type":  "A",
				"ttl":   300,
				"value": "192.0.2.1",
			},
		},
	})
	require.NoError(t, err)

	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var created model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	assert.False(t, created.CreatedAt.IsZero())
	assert.False(t, created.UpdatedAt.IsZero())
	assert.Nil(t, created.DNSSEC)
	require.Len(t, created.Records, 2)
	createdA := apiRecordByNameType(created.Records, "@", model.RecordTypeA)
	require.NotNil(t, createdA)
	assert.NotEmpty(t, createdA.ID)
	assert.NotEqual(t, "client-record-id", createdA.ID)

	persisted, err := store.GetZone(context.Background(), "managed.example.")
	require.NoError(t, err)
	assert.Nil(t, persisted.DNSSEC)
	require.Len(t, persisted.Records, 2)
	persistedA := apiRecordByNameType(persisted.Records, "@", model.RecordTypeA)
	require.NotNil(t, persistedA)
	assert.NotEqual(t, "client-record-id", persistedA.ID)
}

func TestReadyRedactsBackendErrors(t *testing.T) {
	logger := zap.NewNop()
	store := &readinessFailingStore{MemoryBackend: backend.NewMemoryBackend()}
	handler := NewHandler(store, nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = true
	apiCfg.Auth.APIKeys = nil
	apiCfg.RateLimit.Enabled = false
	router := SetupObservabilityRouter(handler, &apiCfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "not_ready", body["status"])
	assert.Equal(t, "backend unavailable", body["error"])
	assert.NotContains(t, w.Body.String(), "db.internal")
	assert.NotContains(t, w.Body.String(), "/var/lib/arca-dns")
}

func TestReadyUsesBackendHealthCheck(t *testing.T) {
	logger := zap.NewNop()
	store := &readinessHealthStore{MemoryBackend: backend.NewMemoryBackend()}
	handler := NewHandler(store, nil, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)
	apiCfg := config.DefaultControllerConfig().API
	apiCfg.Auth.Enabled = false
	apiCfg.RateLimit.Enabled = false
	router := SetupObservabilityRouter(handler, &apiCfg, logger)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, store.healthCalls)
	assert.Equal(t, 0, store.listCalls)
}

func TestHeadZoneReturnsETagWithoutBody(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.Background(), zone))

	resp, err := http.Head(server.URL + "/api/v1/zones/example.com.")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	etag := resp.Header.Get("ETag")
	assert.NotEmpty(t, etag)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, body)

	req, err := http.NewRequest(http.MethodHead, server.URL+"/api/v1/zones/example.com.", nil)
	require.NoError(t, err)
	req.Header.Set("If-None-Match", etag)
	conditionalResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer conditionalResp.Body.Close()

	assert.Equal(t, http.StatusNotModified, conditionalResp.StatusCode)
	assert.Equal(t, etag, conditionalResp.Header.Get("ETag"))
}

func TestHeadSignedZoneReturnsArtifactHeadersWithoutBody(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.Background(), zone))

	resp, err := http.Head(server.URL + "/api/v1/zones/example.com./signed")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	etag := resp.Header.Get("ETag")
	assert.NotEmpty(t, etag)
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Hash"))
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Hash8"))
	assert.Equal(t, "attachment; filename=example.com.zone.signed", resp.Header.Get("Content-Disposition"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, body)

	req, err := http.NewRequest(http.MethodHead, server.URL+"/api/v1/zones/example.com./signed", nil)
	require.NoError(t, err)
	req.Header.Set("If-None-Match", etag)
	conditionalResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer conditionalResp.Body.Close()

	assert.Equal(t, http.StatusNotModified, conditionalResp.StatusCode)
	assert.Equal(t, etag, conditionalResp.Header.Get("ETag"))
}

func TestCreateZone_Duplicate(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}

	body := marshalCreateZoneRequest(t, zone)

	// First create should succeed
	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Second create should fail with conflict
	body = marshalCreateZoneRequest(t, zone)
	resp, err = http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestCreateZone_RejectsDuplicateRecords(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.1"},
		},
	}

	body := marshalCreateZoneRequest(t, zone)
	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	apiErr := decodeAPIError(t, resp.Body)
	assert.Equal(t, model.ErrorCodeInvalidInput, apiErr.Code)
	assert.Equal(t, "Zone validation failed", apiErr.Message)
	assert.Equal(t, "validation_failed", apiErr.Details["reason"])
	assert.Equal(t, "zone", apiErr.Details["field"])
	assert.Contains(t, apiErr.Details["error"], "duplicate record")
}

func TestGetZone(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone first
	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Get the zone
	resp, err := http.Get(server.URL + "/api/v1/zones/example.com.")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))

	var retrieved model.Zone
	err = json.NewDecoder(resp.Body).Decode(&retrieved)
	require.NoError(t, err)
	assert.Equal(t, "example.com.", retrieved.Name)
}

func TestGetZone_NotFound(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/v1/zones/nonexistent.com.")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestListZones(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create multiple zones
	zones := []string{"example.com.", "test.com.", "demo.org."}
	for _, name := range zones {
		zone := &model.Zone{
			Name:    name,
			SOA:     model.DefaultSOA("ns1."+name, "admin."+name),
			Records: []model.Record{apiTestApexNSRecord()},
		}
		require.NoError(t, store.CreateZone(context.TODO(), zone))
	}

	// List zones
	resp, err := http.Get(server.URL + "/api/v1/zones")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		Zones      []*model.Zone `json:"zones"`
		Pagination struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
			Count  int `json:"count"`
		} `json:"pagination"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	assert.Len(t, result.Zones, 3)
	assert.Equal(t, 3, result.Pagination.Count)
}

func TestListZones_SummaryFields(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	resp, err := http.Get(server.URL + "/api/v1/zones?fields=summary")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		Zones      []map[string]interface{} `json:"zones"`
		Pagination struct {
			Count int `json:"count"`
		} `json:"pagination"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Len(t, result.Zones, 1)
	assert.Equal(t, "example.com.", result.Zones[0]["name"])
	assert.NotEmpty(t, result.Zones[0]["version"])
	assert.NotContains(t, result.Zones[0], "records")
	assert.Equal(t, 1, result.Pagination.Count)
}

func TestListZones_InvalidFields(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	tests := []string{
		"full",
		"summary,records",
		"records",
	}

	for _, fields := range tests {
		t.Run(fields, func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/zones?fields=" + url.QueryEscape(fields))
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestListZones_Pagination(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create 5 zones
	for i := 1; i <= 5; i++ {
		zone := &model.Zone{
			Name:    "zone" + string(rune('a'+i-1)) + ".com.",
			SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
			Records: []model.Record{apiTestApexNSRecord()},
		}
		require.NoError(t, store.CreateZone(context.TODO(), zone))
	}

	// List with limit
	resp, err := http.Get(server.URL + "/api/v1/zones?limit=2")
	require.NoError(t, err)
	defer resp.Body.Close()

	var result struct {
		Zones      []*model.Zone `json:"zones"`
		Pagination struct {
			Count int `json:"count"`
		} `json:"pagination"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, 2, result.Pagination.Count)
}

func TestListZones_InvalidPagination(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	tests := []string{
		"offset=-1",
		"offset=abc",
		"limit=0",
		"limit=1001",
		"limit=abc",
	}

	for _, query := range tests {
		t.Run(query, func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/zones?" + query)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestUpdateZone(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone first
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Get current version
	retrieved, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	originalVersion := retrieved.Version

	retrieved.SOA.Refresh = 7200

	body := marshalUpdateZoneRequest(t, retrieved)
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", originalVersion)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	assert.NotEqual(t, originalVersion, updated.Version)
	assert.Equal(t, uint32(7200), updated.SOA.Refresh)
	userRecords := apiRecordsExceptType(updated.Records, model.RecordTypeNS)
	assert.Len(t, userRecords, 1)
	assert.Equal(t, "192.0.2.1", userRecords[0].Value)
}

func TestUpdateZone_RejectsWeakIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	retrieved, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	retrieved.SOA.Refresh = 7200

	body := marshalUpdateZoneRequest(t, retrieved)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `W/"`+retrieved.Version+`"`)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	unchanged, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	assert.Equal(t, uint32(3600), unchanged.SOA.Refresh)
}

func TestUpdateZone_NormalizesURLAndBodyNamesBeforeComparison(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	retrieved, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	soa := retrieved.SOA
	soa.Refresh = 7200

	body, err := json.Marshal(map[string]interface{}{
		"name": "example.com.",
		"soa":  soa,
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/EXAMPLE.COM", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", retrieved.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	assert.Equal(t, "example.com.", updated.Name)
	assert.Equal(t, uint32(7200), updated.SOA.Refresh)
}

func TestUpdateZone_OmittedRecordsPreservesExistingRecords(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	retrieved, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	soa := retrieved.SOA
	soa.Refresh = 7200

	body, err := json.Marshal(map[string]interface{}{
		"name": "example.com.",
		"soa":  soa,
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", retrieved.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	assert.Equal(t, uint32(7200), updated.SOA.Refresh)
	userRecords := apiRecordsExceptType(updated.Records, model.RecordTypeNS)
	assert.Len(t, userRecords, 2)
	assert.Equal(t, "192.0.2.1", userRecords[0].Value)
	assert.Equal(t, "192.0.2.2", userRecords[1].Value)
}

func TestUpdateZone_RepairsStoredDerivedPriority(t *testing.T) {
	priority := uint16(20)
	store := &singleZoneStore{
		zone: &model.Zone{
			Name:    "example.com.",
			Version: "v1",
			SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
			Records: []model.Record{
				apiTestApexNSRecord(),
				{Name: "@", Type: model.RecordTypeMX, TTL: 300, Value: "10 mail.example.com.", Priority: &priority},
			},
		},
	}
	_, server := setupTestWithStore(t, store)

	soa := store.zone.SOA
	soa.Refresh = 7200
	body, err := json.Marshal(map[string]interface{}{
		"name": "example.com.",
		"soa":  soa,
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "v1")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	mxRecord := apiRecordByNameType(updated.Records, "@", model.RecordTypeMX)
	require.NotNil(t, mxRecord)
	require.NotNil(t, mxRecord.Priority)
	assert.Equal(t, uint16(10), *mxRecord.Priority)
	storedMX := apiRecordByNameType(store.zone.Records, "@", model.RecordTypeMX)
	require.NotNil(t, storedMX)
	require.NotNil(t, storedMX.Priority)
	assert.Equal(t, uint16(10), *storedMX.Priority)
}

func TestUpdateZone_RejectsUnknownJSONFields(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	retrieved, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	body, err := json.Marshal(map[string]interface{}{
		"name":    "example.com.",
		"soa":     retrieved.SOA,
		"records": []model.Record{},
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", retrieved.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	unchanged, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	userRecords := apiRecordsExceptType(unchanged.Records, model.RecordTypeNS)
	assert.Len(t, userRecords, 1)
	assert.Equal(t, "192.0.2.1", userRecords[0].Value)
}

func TestListRecords(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	resp, err := http.Get(server.URL + "/api/v1/zones/example.com./records")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))

	var body struct {
		Records []model.Record `json:"records"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Len(t, body.Records, 3)
}

func TestRecordIDsDerivedWhenBackendIDMissing(t *testing.T) {
	records := []model.Record{
		{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
	}

	withIDs := recordsWithIDs(records)

	require.Len(t, withIDs, 1)
	assert.NotEmpty(t, withIDs[0].ID)
	assert.Equal(t, 0, findRecordByID(records, withIDs[0].ID))
}

func TestFindRecordByIDAcceptsStoredAndDerivedID(t *testing.T) {
	record := model.Record{ID: "42", Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"}
	records := []model.Record{record}

	assert.Equal(t, 0, findRecordByID(records, "42"))
	assert.Equal(t, 0, findRecordByID(records, derivedRecordID(record)))
}

func TestCreateRecord(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	record := model.Record{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"}
	body, err := json.Marshal(record)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))
	assert.Contains(t, resp.Header.Get("Location"), "/api/v1/zones/example.com./records/")

	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	assert.Len(t, updated.Records, 3)
	createdRecord := apiRecordByNameType(updated.Records, "www", model.RecordTypeA)
	require.NotNil(t, createdRecord)
	assert.Equal(t, "192.0.2.2", createdRecord.Value)
}

func TestCreateRecord_RejectsUnknownJSONFields(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	body, err := json.Marshal(map[string]interface{}{
		"name":       "www",
		"type":       model.RecordTypeA,
		"ttl":        300,
		"value":      "192.0.2.2",
		"unexpected": true,
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	apiErr := decodeAPIError(t, resp.Body)
	assert.Equal(t, model.ErrorCodeInvalidInput, apiErr.Code)
	assert.Equal(t, "Invalid request body", apiErr.Message)
	assert.Equal(t, "invalid_request_body", apiErr.Details["reason"])
	assert.Equal(t, "body", apiErr.Details["field"])
	assert.Contains(t, apiErr.Details["error"], "unknown field")
	unchanged, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	assert.Len(t, unchanged.Records, 1)
}

func TestCreateRecord_RejectsExpandedRelativeNamesTooLong(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	longZone := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 57),
	}, ".") + "."
	require.NoError(t, model.ValidateZoneName(longZone))

	zone := &model.Zone{
		Name: longZone,
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), longZone)
	require.NoError(t, err)

	tests := []struct {
		name       string
		record     model.Record
		errContain string
	}{
		{
			name:       "relative owner",
			record:     model.Record{Name: "host", Type: model.RecordTypeA, TTL: 300, Value: "192.0.2.2"},
			errContain: "expanded record name",
		},
		{
			name:       "relative target",
			record:     model.Record{Name: "@", Type: model.RecordTypeCNAME, TTL: 300, Value: "target"},
			errContain: "expanded domain target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.record)
			require.NoError(t, err)
			req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/"+longZone+"/records", bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("If-Match", current.Version)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			responseBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(responseBody), tt.errContain)
		})
	}
}

func TestCreateRecord_NormalizesDerivedPriority(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	record := model.Record{Name: "@", Type: "MX", TTL: 300, Value: "0 mail.example.com."}
	body, err := json.Marshal(record)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.Len(t, updated.Records, 3)
	mxRecord := apiRecordByNameType(updated.Records, "@", model.RecordTypeMX)
	require.NotNil(t, mxRecord)
	require.NotNil(t, mxRecord.Priority)
	assert.Equal(t, uint16(0), *mxRecord.Priority)
}

func TestCreateRecord_RejectsPriorityMismatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	priority := uint16(20)
	record := model.Record{Name: "@", Type: "MX", TTL: 300, Value: "10 mail.example.com.", Priority: &priority}
	body, err := json.Marshal(record)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	apiErr := decodeAPIError(t, resp.Body)
	assert.Equal(t, model.ErrorCodeInvalidInput, apiErr.Code)
	assert.Equal(t, "Record validation failed", apiErr.Message)
	assert.Equal(t, "validation_failed", apiErr.Details["reason"])
	assert.Equal(t, "record", apiErr.Details["field"])
	assert.Contains(t, apiErr.Details["error"], "priority 20 does not match value priority 10")

	unchanged, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	assert.Len(t, unchanged.Records, 2)
}

func TestUpdateRecord(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, current.Records, 2)
	currentA := apiRecordByNameType(current.Records, "@", model.RecordTypeA)
	require.NotNil(t, currentA)
	recordID := currentA.ID

	record := model.Record{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.9"}
	body, err := json.Marshal(record)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com./records/"+recordID, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.Len(t, updated.Records, 2)
	updatedA := apiRecordByNameType(updated.Records, "@", model.RecordTypeA)
	require.NotNil(t, updatedA)
	assert.Equal(t, recordID, updatedA.ID)
	assert.Equal(t, "192.0.2.9", updatedA.Value)
}

func TestUpdateRecordAcceptsDerivedIDForStoredRecordID(t *testing.T) {
	store, err := backend.NewSQLiteBackend(":memory:")
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.InitSchema())
	_, server := setupTestWithStore(t, store)

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, current.Records, 2)
	currentA := apiRecordByNameType(current.Records, "@", model.RecordTypeA)
	require.NotNil(t, currentA)
	storedID := currentA.ID
	derivedID := derivedRecordID(*currentA)
	require.NotEmpty(t, storedID)
	require.NotEqual(t, storedID, derivedID)

	record := model.Record{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.9"}
	body, err := json.Marshal(record)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com./records/"+derivedID, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.Len(t, updated.Records, 2)
	updatedA := apiRecordByNameType(updated.Records, "@", model.RecordTypeA)
	require.NotNil(t, updatedA)
	assert.Equal(t, storedID, updatedA.ID)
	assert.Equal(t, "192.0.2.9", updatedA.Value)
}

func TestUpdateRecordReleasesDerivedIDForContentAddressedBackends(t *testing.T) {
	store, err := backend.NewGitBackendWithOptions(t.TempDir(), backend.GitBackendOptions{})
	require.NoError(t, err)
	defer store.Close()
	_, server := setupTestWithStore(t, store)

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, current.Records, 2)
	currentA := apiRecordByNameType(current.Records, "@", model.RecordTypeA)
	require.NotNil(t, currentA)
	require.Empty(t, currentA.ID)
	originalDerivedID := derivedRecordID(*currentA)

	updateRecord := model.Record{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.9"}
	body, err := json.Marshal(updateRecord)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com./records/"+originalDerivedID, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.Len(t, updated.Records, 2)
	updatedA := apiRecordByNameType(updated.Records, "@", model.RecordTypeA)
	require.NotNil(t, updatedA)
	updatedID := updatedA.ID
	require.NotEmpty(t, updatedID)
	require.NotEqual(t, originalDerivedID, updatedID)

	persisted, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, persisted.Records, 2)
	persistedA := apiRecordByNameType(persisted.Records, "@", model.RecordTypeA)
	require.NotNil(t, persistedA)
	require.Empty(t, persistedA.ID)

	createRecord := model.Record{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"}
	body, err = json.Marshal(createRecord)
	require.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", updated.Version)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var recreated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&recreated))
	require.Len(t, recreated.Records, 3)
	aRecords := make([]model.Record, 0, 2)
	for _, record := range recreated.Records {
		if record.Type == model.RecordTypeA {
			aRecords = append(aRecords, record)
		}
	}
	require.Len(t, aRecords, 2)
	assert.NotEqual(t, aRecords[0].ID, aRecords[1].ID)
	assert.Contains(t, []string{aRecords[0].ID, aRecords[1].ID}, originalDerivedID)
	assert.Contains(t, []string{aRecords[0].ID, aRecords[1].ID}, updatedID)
}

func TestDeleteRecord(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, current.Records, 3)
	wwwRecord := apiRecordByNameType(current.Records, "www", model.RecordTypeA)
	require.NotNil(t, wwwRecord)
	recordID := wwwRecord.ID

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com./records/"+recordID, nil)
	require.NoError(t, err)
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	userRecords := apiRecordsExceptType(updated.Records, model.RecordTypeNS)
	require.Len(t, userRecords, 1)
	assert.Equal(t, "192.0.2.1", userRecords[0].Value)
}

func TestBulkRecords_CreateUpdateDelete(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "old", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, current.Records, 3)
	rootRecord := apiRecordByNameType(current.Records, "@", model.RecordTypeA)
	require.NotNil(t, rootRecord)
	oldRecord := apiRecordByNameType(current.Records, "old", model.RecordTypeA)
	require.NotNil(t, oldRecord)
	rootID := rootRecord.ID
	oldID := oldRecord.ID

	body, err := json.Marshal(map[string]interface{}{
		"create": []model.Record{
			{Name: "api", Type: "AAAA", TTL: 300, Value: "2001:db8::1"},
		},
		"update": []map[string]interface{}{
			{"id": rootID, "name": "@", "type": "A", "ttl": 300, "value": "192.0.2.9"},
		},
		"delete": []map[string]interface{}{
			{"id": oldID},
		},
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records/batch", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))

	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.Len(t, updated.Records, 3)
	assert.NotEqual(t, current.Version, updated.Version)

	updatedRoot := apiRecordByNameType(updated.Records, "@", model.RecordTypeA)
	require.NotNil(t, updatedRoot)
	assert.Equal(t, "192.0.2.9", updatedRoot.Value)
	createdAPI := apiRecordByNameType(updated.Records, "api", model.RecordTypeAAAA)
	require.NotNil(t, createdAPI)
	assert.Equal(t, "2001:db8::1", createdAPI.Value)
	assert.Nil(t, apiRecordByNameType(updated.Records, "old", model.RecordTypeA))
}

func TestBulkRecords_RollsBackOnMissingRecord(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "old", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, current.Records, 3)
	oldRecord := apiRecordByNameType(current.Records, "old", model.RecordTypeA)
	require.NotNil(t, oldRecord)

	body, err := json.Marshal(map[string]interface{}{
		"create": []model.Record{
			{Name: "api", Type: "AAAA", TTL: 300, Value: "2001:db8::1"},
		},
		"update": []map[string]interface{}{
			{"id": "missing-record", "name": "@", "type": "A", "ttl": 300, "value": "192.0.2.9"},
		},
		"delete": []map[string]interface{}{
			{"id": oldRecord.ID},
		},
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records/batch", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	unchanged, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	assert.Equal(t, current.Version, unchanged.Version)
	assert.Len(t, unchanged.Records, 3)
	assert.NotNil(t, apiRecordByNameType(unchanged.Records, "old", model.RecordTypeA))
}

func TestBulkRecords_RejectsDuplicateResult(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	body, err := json.Marshal(map[string]interface{}{
		"create": []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records/batch", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestBulkRecords_RejectsEmptyOperationSet(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records/batch", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBulkRecords_RejectsTooManyOperations(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	records := make([]model.Record, maxBulkRecordOperations+1)
	for i := range records {
		records[i] = model.Record{Name: "bulk-" + strconv.Itoa(i), Type: "A", TTL: 300, Value: "192.0.2.1"}
	}
	body, err := json.Marshal(map[string]interface{}{
		"create": records,
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records/batch", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var apiErr model.APIError
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&apiErr))
	assert.Equal(t, model.ErrorCodeInvalidInput, apiErr.Code)
	assert.Equal(t, "Bulk request includes too many operations", apiErr.Message)
	assert.Equal(t, float64(maxBulkRecordOperations+1), apiErr.Details["operations"])
	assert.Equal(t, float64(maxBulkRecordOperations), apiErr.Details["max_operations"])

	unchanged, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	assert.Equal(t, current.Version, unchanged.Version)
	assert.Len(t, unchanged.Records, 1)
}

func TestCreateRecord_RequiresIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	record := model.Record{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"}
	body, err := json.Marshal(record)
	require.NoError(t, err)
	resp, err := http.Post(server.URL+"/api/v1/zones/example.com./records", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPreconditionRequired, resp.StatusCode)
}

func TestCreateRecord_RejectsWildcardIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	record := model.Record{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"}
	body, err := json.Marshal(record)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "*")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	unchanged, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, unchanged.Records, 1)
	assert.Equal(t, model.RecordTypeNS, unchanged.Records[0].Type)
	assert.Equal(t, "ns1.example.com.", unchanged.Records[0].Value)
}

func TestCreateRecord_RejectsStaleIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	record := model.Record{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"}
	body, err := json.Marshal(record)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/zones/example.com./records", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "stale-version")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	apiErr := decodeAPIError(t, resp.Body)
	assert.Equal(t, model.ErrorCodeConflict, apiErr.Code)
	assert.Equal(t, "stale-version", apiErr.Details["provided_etag"])
	assert.Equal(t, current.Version, apiErr.Details["current_version"])
}

func TestUpdateZone_PreservesDNSSECMetadata(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
		DNSSEC: &model.DNSSECConfig{
			Enabled:         true,
			Algorithm:       13,
			KSKKeyTag:       12345,
			ZSKKeyTag:       23456,
			NSEC3Enabled:    true,
			NSEC3Iterations: 1,
			NSEC3Salt:       "abcd",
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	retrieved, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	soa := retrieved.SOA
	soa.Refresh = 7200

	body, err := json.Marshal(map[string]interface{}{
		"name": "example.com.",
		"soa":  soa,
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", retrieved.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.NotNil(t, updated.DNSSEC)
	assert.True(t, updated.DNSSEC.Enabled)
	assert.Equal(t, uint8(13), updated.DNSSEC.Algorithm)
	assert.Equal(t, uint16(12345), updated.DNSSEC.KSKKeyTag)
	assert.Equal(t, uint16(23456), updated.DNSSEC.ZSKKeyTag)
	assert.True(t, updated.DNSSEC.NSEC3Enabled)
	assert.Equal(t, uint16(1), updated.DNSSEC.NSEC3Iterations)
	assert.Equal(t, "abcd", updated.DNSSEC.NSEC3Salt)
}

func TestUpdateZone_Conflict(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone
	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	// Try to update with wrong version
	body := marshalUpdateZoneRequest(t, zone)
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "wrong-version")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	apiErr := decodeAPIError(t, resp.Body)
	assert.Equal(t, model.ErrorCodeConflict, apiErr.Code)
	assert.Equal(t, "wrong-version", apiErr.Details["provided_etag"])
	assert.Equal(t, current.Version, apiErr.Details["current_version"])
}

func TestDeleteZone(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone first
	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	// Delete the zone
	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com.", nil)
	req.Header.Set("If-Match", current.Version)
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Verify it's deleted
	_, err = store.GetZone(context.TODO(), "example.com.")
	assert.ErrorIs(t, err, model.ErrZoneNotFound)
}

func TestDeleteZone_NotFound(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/nonexistent.com.", nil)
	req.Header.Set("If-Match", "missing-version")
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDeleteZone_RequiresIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com.", nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPreconditionRequired, resp.StatusCode)
	_, err = store.GetZone(context.TODO(), "example.com.")
	assert.NoError(t, err)
}

func TestDeleteZone_RejectsWildcardIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com.", nil)
	req.Header.Set("If-Match", "*")
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_, err = store.GetZone(context.TODO(), "example.com.")
	assert.NoError(t, err)
}

func TestDeleteZone_RejectsStaleIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com.", nil)
	req.Header.Set("If-Match", "stale-version")
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	apiErr := decodeAPIError(t, resp.Body)
	assert.Equal(t, model.ErrorCodeConflict, apiErr.Code)
	assert.Equal(t, "stale-version", apiErr.Details["provided_etag"])
	assert.Equal(t, current.Version, apiErr.Details["current_version"])
	_, err = store.GetZone(context.TODO(), "example.com.")
	assert.NoError(t, err)
}

func TestDeleteZone_RejectsBackendWithoutConditionalDeleteStore(t *testing.T) {
	inner := backend.NewMemoryBackend()
	store := &zoneStoreWithoutConditionalDelete{inner: inner}
	_, server := setupTestWithStore(t, store)

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)

	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com.", nil)
	req.Header.Set("If-Match", current.Version)
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	_, err = store.GetZone(context.TODO(), "example.com.")
	assert.NoError(t, err)
}

func TestGetSignedZone(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone first
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Get the signed zone file
	resp, err := http.Get(server.URL + "/api/v1/zones/example.com./signed")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Serial"))
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Hash"))
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "attachment; filename=example.com.zone.signed", resp.Header.Get("Content-Disposition"))

	// Verify zone file content
	body, _ := io.ReadAll(resp.Body)
	zoneFile := string(body)
	assert.Contains(t, zoneFile, "$ORIGIN example.com.")
	assert.Contains(t, zoneFile, "192.0.2.1")
	assert.Contains(t, zoneFile, "ns1.example.com.")
}

func TestSignedZoneContentDispositionUsesSafeFilename(t *testing.T) {
	header := signedZoneContentDisposition("../Bad Zone\r\nX-Injected: yes.")

	assert.Equal(t, "attachment; filename=__bad_zone__x-injected__yes.zone.signed", header)
	assert.NotContains(t, header, "\r")
	assert.NotContains(t, header, "\n")
	assert.NotContains(t, header, "/")
}

func TestGetSignedZone_WithArtifactSignature(t *testing.T) {
	handler, store, server := setupTest(t)
	defer server.Close()
	handler.SetArtifactSignatureKey("test-signature-key")

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	resp, err := http.Get(server.URL + "/api/v1/zones/example.com./signed")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, signArtifact(string(body), "test-signature-key"), resp.Header.Get("X-Zone-Signature"))
}

func TestGetSignedZone_AgentClientVerifiesArtifactSignature(t *testing.T) {
	handler, store, server := setupTest(t)
	defer server.Close()
	handler.SetArtifactSignatureKey("test-signature-key")

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	client, err := agentsync.NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    10 * time.Millisecond,
	})
	require.NoError(t, err)
	defer client.Close()
	client.SetSignatureVerification(true, "test-signature-key")

	zoneFile, _, notModified, err := client.FetchSignedZone(context.Background(), "example.com.", "")
	require.NoError(t, err)
	assert.False(t, notModified)
	assert.Contains(t, zoneFile, "192.0.2.1")
}

func TestGetSignedZone_NotModified(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone
	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Get signed artifact to retrieve its content ETag.
	firstResp, err := http.Get(server.URL + "/api/v1/zones/example.com./signed")
	require.NoError(t, err)
	etag := firstResp.Header.Get("ETag")
	require.NotEmpty(t, etag)
	require.Equal(t, http.StatusOK, firstResp.StatusCode)
	require.NoError(t, firstResp.Body.Close())

	// Request with If-None-Match
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/zones/example.com./signed", nil)
	req.Header.Set("If-None-Match", etag)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotModified, resp.StatusCode)
	assert.Equal(t, etag, resp.Header.Get("ETag"))
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Serial"))

	// Body should be empty for 304
	body, _ := io.ReadAll(resp.Body)
	assert.Empty(t, body)
}

func TestGetSignedZone_NotFound(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/v1/zones/nonexistent.com./signed")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestUpdateZone_MissingIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone
	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Try to update without If-Match header
	body := marshalUpdateZoneRequest(t, zone)
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No If-Match header

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPreconditionRequired, resp.StatusCode)
}

func TestUpdateZone_RejectsWildcardIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{apiTestApexNSRecord()},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	zone.SOA.Refresh = 7200
	body := marshalUpdateZoneRequest(t, zone)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "*")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	unchanged, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	assert.Equal(t, uint32(3600), unchanged.SOA.Refresh)
}
