package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestCreateZone(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}

	body, err := json.Marshal(zone)
	require.NoError(t, err)
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

func TestCreateZone_Duplicate(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}

	body, err := json.Marshal(zone)
	require.NoError(t, err)

	// First create should succeed
	resp, err := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Second create should fail with conflict
	body, err = json.Marshal(zone)
	require.NoError(t, err)
	resp, err = http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestGetZone(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone first
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
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
			Name: name,
			SOA:  model.DefaultSOA("ns1."+name, "admin."+name),
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

func TestListZones_Pagination(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create 5 zones
	for i := 1; i <= 5; i++ {
		zone := &model.Zone{
			Name: "zone" + string(rune('a'+i-1)) + ".com.",
			SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
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

func TestUpdateZone(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone first
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Get current version
	retrieved, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	originalVersion := retrieved.Version

	// Update the zone. Records in a zone update request are ignored; record
	// mutations belong to record-specific workflows.
	retrieved.SOA.Refresh = 7200
	retrieved.Records = append(retrieved.Records, model.Record{
		Name:  "www",
		Type:  "A",
		TTL:   300,
		Value: "192.0.2.2",
	})

	body, _ := json.Marshal(retrieved)
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
	assert.Len(t, updated.Records, 1)
	assert.Equal(t, "192.0.2.1", updated.Records[0].Value)
}

func TestUpdateZone_OmittedRecordsPreservesExistingRecords(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
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
	assert.Len(t, updated.Records, 2)
	assert.Equal(t, "192.0.2.1", updated.Records[0].Value)
	assert.Equal(t, "192.0.2.2", updated.Records[1].Value)
}

func TestUpdateZone_EmptyRecordsPreservesExistingRecords(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
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

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	assert.Len(t, updated.Records, 1)
	assert.Equal(t, "192.0.2.1", updated.Records[0].Value)
}

func TestListRecords(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
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
	assert.Len(t, body.Records, 2)
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

func TestCreateRecord(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
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
	assert.Len(t, updated.Records, 2)
	assert.Equal(t, "www", updated.Records[1].Name)
	assert.Equal(t, "192.0.2.2", updated.Records[1].Value)
}

func TestUpdateRecord(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, current.Records, 1)
	recordID := current.Records[0].ID

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
	require.Len(t, updated.Records, 1)
	assert.Equal(t, recordID, updated.Records[0].ID)
	assert.Equal(t, "192.0.2.9", updated.Records[0].Value)
}

func TestDeleteRecord(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			{Name: "@", Type: "A", TTL: 300, Value: "192.0.2.1"},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.2"},
		},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))
	current, err := store.GetZone(context.TODO(), "example.com.")
	require.NoError(t, err)
	require.Len(t, current.Records, 2)
	recordID := current.Records[1].ID

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com./records/"+recordID, nil)
	require.NoError(t, err)
	req.Header.Set("If-Match", current.Version)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var updated model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.Len(t, updated.Records, 1)
	assert.Equal(t, "192.0.2.1", updated.Records[0].Value)
}

func TestCreateRecord_RequiresIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{},
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

func TestCreateRecord_RejectsStaleIfMatch(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name:    "example.com.",
		SOA:     model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{},
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

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
}

func TestUpdateZone_PreservesDNSSECMetadata(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
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
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Try to update with wrong version
	body, _ := json.Marshal(zone)
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "wrong-version")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestDeleteZone(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone first
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Delete the zone
	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com.", nil)
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
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestGetSignedZone(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone first
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
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

	// Verify zone file content
	body, _ := io.ReadAll(resp.Body)
	zoneFile := string(body)
	assert.Contains(t, zoneFile, "$ORIGIN example.com.")
	assert.Contains(t, zoneFile, "192.0.2.1")
	assert.Contains(t, zoneFile, "ns1.example.com.")
}

func TestGetSignedZone_NotModified(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
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
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}
	require.NoError(t, store.CreateZone(context.TODO(), zone))

	// Try to update without If-Match header
	body, _ := json.Marshal(zone)
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No If-Match header

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPreconditionRequired, resp.StatusCode)
}
