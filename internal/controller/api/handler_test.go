package api

import (
	"bytes"
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

	logger, _ := zap.NewDevelopment()
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

	body, _ := json.Marshal(zone)
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

	body, _ := json.Marshal(zone)

	// First create should succeed
	resp, _ := http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Second create should fail with conflict
	body, _ = json.Marshal(zone)
	resp, _ = http.Post(server.URL+"/api/v1/zones", "application/json", bytes.NewReader(body))
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
	store.CreateZone(nil, zone)

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
		store.CreateZone(nil, zone)
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
		store.CreateZone(nil, zone)
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
	json.NewDecoder(resp.Body).Decode(&result)
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
	store.CreateZone(nil, zone)

	// Get current version
	retrieved, _ := store.GetZone(nil, "example.com.")
	originalVersion := retrieved.Version

	// Update the zone
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
	json.NewDecoder(resp.Body).Decode(&updated)
	assert.NotEqual(t, originalVersion, updated.Version)
	assert.Len(t, updated.Records, 2)
}

func TestUpdateZone_Conflict(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	// Create a zone
	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
	}
	store.CreateZone(nil, zone)

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
	store.CreateZone(nil, zone)

	// Delete the zone
	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/zones/example.com.", nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Verify it's deleted
	_, err = store.GetZone(nil, "example.com.")
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
	store.CreateZone(nil, zone)

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
	store.CreateZone(nil, zone)

	// Get zone to retrieve ETag
	retrieved, _ := store.GetZone(nil, "example.com.")
	etag := retrieved.Version

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
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Hash"))

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
	store.CreateZone(nil, zone)

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
