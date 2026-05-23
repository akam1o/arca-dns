package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupTestWithStore(t *testing.T, store backend.ZoneStore) (*Handler, *httptest.Server) {
	t.Helper()

	logger, err := zap.NewDevelopment()
	require.NoError(t, err)

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
	t.Cleanup(server.Close)

	return handler, server
}

func TestZoneVersions_NotSupportedBackend(t *testing.T) {
	store := backend.NewMemoryBackend()
	_, server := setupTestWithStore(t, store)

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
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp, err = http.Get(server.URL + "/api/v1/zones/example.com./versions")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
}

func TestZoneVersions_GitBackend(t *testing.T) {
	repoDir := t.TempDir()
	store, err := backend.NewGitBackend(repoDir, "main", "tester", "tester@example.com", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, server := setupTestWithStore(t, store)

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
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Update zone to create a second version.
	resp, err = http.Get(server.URL + "/api/v1/zones/example.com.")
	require.NoError(t, err)
	var current model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&current))
	etag := resp.Header.Get("ETag")
	require.NotEmpty(t, etag)
	require.NoError(t, resp.Body.Close())

	current.SOA.Refresh = 7200
	body = marshalUpdateZoneRequest(t, &current)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/zones/example.com.", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", etag)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Get(server.URL + "/api/v1/zones/example.com.")
	require.NoError(t, err)
	var afterUpdate model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&afterUpdate))
	currentVersion := afterUpdate.Version
	require.NotEmpty(t, currentVersion)
	require.NoError(t, resp.Body.Close())

	// List versions.
	resp, err = http.Get(server.URL + "/api/v1/zones/example.com./versions?limit=100&offset=0")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var listResp struct {
		Versions   []*model.ZoneVersion `json:"versions"`
		Pagination struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
			Count  int `json:"count"`
		} `json:"pagination"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResp))
	require.GreaterOrEqual(t, len(listResp.Versions), 2)
	assert.Equal(t, len(listResp.Versions), listResp.Pagination.Count)
	assert.Equal(t, currentVersion, listResp.Versions[0].Version)
	assert.NotEmpty(t, listResp.Versions[0].Hash)
	assert.NotEmpty(t, listResp.Versions[0].Hash8)

	// Fetch an older revision.
	oldest := listResp.Versions[len(listResp.Versions)-1].Version
	resp, err = http.Get(server.URL + "/api/v1/zones/example.com./versions/" + oldest)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var rev model.Zone
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rev))
	assert.Equal(t, oldest, rev.Version)
}

func TestGetZoneRevision_InvalidVersion(t *testing.T) {
	store := backend.NewMemoryBackend()
	_, server := setupTestWithStore(t, store)

	tests := []string{
		"not-a-valid-version",
		"v01ARZ3NDEKTSV4RRFFQ69G5FAV-extra",
		"v2024122801-zzzzzzzz",
		"v2024122801-123456789",
	}

	for _, version := range tests {
		t.Run(version, func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/zones/example.com./versions/" + url.PathEscape(version))
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestZoneVersions_InvalidPagination(t *testing.T) {
	repoDir := t.TempDir()
	store, err := backend.NewGitBackend(repoDir, "main", "tester", "tester@example.com", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	zone := &model.Zone{
		Name: "example.com.",
		SOA:  model.DefaultSOA("ns1.example.com.", "admin.example.com."),
		Records: []model.Record{
			apiTestApexNSRecord(),
		},
	}
	require.NoError(t, store.CreateZone(context.Background(), zone))

	_, server := setupTestWithStore(t, store)

	tests := []string{
		"offset=-1",
		"offset=abc",
		"limit=0",
		"limit=1001",
		"limit=abc",
	}

	for _, query := range tests {
		t.Run(query, func(t *testing.T) {
			resp, err := http.Get(server.URL + "/api/v1/zones/example.com./versions?" + query)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}
