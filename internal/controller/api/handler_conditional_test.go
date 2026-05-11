package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetZone_IfNoneMatch_NotModified(t *testing.T) {
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

	// First GET obtains the ETag/version.
	resp, err := http.Get(server.URL + "/api/v1/zones/example.com.")
	require.NoError(t, err)
	etag := resp.Header.Get("ETag")
	require.NotEmpty(t, etag)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	// Second GET with If-None-Match should return 304 with empty body.
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/zones/example.com.", nil)
	require.NoError(t, err)
	req.Header.Set("If-None-Match", etag)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotModified, resp.StatusCode)
	assert.Equal(t, etag, resp.Header.Get("ETag"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
}

func TestETagMatching_StrongAndWeakValidators(t *testing.T) {
	assert.True(t, etagMatches(`W/"v1"`, "v1"))
	assert.True(t, etagMatches(`"stale", W/"v1"`, "v1"))

	assert.True(t, strongETagMatches(`"v1"`, "v1"))
	assert.True(t, strongETagMatches(`"stale", "v1"`, "v1"))
	assert.True(t, strongETagMatches("v1", "v1"))
	assert.False(t, strongETagMatches(`W/"v1"`, "v1"))
	assert.False(t, strongETagMatches(`"stale", W/"v1"`, "v1"))
}

func TestGetSignedZoneMetadata_IfNoneMatch_NotModified(t *testing.T) {
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

	// First request returns 200 with ETag.
	resp, err := http.Get(server.URL + "/api/v1/zones/example.com./signed/metadata")
	require.NoError(t, err)
	etag := resp.Header.Get("ETag")
	require.NotEmpty(t, etag)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	// Second request returns 304 and empty body.
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/zones/example.com./signed/metadata", nil)
	require.NoError(t, err)
	req.Header.Set("If-None-Match", etag)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotModified, resp.StatusCode)
	assert.Equal(t, etag, resp.Header.Get("ETag"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
}

func TestGetSignedZoneMetadata_BodyAndHeaders(t *testing.T) {
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

	resp, err := http.Get(server.URL + "/api/v1/zones/example.com./signed/metadata")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Serial"))
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Hash"))
	assert.NotEmpty(t, resp.Header.Get("X-Zone-Hash8"))

	var payload struct {
		Zone          string `json:"zone"`
		Version       string `json:"version"`
		Serial        uint32 `json:"serial"`
		Hash          string `json:"hash"`
		Hash8         string `json:"hash8"`
		DNSSECEnabled bool   `json:"dnssec_enabled"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	assert.Equal(t, "example.com.", payload.Zone)
	assert.NotEmpty(t, payload.Version)
	assert.NotZero(t, payload.Serial)
	assert.NotEmpty(t, payload.Hash)
	assert.NotEmpty(t, payload.Hash8)
	assert.False(t, payload.DNSSECEnabled)
}
