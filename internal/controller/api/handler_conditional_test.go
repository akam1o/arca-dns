package api

import (
	"context"
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
