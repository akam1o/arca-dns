package api

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateZoneRaw_TextPlain(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zoneFile := `$TTL 3600
example.com. IN SOA ns1.example.com. admin.example.com. (
    2024010101 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    86400      ; minimum
)
example.com. IN NS ns1.example.com.
example.com. IN A 192.0.2.1
www.example.com. IN A 192.0.2.2
`

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=example.com.",
		strings.NewReader(zoneFile))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))
	assert.Equal(t, "/api/v1/zones/example.com.", resp.Header.Get("Location"))
}

func TestCreateZoneRaw_MultipartForm(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zoneFile := `$TTL 3600
test.com. IN SOA ns1.test.com. admin.test.com. (
    2024010101 3600 1800 604800 86400
)
test.com. IN NS ns1.test.com.
test.com. IN A 192.0.2.1
`

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("zonefile", "test.com.zone")
	require.NoError(t, err)
	_, err = part.Write([]byte(zoneFile))
	require.NoError(t, err)

	require.NoError(t, writer.Close())

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("ETag"))
}

func TestCreateZoneRaw_WithOriginDirective(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zoneFile := `$ORIGIN origin-test.com.
$TTL 3600
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
@ IN NS ns1
@ IN A 192.0.2.1
www IN A 192.0.2.2
`

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw",
		strings.NewReader(zoneFile))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

func TestCreateZoneRaw_Duplicate(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zoneFile := `$TTL 3600
dup.com. IN SOA ns1.dup.com. admin.dup.com. (
    2024010101 3600 1800 604800 86400
)
	dup.com. IN NS ns1.dup.com.
`

	// First request
	req1, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=dup.com.", strings.NewReader(zoneFile))
	require.NoError(t, err)
	req1.Header.Set("Content-Type", "text/plain")
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusCreated, resp1.StatusCode)

	// Second request (duplicate)
	req2, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=dup.com.", strings.NewReader(zoneFile))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "text/plain")
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

func TestCreateZoneRaw_InvalidZone_NoSOA(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zoneFile := `$TTL 3600
invalid.com. IN NS ns1.invalid.com.
invalid.com. IN A 192.0.2.1
`

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=invalid.com.",
		strings.NewReader(zoneFile))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateZoneRaw_EmptyContent(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=empty.com.",
		strings.NewReader(""))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateZoneRaw_UnsupportedContentType(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw",
		strings.NewReader("some content"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
}

func TestCreateZoneRaw_NoOrigin(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zoneFile := `$TTL 3600
@ IN SOA ns1 admin (2024010101 3600 1800 604800 86400)
@ IN NS ns1
`

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw",
		strings.NewReader(zoneFile))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail because @ symbol requires $ORIGIN
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateZoneRaw_AllRecordTypes(t *testing.T) {
	_, _, server := setupTest(t)
	defer server.Close()

	zoneFile := `$TTL 3600
all-types.com. IN SOA ns1.all-types.com. admin.all-types.com. (
    2024010101 3600 1800 604800 86400
)
all-types.com. IN NS ns1.all-types.com.
all-types.com. IN A 192.0.2.1
all-types.com. IN AAAA 2001:db8::1
www.all-types.com. IN CNAME all-types.com.
all-types.com. IN MX 10 mail.all-types.com.
all-types.com. IN TXT "v=spf1 -all"
1.2.0.192.in-addr.arpa. IN PTR all-types.com.
_http._tcp.all-types.com. IN SRV 0 5 80 www.all-types.com.
all-types.com. IN CAA 0 issue "ca.example.com"
`

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=all-types.com.",
		strings.NewReader(zoneFile))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Verify created zone can be retrieved
	getResp, err := http.Get(server.URL + "/api/v1/zones/all-types.com.")
	require.NoError(t, err)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)
}
