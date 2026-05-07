package api

import (
	"bytes"
	"context"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akam1o/arca-dns/internal/controller/service"
	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/dnssec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupRawTestWithSigning(t *testing.T) (*backend.MemoryBackend, *httptest.Server) {
	t.Helper()

	logger := zap.NewNop()
	store := backend.NewMemoryBackend()
	tmpDir := t.TempDir()

	masterKey, err := dnssec.GenerateMasterKey()
	require.NoError(t, err)

	keyManager, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: filepath.Join(tmpDir, "keys"),
		MasterKey:    masterKey,
		Algorithm:    13,
	})
	require.NoError(t, err)

	signingService := service.NewSigningService(store, keyManager, filepath.Join(tmpDir, "artifacts"), nil, logger)
	handler := NewHandler(store, signingService, nil, BuildInfo{Version: "test", Commit: "test", Date: "test"}, logger)

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

	return store, server
}

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

func TestCreateZoneRaw_EmptyTXTRecord(t *testing.T) {
	_, store, server := setupTest(t)
	defer server.Close()

	zoneFile := `$TTL 3600
empty-txt.com. IN SOA ns1.empty-txt.com. admin.empty-txt.com. (
    2024010101 3600 1800 604800 86400
)
empty-txt.com. IN NS ns1.empty-txt.com.
empty-txt.com. IN TXT ""
`

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=empty-txt.com.",
		strings.NewReader(zoneFile))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	zone, err := store.GetZone(context.Background(), "empty-txt.com.")
	require.NoError(t, err)
	require.Len(t, zone.Records, 2)
	assert.Equal(t, "TXT", zone.Records[1].Type)
	assert.Empty(t, zone.Records[1].Value)
}

func TestCreateZoneRaw_AutoSignsWhenSigningServiceEnabled(t *testing.T) {
	store, server := setupRawTestWithSigning(t)
	defer server.Close()

	zoneFile := `$TTL 3600
signed-raw.com. IN SOA ns1.signed-raw.com. admin.signed-raw.com. (
    2024010101 3600 1800 604800 86400
)
signed-raw.com. IN NS ns1.signed-raw.com.
signed-raw.com. IN A 192.0.2.1
`

	req, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=signed-raw.com.",
		strings.NewReader(zoneFile))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	created, err := store.GetZone(context.Background(), "signed-raw.com.")
	require.NoError(t, err)
	require.NotNil(t, created.DNSSEC)
	assert.True(t, created.DNSSEC.Enabled)
	assert.NotZero(t, created.DNSSEC.KSKKeyTag)
	assert.NotZero(t, created.DNSSEC.ZSKKeyTag)
	assert.NotNil(t, created.DNSSEC.SignatureExpiration)
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

	zoneFile := strings.Join([]string{
		"$TTL 3600",
		"dup.com. IN SOA ns1.dup.com. admin.dup.com. (",
		"    2024010101 3600 1800 604800 86400",
		")",
		"dup.com. IN NS ns1.dup.com.",
		"",
	}, "\n")

	// First request
	req1, err := http.NewRequest("POST", server.URL+"/api/v1/zones/raw?origin=dup.com.", strings.NewReader(zoneFile))
	require.NoError(t, err)
	req1.Header.Set("Content-Type", "text/plain")
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp1.StatusCode)
	require.NoError(t, resp1.Body.Close())

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
ptr.all-types.com. IN PTR all-types.com.
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
