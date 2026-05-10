package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
)

func requireTCPListener(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen not permitted in this environment: %v", err)
		return
	}
	_ = ln.Close()
}

func TestNewClient(t *testing.T) {
	cfg := config.ControllerClientConfig{
		URL:           "http://localhost:8080",
		Timeout:       30 * time.Second,
		RetryAttempts: 3,
		RetryDelay:    1 * time.Second,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	if client.baseURL != cfg.URL {
		t.Errorf("Expected baseURL %s, got %s", cfg.URL, client.baseURL)
	}
}

func TestNewClient_NormalizesTrailingSlash(t *testing.T) {
	cfg := config.ControllerClientConfig{
		URL:           "http://localhost:8080/",
		Timeout:       30 * time.Second,
		RetryAttempts: 3,
		RetryDelay:    1 * time.Second,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if client.baseURL != "http://localhost:8080" {
		t.Errorf("Expected normalized baseURL http://localhost:8080, got %s", client.baseURL)
	}
}

func TestNewClient_RejectsIncompleteClientAuthTLS(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.ControllerClientConfig
		want string
	}{
		{
			name: "client auth without tls",
			cfg: config.ControllerClientConfig{
				URL: "https://localhost:8080",
				TLS: config.TLSConfig{
					ClientAuth: true,
					CertFile:   "/tmp/client.crt",
					KeyFile:    "/tmp/client.key",
				},
			},
			want: "client_auth requires TLS",
		},
		{
			name: "ca file without tls",
			cfg: config.ControllerClientConfig{
				URL: "https://localhost:8080",
				TLS: config.TLSConfig{
					CAFile: "/tmp/controller-ca.crt",
				},
			},
			want: "TLS must be enabled",
		},
		{
			name: "client cert without client auth",
			cfg: config.ControllerClientConfig{
				URL: "https://localhost:8080",
				TLS: config.TLSConfig{
					Enabled:  true,
					CertFile: "/tmp/client.crt",
					KeyFile:  "/tmp/client.key",
				},
			},
			want: "client_auth is required",
		},
		{
			name: "tls enabled with http url",
			cfg: config.ControllerClientConfig{
				URL: "http://localhost:8080",
				TLS: config.TLSConfig{
					Enabled: true,
				},
			},
			want: "https controller URL",
		},
		{
			name: "client auth without cert",
			cfg: config.ControllerClientConfig{
				URL: "https://localhost:8080",
				TLS: config.TLSConfig{
					Enabled:    true,
					ClientAuth: true,
					KeyFile:    "/tmp/client.key",
				},
			},
			want: "cert_file",
		},
		{
			name: "client auth without key",
			cfg: config.ControllerClientConfig{
				URL: "https://localhost:8080",
				TLS: config.TLSConfig{
					Enabled:    true,
					ClientAuth: true,
					CertFile:   "/tmp/client.crt",
				},
			},
			want: "key_file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClient(tc.cfg)
			if err == nil {
				t.Fatal("Expected NewClient to fail")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Expected error to contain %q, got %v", tc.want, err)
			}
		})
	}
}

func TestListZones(t *testing.T) {
	requireTCPListener(t)
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/zones" {
			t.Errorf("Expected path /api/v1/zones, got %s", r.URL.Path)
		}

		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}

		if fields := r.URL.Query().Get("fields"); fields != "summary" {
			t.Errorf("Expected fields summary, got %s", fields)
		}

		// Return mock zone list
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"zones": [
				{
					"name": "example.com.",
					"version": "v01ARZ3NDEKTSV4RRFFQ69G5FAV",
					"soa": {
						"mname": "ns1.example.com.",
						"rname": "admin.example.com.",
						"serial": 2024122801,
						"refresh": 3600,
						"retry": 1800,
						"expire": 604800,
						"minimum": 86400
					},
					"records": [],
					"created_at": "2024-12-28T00:00:00Z",
					"updated_at": "2024-12-28T00:00:00Z"
				}
			]
		}`)
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	zones, err := client.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	if len(zones) != 1 {
		t.Fatalf("Expected 1 zone, got %d", len(zones))
	}

	if zones[0].Name != "example.com." {
		t.Errorf("Expected zone name example.com., got %s", zones[0].Name)
	}

	if zones[0].Version != "v01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("Expected version v01ARZ3NDEKTSV4RRFFQ69G5FAV, got %s", zones[0].Version)
	}
}

func TestListZones_Paginates(t *testing.T) {
	requireTCPListener(t)

	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/zones" {
			t.Errorf("Expected path /api/v1/zones, got %s", r.URL.Path)
		}

		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}

		if fields := r.URL.Query().Get("fields"); fields != "summary" {
			t.Errorf("Expected fields summary, got %s", fields)
		}

		limit := r.URL.Query().Get("limit")
		if limit != "1000" {
			t.Errorf("Expected limit 1000, got %s", limit)
		}

		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)

		switch offset {
		case "0":
			writeListZonesPage(w, 0, 1000)
		case "1000":
			writeListZonesPage(w, 1000, 1)
		default:
			t.Errorf("Unexpected offset %s", offset)
			writeListZonesPage(w, 0, 0)
		}
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	zones, err := client.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	if len(zones) != 1001 {
		t.Fatalf("Expected 1001 zones, got %d", len(zones))
	}

	expectedOffsets := []string{"0", "1000"}
	if len(offsets) != len(expectedOffsets) {
		t.Fatalf("Expected offsets %v, got %v", expectedOffsets, offsets)
	}
	for i := range expectedOffsets {
		if offsets[i] != expectedOffsets[i] {
			t.Fatalf("Expected offsets %v, got %v", expectedOffsets, offsets)
		}
	}

	if zones[1000].Name != "zone-1000.example.com." {
		t.Errorf("Expected final zone name zone-1000.example.com., got %s", zones[1000].Name)
	}
}

func TestListZones_NormalizesTrailingSlash(t *testing.T) {
	requireTCPListener(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/zones" {
			t.Errorf("Expected path /api/v1/zones, got %s", r.URL.Path)
		}

		writeListZonesPage(w, 0, 0)
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL + "/",
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	if _, err := client.ListZones(context.Background()); err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}
}

func writeListZonesPage(w http.ResponseWriter, offset, count int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"zones":[`)
	for i := 0; i < count; i++ {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		zoneID := offset + i
		fmt.Fprintf(w, `{"name":"zone-%d.example.com.","version":"v%04d","records":[]}`, zoneID, zoneID)
	}
	fmt.Fprintf(w, `],"pagination":{"offset":%d,"limit":1000,"count":%d}}`, offset, count)
}

func TestFetchSignedZone_Success(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400
example.com. 3600 IN NS ns1.example.com.
www.example.com. 300 IN A 192.0.2.1
`

	// Compute hash
	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])[:8]

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/zones/example.com./signed" {
			t.Errorf("Expected path /api/v1/zones/example.com./signed, got %s", r.URL.Path)
		}

		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}

		// Return zone file with headers
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", hex.EncodeToString(hash[:]))
		w.Header().Set("X-Zone-Hash8", hashHex)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	content, etag, notModified, err := client.FetchSignedZone(context.Background(), "example.com.", "")
	if err != nil {
		t.Fatalf("FetchSignedZone failed: %v", err)
	}

	if notModified {
		t.Error("Expected notModified to be false")
	}

	if etag != "v01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("Expected ETag v01ARZ3NDEKTSV4RRFFQ69G5FAV, got %s", etag)
	}

	if content != zoneContent {
		t.Errorf("Zone content mismatch")
	}
}

func TestFetchSignedZoneArtifact_RejectsSerialHeaderMismatch(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400
example.com. 3600 IN NS ns1.example.com.
`
	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+hashHex+`"`)
		w.Header().Set("X-Zone-Serial", "2024122701")
		w.Header().Set("X-Zone-Hash", hashHex)
		w.Header().Set("X-Zone-Hash8", hashHex[:8])
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, err = client.FetchSignedZoneArtifact(context.Background(), "example.com.", "")
	if err == nil {
		t.Fatal("Expected mismatched X-Zone-Serial to fail")
	}
	if !strings.Contains(err.Error(), "zone serial header mismatch") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFetchSignedZone_NotModified(t *testing.T) {
	requireTCPListener(t)
	currentETag := strings.Repeat("a", sha256.Size*2)
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedIfNoneMatch := `"` + currentETag + `"`
		if r.Header.Get("If-None-Match") != expectedIfNoneMatch {
			t.Errorf("Expected If-None-Match header %s, got %s", expectedIfNoneMatch, r.Header.Get("If-None-Match"))
		}

		// Return 304 Not Modified
		w.Header().Set("ETag", currentETag)
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", currentETag)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	content, etag, notModified, err := client.FetchSignedZone(context.Background(), "example.com.", currentETag)
	if err != nil {
		t.Fatalf("FetchSignedZone failed: %v", err)
	}

	if !notModified {
		t.Error("Expected notModified to be true")
	}

	if content != "" {
		t.Error("Expected empty content for 304 response")
	}

	if etag != currentETag {
		t.Errorf("Expected ETag %s, got %s", currentETag, etag)
	}
}

func TestFetchSignedZone_NotModifiedRejectsShortChecksum(t *testing.T) {
	requireTCPListener(t)
	currentETag := strings.Repeat("a", sha256.Size*2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", currentETag)
		w.Header().Set("X-Zone-Hash", "a3f5c2e9")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", currentETag)
	if err == nil {
		t.Fatal("Expected short checksum header in 304 response to fail")
	}
	if !strings.Contains(err.Error(), "invalid checksum header length") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFetchSignedZone_NotModifiedRejectsChecksumETagMismatch(t *testing.T) {
	requireTCPListener(t)
	currentETag := strings.Repeat("a", sha256.Size*2)
	otherHash := strings.Repeat("b", sha256.Size*2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", currentETag)
		w.Header().Set("X-Zone-Hash", otherHash)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", currentETag)
	if err == nil {
		t.Fatal("Expected mismatched checksum header in 304 response to fail")
	}
	if !strings.Contains(err.Error(), "checksum header mismatch") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFetchSignedZone_NotModifiedRejectsMissingETag(t *testing.T) {
	requireTCPListener(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "\"v01ARZ3NDEKTSV4RRFFQ69G5FAV\"" {
			t.Errorf("Expected If-None-Match header \"v01ARZ3NDEKTSV4RRFFQ69G5FAV\", got %s", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err == nil {
		t.Fatal("Expected missing ETag in 304 response to fail")
	}
	if !strings.Contains(err.Error(), "missing ETag") {
		t.Errorf("Expected missing ETag error, got %v", err)
	}
}

func TestFetchSignedZone_NotModifiedRejectsMismatchedETag(t *testing.T) {
	requireTCPListener(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "\"v01ARZ3NDEKTSV4RRFFQ69G5FAV\"" {
			t.Errorf("Expected If-None-Match header \"v01ARZ3NDEKTSV4RRFFQ69G5FAV\", got %s", r.Header.Get("If-None-Match"))
		}
		w.Header().Set("ETag", "v01DIFFERENT")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err == nil {
		t.Fatal("Expected mismatched ETag in 304 response to fail")
	}
	if !strings.Contains(err.Error(), "ETag mismatch") {
		t.Errorf("Expected ETag mismatch error, got %v", err)
	}
}

func TestFetchSignedZone_ChecksumVerification(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	badHash := strings.Repeat("0", sha256.Size*2)

	// Create mock server with incorrect hash
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", badHash)
		w.Header().Set("X-Zone-Hash8", badHash[:8])
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", "")
	if err == nil {
		t.Fatal("Expected checksum verification to fail")
	}

	// Just check that it's a checksum verification error
	// The actual hash value depends on the content
	if !strings.HasPrefix(err.Error(), "checksum verification failed: expected ") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFetchSignedZone_ShortChecksumRejected(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", "a3f5c2e9")
		w.Header().Set("X-Zone-Hash8", "a3f5c2e9")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", "")
	if err == nil {
		t.Fatal("Expected short checksum header to fail")
	}
	if !strings.Contains(err.Error(), "invalid checksum header length") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFetchSignedZone_MissingChecksumRejected(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", "")
	if err == nil {
		t.Fatal("Expected missing checksum header to fail")
	}
	if err.Error() != "missing full checksum header in response" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFetchSignedZone_ChecksumVerificationDisabled(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()
	client.SetVerifyChecksums(false)

	content, _, _, err := client.FetchSignedZone(context.Background(), "example.com.", "")
	if err != nil {
		t.Fatalf("FetchSignedZone failed with checksum verification disabled: %v", err)
	}
	if content != zoneContent {
		t.Errorf("Zone content mismatch")
	}
}

func TestFetchSignedZone_SignatureVerification(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	signatureKey := "test-signature-key"

	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", hashHex)
		w.Header().Set("X-Zone-Hash8", hashHex[:8])
		w.Header().Set("X-Zone-Signature", artifactSignature([]byte(zoneContent), signatureKey))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()
	client.SetSignatureVerification(true, signatureKey)

	content, _, _, err := client.FetchSignedZone(context.Background(), "example.com.", "")
	if err != nil {
		t.Fatalf("FetchSignedZone failed with valid signature: %v", err)
	}
	if content != zoneContent {
		t.Errorf("Zone content mismatch")
	}
}

func TestFetchSignedZone_SignatureVerificationForcesFullFetch(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	signatureKey := "test-signature-key"

	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			t.Errorf("Expected signature verification to force a full fetch, got If-None-Match %s", r.Header.Get("If-None-Match"))
		}

		w.Header().Set("ETag", `"`+hashHex+`"`)
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", hashHex)
		w.Header().Set("X-Zone-Hash8", hashHex[:8])
		w.Header().Set("X-Zone-Signature", artifactSignature([]byte(zoneContent), signatureKey))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()
	client.SetSignatureVerification(true, signatureKey)

	content, etag, notModified, err := client.FetchSignedZone(context.Background(), "example.com.", hashHex)
	if err != nil {
		t.Fatalf("FetchSignedZone failed with valid signature: %v", err)
	}
	if notModified {
		t.Fatal("Expected signed fetch to return a full artifact")
	}
	if etag != `"`+hashHex+`"` {
		t.Errorf("Expected ETag %q, got %q", `"`+hashHex+`"`, etag)
	}
	if content != zoneContent {
		t.Errorf("Zone content mismatch")
	}
}

func TestFetchSignedZone_SignatureVerificationUsesConditionalFetchWithCurrentBody(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	signatureKey := "test-signature-key"

	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])
	expectedIfNoneMatch := `"` + hashHex + `"`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got != expectedIfNoneMatch {
			t.Errorf("If-None-Match = %q, want %q", got, expectedIfNoneMatch)
		}

		w.Header().Set("ETag", expectedIfNoneMatch)
		w.Header().Set("X-Zone-Hash", hashHex)
		w.Header().Set("X-Zone-Signature", artifactSignature([]byte(zoneContent), signatureKey))
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()
	client.SetSignatureVerification(true, signatureKey)

	content, etag, notModified, err := client.FetchSignedZoneWithCurrent(context.Background(), "example.com.", hashHex, zoneContent)
	if err != nil {
		t.Fatalf("FetchSignedZoneWithCurrent failed: %v", err)
	}
	if !notModified {
		t.Fatal("Expected signed conditional fetch to return not modified")
	}
	if content != "" {
		t.Errorf("Expected empty content for 304, got %q", content)
	}
	if etag != hashHex {
		t.Errorf("Expected ETag %q, got %q", hashHex, etag)
	}
}

func TestFetchSignedZone_SignatureVerificationRejectsUnsignedNotModified(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`
	signatureKey := "test-signature-key"

	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+hashHex+`"`)
		w.Header().Set("X-Zone-Hash", hashHex)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()
	client.SetSignatureVerification(true, signatureKey)

	_, _, _, err = client.FetchSignedZoneWithCurrent(context.Background(), "example.com.", hashHex, zoneContent)
	if err == nil {
		t.Fatal("Expected unsigned 304 response to fail")
	}
	if !strings.Contains(err.Error(), "signature header") {
		t.Errorf("Expected signature header error, got %v", err)
	}
}

func TestFetchSignedZone_MissingSignatureRejected(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`

	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", hashHex)
		w.Header().Set("X-Zone-Hash8", hashHex[:8])
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()
	client.SetSignatureVerification(true, "test-signature-key")

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", "")
	if err == nil {
		t.Fatal("Expected missing signature header to fail")
	}
	if err.Error() != "missing signature header in response" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFetchSignedZone_InvalidSignatureRejected(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`

	hash := sha256.Sum256([]byte(zoneContent))
	hashHex := hex.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", hashHex)
		w.Header().Set("X-Zone-Hash8", hashHex[:8])
		w.Header().Set("X-Zone-Signature", artifactSignature([]byte(zoneContent), "wrong-signature-key"))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, zoneContent)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()
	client.SetSignatureVerification(true, "test-signature-key")

	_, _, _, err = client.FetchSignedZone(context.Background(), "example.com.", "")
	if err == nil {
		t.Fatal("Expected invalid signature to fail")
	}
	if err.Error() != "signature verification failed" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRetryLogic(t *testing.T) {
	requireTCPListener(t)
	attempts := 0

	// Create mock server that fails twice then succeeds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"zones": []}`)
	}))
	defer server.Close()

	cfg := config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 3,
		RetryDelay:    10 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	_, err = client.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones failed after retries: %v", err)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestRetryDelayHonorsContextCancellation(t *testing.T) {
	requireTCPListener(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(config.ControllerClientConfig{
		URL:           server.URL,
		Timeout:       5 * time.Second,
		RetryAttempts: 3,
		RetryDelay:    time.Hour,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = client.ListZones(ctx)
	if err == nil {
		t.Fatal("expected ListZones to fail after context cancellation")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("ListZones ignored context during retry delay; elapsed=%s", elapsed)
	}
}
