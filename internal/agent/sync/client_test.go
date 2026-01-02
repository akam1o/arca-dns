package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

	zones, err := client.ListZones()
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

	content, etag, notModified, err := client.FetchSignedZone("example.com.", "")
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

func TestFetchSignedZone_NotModified(t *testing.T) {
	requireTCPListener(t)
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "\"v01ARZ3NDEKTSV4RRFFQ69G5FAV\"" {
			t.Errorf("Expected If-None-Match header \"v01ARZ3NDEKTSV4RRFFQ69G5FAV\", got %s", r.Header.Get("If-None-Match"))
		}

		// Return 304 Not Modified
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash", "a3f5c2e9")
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

	content, etag, notModified, err := client.FetchSignedZone("example.com.", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err != nil {
		t.Fatalf("FetchSignedZone failed: %v", err)
	}

	if !notModified {
		t.Error("Expected notModified to be true")
	}

	if content != "" {
		t.Error("Expected empty content for 304 response")
	}

	if etag != "v01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("Expected ETag v01ARZ3NDEKTSV4RRFFQ69G5FAV, got %s", etag)
	}
}

func TestFetchSignedZone_ChecksumVerification(t *testing.T) {
	requireTCPListener(t)
	zoneContent := `example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024122801 3600 1800 604800 86400`

	// Create mock server with incorrect hash
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "v01ARZ3NDEKTSV4RRFFQ69G5FAV")
		w.Header().Set("X-Zone-Serial", "2024122801")
		w.Header().Set("X-Zone-Hash8", "badhash1") // Incorrect hash
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

	_, _, _, err = client.FetchSignedZone("example.com.", "")
	if err == nil {
		t.Fatal("Expected checksum verification to fail")
	}

	// Just check that it's a checksum verification error
	// The actual hash value depends on the content
	if err.Error()[:36] != "checksum verification failed: expect" {
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

	_, err = client.ListZones()
	if err != nil {
		t.Fatalf("ListZones failed after retries: %v", err)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}
