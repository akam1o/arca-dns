package sync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
)

const listZonesPageLimit = 1000

// Client is an HTTP client for communicating with the arca-dns controller.
type Client struct {
	httpClient       *http.Client
	baseURL          string
	apiKey           string
	config           config.ControllerClientConfig
	verifyChecksums  bool
	verifySignatures bool
	signatureKey     string
}

// ZoneInfo contains information about a zone from the controller.
type ZoneInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	ETag    string `json:"etag"`
}

// SignedZoneResponse contains a signed zone file and metadata.
type SignedZoneResponse struct {
	ZoneFile string `json:"zone_file"`
	Metadata struct {
		Version string `json:"version"`
		Serial  uint32 `json:"serial"`
		Hash    string `json:"hash"`
	} `json:"metadata"`
}

type listZonesResponse struct {
	Zones      []ZoneInfo `json:"zones"`
	Pagination struct {
		Offset int `json:"offset"`
		Limit  int `json:"limit"`
		Count  int `json:"count"`
	} `json:"pagination"`
}

func (r listZonesResponse) hasPagination() bool {
	return r.Pagination.Offset != 0 || r.Pagination.Limit != 0 || r.Pagination.Count != 0
}

func normalizeIfNoneMatch(etag string) string {
	etag = strings.TrimSpace(etag)
	if etag == "" {
		return ""
	}
	if etag == "*" {
		return "*"
	}
	etag = strings.TrimPrefix(etag, "W/")
	etag = strings.TrimSpace(etag)
	etag = strings.Trim(etag, "\"")
	if etag == "" {
		return ""
	}
	// Use a quoted strong ETag to match typical HTTP semantics and controller responses.
	return `"` + etag + `"`
}

// NewClient creates a new controller client with retry logic and connection pooling.
func NewClient(cfg config.ControllerClientConfig) (*Client, error) {
	// Create TLS configuration if enabled
	var tlsConfig *tls.Config
	if cfg.TLS.Enabled {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Load CA certificate if provided
		if cfg.TLS.CAFile != "" {
			caCert, err := os.ReadFile(cfg.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		// Load client certificate if mutual TLS is enabled
		if cfg.TLS.ClientAuth && cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	// Create HTTP client with connection pooling and timeout
	httpClient := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	return &Client{
		httpClient:      httpClient,
		baseURL:         cfg.URL,
		apiKey:          cfg.APIKey,
		config:          cfg,
		verifyChecksums: true,
	}, nil
}

// SetVerifyChecksums controls whether signed zone downloads must include and
// match controller checksum headers.
func (c *Client) SetVerifyChecksums(enabled bool) {
	c.verifyChecksums = enabled
}

// SetSignatureVerification controls whether signed zone downloads must include
// a valid X-Zone-Signature header. The signature is base64(HMAC-SHA256(body, key)).
func (c *Client) SetSignatureVerification(enabled bool, key string) {
	c.verifySignatures = enabled
	c.signatureKey = key
}

// ListZones retrieves the list of zones from the controller.
func (c *Client) ListZones(ctx context.Context) ([]ZoneInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var zones []ZoneInfo

	for offset := 0; ; {
		result, err := c.listZonesPage(ctx, offset, listZonesPageLimit)
		if err != nil {
			return nil, err
		}

		for _, z := range result.Zones {
			zones = append(zones, ZoneInfo{
				Name:    z.Name,
				Version: z.Version,
				ETag:    z.Version, // ETag is the same as version
			})
		}

		if !result.hasPagination() {
			return zones, nil
		}

		count := result.Pagination.Count
		if count == 0 {
			count = len(result.Zones)
		}

		limit := result.Pagination.Limit
		if limit <= 0 {
			limit = listZonesPageLimit
		}

		if count == 0 || count < limit {
			break
		}

		offset += count
	}

	return zones, nil
}

func (c *Client) listZonesPage(ctx context.Context, offset, limit int) (*listZonesResponse, error) {
	endpoint, err := url.Parse(fmt.Sprintf("%s/api/v1/zones", c.baseURL))
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("fields", "summary")
	query.Set("offset", fmt.Sprintf("%d", offset))
	query.Set("limit", fmt.Sprintf("%d", limit))
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var result listZonesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// FetchSignedZone fetches a signed zone file from the controller.
// If currentETag is provided, it performs a conditional fetch using If-None-Match.
// Returns (zoneContent, newETag, isNotModified, error).
func (c *Client) FetchSignedZone(ctx context.Context, zoneName string, currentETag string) (string, string, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	url := fmt.Sprintf("%s/api/v1/zones/%s/signed", c.baseURL, zoneName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", false, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	// Add If-None-Match header for conditional fetch (ETag-based)
	requestETag := normalizeIfNoneMatch(currentETag)
	if requestETag != "" {
		req.Header.Set("If-None-Match", requestETag)
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return "", "", false, err
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified (zone hasn't changed)
	if resp.StatusCode == http.StatusNotModified {
		if requestETag == "" {
			return "", "", false, fmt.Errorf("received 304 Not Modified without a conditional ETag")
		}

		responseETag := normalizeIfNoneMatch(resp.Header.Get("ETag"))
		if responseETag == "" {
			return "", "", false, fmt.Errorf("missing ETag header in 304 response")
		}
		if responseETag != requestETag {
			return "", "", false, fmt.Errorf("ETag mismatch in 304 response: requested %s, got %s", requestETag, responseETag)
		}

		return "", currentETag, true, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", false, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Read zone file content
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", false, fmt.Errorf("failed to read response body: %w", err)
	}

	// Extract ETag from response headers
	newETag := resp.Header.Get("ETag")
	if newETag == "" {
		return "", "", false, fmt.Errorf("missing ETag header in response")
	}

	// Extract integrity metadata from headers
	zoneSerial := resp.Header.Get("X-Zone-Serial")
	zoneHash := resp.Header.Get("X-Zone-Hash")
	zoneHash8 := resp.Header.Get("X-Zone-Hash8")
	zoneSignature := resp.Header.Get("X-Zone-Signature")

	// Verify SHA256 checksum when enabled. Missing checksum headers are an error
	// because the agent otherwise cannot detect truncated or altered artifacts.
	if c.verifyChecksums {
		if zoneHash == "" && zoneHash8 == "" {
			return "", "", false, fmt.Errorf("missing checksum header in response")
		}

		computedHash := sha256.Sum256(body)
		computedHashHex := hex.EncodeToString(computedHash[:])
		computedHash8 := computedHashHex
		if len(computedHash8) > 8 {
			computedHash8 = computedHash8[:8]
		}

		// Backward/forward compatible verification:
		// - If X-Zone-Hash is 64 hex chars: treat as full SHA256.
		// - If X-Zone-Hash is 8 chars: treat as hash8.
		// - If X-Zone-Hash8 is present: treat as hash8.
		if zoneHash != "" {
			switch len(zoneHash) {
			case 64:
				if computedHashHex != zoneHash {
					return "", "", false, fmt.Errorf("checksum verification failed: expected %s, got %s", zoneHash, computedHashHex)
				}
			case 8:
				if computedHash8 != zoneHash {
					return "", "", false, fmt.Errorf("checksum verification failed: expected %s, got %s", zoneHash, computedHash8)
				}
			default:
				// Unknown length; best-effort: compare prefix.
				if !strings.HasPrefix(computedHashHex, zoneHash) {
					return "", "", false, fmt.Errorf("checksum verification failed: expected prefix %s, got %s", zoneHash, computedHashHex)
				}
			}
		}

		if zoneHash8 != "" && computedHash8 != zoneHash8 {
			return "", "", false, fmt.Errorf("checksum verification failed: expected %s, got %s", zoneHash8, computedHash8)
		}
	}

	if c.verifySignatures {
		if err := verifyArtifactSignature(body, zoneSignature, c.signatureKey); err != nil {
			return "", "", false, err
		}
	}

	// Log integrity metadata for debugging
	_ = zoneSerial // Available for logging if needed

	return string(body), newETag, false, nil
}

func artifactSignature(body []byte, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func verifyArtifactSignature(body []byte, signatureHeader string, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("signature verification enabled but controller public key is empty")
	}

	signatureHeader = strings.TrimSpace(signatureHeader)
	if signatureHeader == "" {
		return fmt.Errorf("missing signature header in response")
	}

	signatureHeader = strings.TrimPrefix(signatureHeader, "sha256=")
	signatureHeader = strings.TrimPrefix(signatureHeader, "hmac-sha256=")

	actual, err := base64.StdEncoding.DecodeString(signatureHeader)
	if err != nil {
		return fmt.Errorf("invalid signature header: %w", err)
	}

	expected := hmac.New(sha256.New, []byte(key))
	_, _ = expected.Write(body)
	if !hmac.Equal(actual, expected.Sum(nil)) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// doWithRetry executes an HTTP request with retry logic.
func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(c.config.RetryDelay)
			select {
			case <-timer.C:
			case <-req.Context().Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return nil, req.Context().Err()
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d failed: %w", attempt+1, err)
			continue
		}

		// Success or non-retriable error (4xx, 5xx)
		if resp.StatusCode < 500 || resp.StatusCode == http.StatusNotModified {
			return resp, nil
		}

		// 5xx errors are retriable
		resp.Body.Close()
		lastErr = fmt.Errorf("attempt %d returned status %d", attempt+1, resp.StatusCode)
	}

	return nil, fmt.Errorf("all retry attempts exhausted: %w", lastErr)
}

// Close closes the HTTP client's idle connections.
func (c *Client) Close() {
	c.httpClient.CloseIdleConnections()
}
