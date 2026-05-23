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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
)

const (
	listZonesPageLimit       = 1000
	maxErrorResponseBodySize = 4 * 1024
)

// Client is an HTTP client for communicating with the arca-dns controller.
type Client struct {
	httpClient       *http.Client
	baseURL          string
	apiKey           string
	config           config.ControllerClientConfig
	maxResponseBytes int64
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

// SignedZoneArtifact is a fetched signed zone file and its verified metadata.
type SignedZoneArtifact struct {
	Content     string
	ETag        string
	Serial      uint32
	Hash        string
	NotModified bool
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
	etag = strings.TrimPrefix(etag, "W/")
	etag = strings.TrimSpace(etag)
	etag = strings.Trim(etag, "\"")
	if etag == "" || etag == "*" || strings.ContainsAny(etag, `",\`) || strings.ContainsFunc(etag, isInvalidETagChar) {
		return ""
	}
	// Use a quoted strong ETag to match typical HTTP semantics and controller responses.
	return `"` + etag + `"`
}

func isInvalidETagChar(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// NewClient creates a new controller client with retry logic and connection pooling.
func NewClient(cfg config.ControllerClientConfig) (*Client, error) {
	if err := validateTLSConfig(cfg); err != nil {
		return nil, err
	}

	// Create TLS configuration if enabled
	var tlsConfig *tls.Config
	if cfg.TLS.Enabled {
		caFile := strings.TrimSpace(cfg.TLS.CAFile)
		certFile := strings.TrimSpace(cfg.TLS.CertFile)
		keyFile := strings.TrimSpace(cfg.TLS.KeyFile)

		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Load CA certificate if provided
		if caFile != "" {
			caCert, err := readRegularTLSFile(caFile, "CA certificate file")
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
		if cfg.TLS.ClientAuth {
			cert, err := loadRegularClientCertificate(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	// Create HTTP client with connection pooling and timeout
	httpClient := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 || sameOrigin(req.URL, via[0].URL) {
				return nil
			}
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	maxResponseBytes := cfg.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = config.DefaultControllerClientMaxResponseBytes
	}

	return &Client{
		httpClient:       httpClient,
		baseURL:          strings.TrimRight(cfg.URL, "/"),
		apiKey:           cfg.APIKey,
		config:           cfg,
		maxResponseBytes: maxResponseBytes,
		verifyChecksums:  true,
	}, nil
}

func loadRegularClientCertificate(certFile string, keyFile string) (tls.Certificate, error) {
	certPEMBlock, err := readRegularTLSFile(certFile, "client certificate file")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read client certificate file: %w", err)
	}
	keyPEMBlock, err := readRegularTLSPrivateKeyFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read client key file: %w", err)
	}

	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}

func readRegularTLSFile(path string, label string) ([]byte, error) {
	return readRegularTLSFileValidated(path, label, nil)
}

func readRegularTLSPrivateKeyFile(path string) ([]byte, error) {
	return readRegularTLSFileValidated(path, "client key file", func(info os.FileInfo) error {
		if info.Mode().Perm()&0o007 != 0 {
			return fmt.Errorf("client key file permissions must not allow other access: %s (mode %04o)", path, info.Mode().Perm())
		}
		return nil
	})
}

func readRegularTLSFileValidated(path string, label string, validate func(os.FileInfo) error) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symlink: %s", label, path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file: %s", label, path)
	}
	if validate != nil {
		if err := validate(info); err != nil {
			return nil, err
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("%s changed while opening: %s", label, path)
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file: %s", label, path)
	}
	if validate != nil {
		if err := validate(openedInfo); err != nil {
			return nil, err
		}
	}

	return io.ReadAll(file)
}

func sameOrigin(a *url.URL, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func validateTLSConfig(cfg config.ControllerClientConfig) error {
	if err := validateAPIKeyTransport(cfg); err != nil {
		return err
	}

	caFile := strings.TrimSpace(cfg.TLS.CAFile)
	certFile := strings.TrimSpace(cfg.TLS.CertFile)
	keyFile := strings.TrimSpace(cfg.TLS.KeyFile)

	if cfg.TLS.ClientAuth {
		if !cfg.TLS.Enabled {
			return fmt.Errorf("invalid TLS configuration: client_auth requires TLS to be enabled")
		}
		if certFile == "" {
			return fmt.Errorf("invalid TLS configuration: cert_file is required when client_auth is enabled")
		}
		if keyFile == "" {
			return fmt.Errorf("invalid TLS configuration: key_file is required when client_auth is enabled")
		}
	}
	if (caFile != "" || certFile != "" || keyFile != "") && !cfg.TLS.Enabled {
		return fmt.Errorf("invalid TLS configuration: TLS must be enabled when ca_file, cert_file, or key_file is set")
	}
	if certFile == "" && keyFile != "" {
		return fmt.Errorf("invalid TLS configuration: cert_file is required when key_file is set")
	}
	if certFile != "" && keyFile == "" {
		return fmt.Errorf("invalid TLS configuration: key_file is required when cert_file is set")
	}
	if (certFile != "" || keyFile != "") && !cfg.TLS.ClientAuth {
		return fmt.Errorf("invalid TLS configuration: client_auth is required when cert_file or key_file is set")
	}
	if cfg.TLS.Enabled {
		parsed, err := url.Parse(cfg.URL)
		if err != nil {
			return fmt.Errorf("invalid TLS configuration: invalid controller URL: %w", err)
		}
		if strings.ToLower(parsed.Scheme) != "https" {
			return fmt.Errorf("invalid TLS configuration: TLS requires an https controller URL")
		}
	}
	if caFile != "" {
		if err := validateTLSFilePath("ca_file", cfg.TLS.CAFile); err != nil {
			return err
		}
	}
	if certFile != "" {
		if err := validateTLSFilePath("cert_file", cfg.TLS.CertFile); err != nil {
			return err
		}
	}
	if keyFile != "" {
		if err := validateTLSFilePath("key_file", cfg.TLS.KeyFile); err != nil {
			return err
		}
	}
	return nil
}

func validateTLSFilePath(field string, path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("invalid TLS configuration: %s is empty", field)
	}
	if trimmed != path {
		return fmt.Errorf("invalid TLS configuration: %s must not contain surrounding whitespace", field)
	}
	if strings.ContainsFunc(path, unsafeTLSFilePathChar) {
		return fmt.Errorf("invalid TLS configuration: %s contains control characters", field)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("invalid TLS configuration: %s must be an absolute path", field)
	}
	return nil
}

func unsafeTLSFilePathChar(r rune) bool {
	return r < ' ' || r == 0x7f
}

func validateAPIKeyTransport(cfg config.ControllerClientConfig) error {
	if strings.TrimSpace(cfg.APIKey) == "" || cfg.AllowPlaintextAPIKey {
		return nil
	}

	parsed, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil {
		return fmt.Errorf("invalid controller URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "http") {
		return nil
	}
	if isLoopbackURLHost(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("invalid controller API key transport: plaintext HTTP is only allowed for loopback hosts; use https or set allow_plaintext_api_key=true for an intentionally trusted transport")
}

func isLoopbackURLHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

func (c *Client) readResponseBody(body io.Reader) ([]byte, error) {
	limit := c.maxResponseBytes
	if limit <= 0 {
		limit = config.DefaultControllerClientMaxResponseBytes
	}

	data, err := readLimitedBody(body, limit)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func readLimitedBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeds limit of %d bytes", limit)
	}
	return data, nil
}

func readErrorResponseBody(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, maxErrorResponseBodySize+1))
	if err != nil {
		return fmt.Sprintf("<failed to read body: %v>", err)
	}
	if len(data) > maxErrorResponseBodySize {
		return string(data[:maxErrorResponseBodySize]) + "...(truncated)"
	}
	return string(data)
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

		if err := validateListZonesPagination(result, offset, listZonesPageLimit); err != nil {
			return nil, err
		}

		count := result.Pagination.Count
		limit := result.Pagination.Limit

		if count == 0 || count < limit {
			break
		}

		offset += count
	}

	return zones, nil
}

func validateListZonesPagination(result *listZonesResponse, expectedOffset, expectedLimit int) error {
	if result.Pagination.Offset != expectedOffset {
		return fmt.Errorf("invalid zones pagination offset: got %d, want %d", result.Pagination.Offset, expectedOffset)
	}
	if result.Pagination.Limit != expectedLimit {
		return fmt.Errorf("invalid zones pagination limit: got %d, want %d", result.Pagination.Limit, expectedLimit)
	}
	if result.Pagination.Count < 0 {
		return fmt.Errorf("invalid zones pagination count: must be non-negative")
	}
	if result.Pagination.Count != len(result.Zones) {
		return fmt.Errorf("invalid zones pagination count: got %d, decoded %d zones", result.Pagination.Count, len(result.Zones))
	}
	if result.Pagination.Count > result.Pagination.Limit {
		return fmt.Errorf("invalid zones pagination count: got %d, exceeds limit %d", result.Pagination.Count, result.Pagination.Limit)
	}
	return nil
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
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, readErrorResponseBody(resp.Body))
	}

	var result listZonesResponse
	body, err := c.readResponseBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// FetchSignedZone fetches a signed zone file from the controller. If currentETag
// is provided, it performs a conditional fetch using If-None-Match unless
// artifact signatures are required. Use FetchSignedZoneWithCurrent when the
// caller can provide the locally cached body for signed 304 verification.
// Returns (zoneContent, newETag, isNotModified, error).
func (c *Client) FetchSignedZone(ctx context.Context, zoneName string, currentETag string) (string, string, bool, error) {
	artifact, err := c.FetchSignedZoneArtifact(ctx, zoneName, currentETag)
	if err != nil {
		return "", "", false, err
	}
	return artifact.Content, artifact.ETag, artifact.NotModified, nil
}

// FetchSignedZoneWithCurrent fetches a signed zone and may use conditional GET
// when currentBody is the locally cached artifact for currentETag. When
// signature verification is enabled, a 304 response is accepted only if the
// controller signs the local body with X-Zone-Signature.
func (c *Client) FetchSignedZoneWithCurrent(ctx context.Context, zoneName string, currentETag string, currentBody string) (string, string, bool, error) {
	artifact, err := c.FetchSignedZoneArtifactWithCurrent(ctx, zoneName, currentETag, currentBody)
	if err != nil {
		return "", "", false, err
	}
	return artifact.Content, artifact.ETag, artifact.NotModified, nil
}

// FetchSignedZoneArtifact fetches a signed zone file with verified artifact metadata.
func (c *Client) FetchSignedZoneArtifact(ctx context.Context, zoneName string, currentETag string) (*SignedZoneArtifact, error) {
	return c.fetchSignedZoneArtifact(ctx, zoneName, currentETag, "")
}

// FetchSignedZoneArtifactWithCurrent fetches a signed zone file with verified
// artifact metadata and may use conditional GET when the current body is known.
func (c *Client) FetchSignedZoneArtifactWithCurrent(ctx context.Context, zoneName string, currentETag string, currentBody string) (*SignedZoneArtifact, error) {
	return c.fetchSignedZoneArtifact(ctx, zoneName, currentETag, currentBody)
}

func (c *Client) fetchSignedZoneArtifact(ctx context.Context, zoneName string, currentETag string, currentBody string) (*SignedZoneArtifact, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	endpoint := fmt.Sprintf("%s/api/v1/zones/%s/signed", c.baseURL, url.PathEscape(zoneName))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	// Add If-None-Match header for conditional fetch (ETag-based).
	requestETag := c.conditionalRequestETag(currentETag, currentBody)
	if requestETag != "" {
		req.Header.Set("If-None-Match", requestETag)
	}

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified (zone hasn't changed)
	if resp.StatusCode == http.StatusNotModified {
		if requestETag == "" {
			return nil, fmt.Errorf("received 304 Not Modified without a conditional ETag")
		}

		responseETag := normalizeIfNoneMatch(resp.Header.Get("ETag"))
		if responseETag == "" {
			return nil, fmt.Errorf("missing ETag header in 304 response")
		}
		if responseETag != requestETag {
			return nil, fmt.Errorf("ETag mismatch in 304 response: requested %s, got %s", requestETag, responseETag)
		}

		if c.verifyChecksums {
			zoneHash := resp.Header.Get("X-Zone-Hash")
			if err := validateFullChecksumHeader(zoneHash); err != nil {
				return nil, fmt.Errorf("invalid checksum header in 304 response: %w", err)
			}
			responseHash := etagValue(responseETag)
			if !strings.EqualFold(responseHash, zoneHash) {
				return nil, fmt.Errorf("checksum header mismatch in 304 response: ETag %s, X-Zone-Hash %s", responseHash, zoneHash)
			}
			if currentBody != "" {
				computedHash := sha256.Sum256([]byte(currentBody))
				computedHashHex := hex.EncodeToString(computedHash[:])
				if !strings.EqualFold(computedHashHex, zoneHash) {
					return nil, fmt.Errorf("local artifact checksum mismatch in 304 response: local %s, X-Zone-Hash %s", computedHashHex, zoneHash)
				}
			}
		}

		if c.verifySignatures {
			if err := verifyArtifactSignature([]byte(currentBody), resp.Header.Get("X-Zone-Signature"), c.signatureKey); err != nil {
				return nil, fmt.Errorf("invalid signature header in 304 response: %w", err)
			}
		}

		return &SignedZoneArtifact{
			ETag:        currentETag,
			NotModified: true,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, readErrorResponseBody(resp.Body))
	}

	// Read zone file content
	body, err := c.readResponseBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Extract ETag from response headers
	newETag := resp.Header.Get("ETag")
	if newETag == "" {
		return nil, fmt.Errorf("missing ETag header in response")
	}

	// Extract integrity metadata from headers
	zoneSerial := resp.Header.Get("X-Zone-Serial")
	zoneHash := resp.Header.Get("X-Zone-Hash")
	zoneHash8 := resp.Header.Get("X-Zone-Hash8")
	zoneSignature := resp.Header.Get("X-Zone-Signature")

	// Verify SHA256 checksum when enabled. A full checksum header is required
	// because the agent otherwise cannot detect truncated or altered artifacts.
	if c.verifyChecksums {
		if err := validateFullChecksumHeader(zoneHash); err != nil {
			return nil, err
		}

		computedHash := sha256.Sum256(body)
		computedHashHex := hex.EncodeToString(computedHash[:])
		if !strings.EqualFold(computedHashHex, zoneHash) {
			return nil, fmt.Errorf("checksum verification failed: expected %s, got %s", zoneHash, computedHashHex)
		}
	}

	if c.verifySignatures {
		if err := verifyArtifactSignature(body, zoneSignature, c.signatureKey); err != nil {
			return nil, err
		}
	}

	bodySerial, err := parseZoneSOASerial(zoneName, string(body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed zone SOA serial: %w", err)
	}
	headerSerial, err := parseZoneSerialHeader(zoneSerial)
	if err != nil {
		return nil, err
	}
	if headerSerial != bodySerial {
		return nil, fmt.Errorf("zone serial header mismatch: X-Zone-Serial %d, SOA serial %d", headerSerial, bodySerial)
	}

	_ = zoneHash8 // Short hash is display metadata only; verification uses X-Zone-Hash.

	return &SignedZoneArtifact{
		Content: string(body),
		ETag:    newETag,
		Serial:  bodySerial,
		Hash:    zoneHash,
	}, nil
}

func parseZoneSerialHeader(value string) (uint32, error) {
	if strings.TrimSpace(value) == "" {
		return 0, fmt.Errorf("missing X-Zone-Serial header in response")
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid X-Zone-Serial header: %w", err)
	}
	return uint32(parsed), nil
}

func (c *Client) conditionalRequestETag(currentETag string, currentBody string) string {
	requestETag := normalizeIfNoneMatch(currentETag)
	if requestETag == "" {
		return ""
	}

	if !c.verifySignatures {
		return requestETag
	}

	if currentBody == "" {
		return ""
	}

	expectedHash := etagValue(requestETag)
	if len(expectedHash) != sha256.Size*2 {
		return ""
	}
	if _, err := hex.DecodeString(expectedHash); err != nil {
		return ""
	}

	computedHash := sha256.Sum256([]byte(currentBody))
	if !strings.EqualFold(hex.EncodeToString(computedHash[:]), expectedHash) {
		return ""
	}

	return requestETag
}

func validateFullChecksumHeader(zoneHash string) error {
	if zoneHash == "" {
		return fmt.Errorf("missing full checksum header in response")
	}
	if len(zoneHash) != sha256.Size*2 {
		return fmt.Errorf("invalid checksum header length: expected %d hex chars, got %d", sha256.Size*2, len(zoneHash))
	}
	if _, err := hex.DecodeString(zoneHash); err != nil {
		return fmt.Errorf("invalid checksum header: %w", err)
	}
	return nil
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
