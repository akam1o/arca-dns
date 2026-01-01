package parser

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"
)

// ParsedZone represents the intermediate representation of a parsed BIND zone file
type ParsedZone struct {
	Origin     string    // Zone origin (e.g., "example.com.")
	DefaultTTL uint32    // Default TTL from $TTL directive
	Records    []dns.RR  // Parsed resource records
}

// ParseOptions configures zone file parsing behavior
type ParseOptions struct {
	// AllowIncludes enables support for $INCLUDE directive (single level only)
	AllowIncludes bool
	// DefaultTTL is used when $TTL directive is missing
	DefaultTTL uint32
}

// DefaultParseOptions returns sensible defaults for zone file parsing
// Note: AllowIncludes is false by default for security (prevents arbitrary file access)
func DefaultParseOptions() ParseOptions {
	return ParseOptions{
		AllowIncludes: false, // Secure default for API usage
		DefaultTTL:    3600,  // 1 hour default if $TTL not specified
	}
}

// ParseBINDZone parses a BIND zone file and returns an intermediate representation
func ParseBINDZone(reader io.Reader, origin string, opts ParseOptions) (*ParsedZone, error) {
	if origin == "" {
		return nil, fmt.Errorf("origin must not be empty")
	}

	// Ensure origin ends with a dot
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}

	// Read all content for pre-scan validation
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read zone file: %w", err)
	}

	// Pre-scan for unsupported directives
	if err := validateDirectives(string(content), opts); err != nil {
		return nil, err
	}

	parsed := &ParsedZone{
		Origin:     origin,
		DefaultTTL: opts.DefaultTTL,
		Records:    make([]dns.RR, 0),
	}

	// Create zone parser from buffered content
	zoneParser := dns.NewZoneParser(strings.NewReader(string(content)), origin, "")
	zoneParser.SetDefaultTTL(opts.DefaultTTL)

	// Enable includes if allowed
	if opts.AllowIncludes {
		zoneParser.SetIncludeAllowed(true)
	}

	// Track if we've seen $TTL directive
	hasTTL := false

	for rr, ok := zoneParser.Next(); ok; rr, ok = zoneParser.Next() {
		// Check for parsing errors
		if err := zoneParser.Err(); err != nil {
			return nil, fmt.Errorf("parse error: %w", err)
		}

		// Extract TTL from first record if $TTL not explicitly set
		if !hasTTL && rr != nil && rr.Header().Ttl > 0 {
			hasTTL = true
			parsed.DefaultTTL = rr.Header().Ttl
		}

		if rr != nil {
			parsed.Records = append(parsed.Records, rr)
		}
	}

	// Check for final parsing errors
	if err := zoneParser.Err(); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	// Validate we got at least some records
	if len(parsed.Records) == 0 {
		return nil, fmt.Errorf("no records found in zone file")
	}

	return parsed, nil
}

// validateDirectives performs pre-scan validation of zone file directives
func validateDirectives(content string, opts ParseOptions) error {
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	includeCount := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Trim leading/trailing whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Convert to uppercase for case-insensitive directive matching
		lineUpper := strings.ToUpper(line)

		// Check for $GENERATE (explicitly unsupported) - case insensitive
		if strings.HasPrefix(lineUpper, "$GENERATE") || strings.Contains(lineUpper, "$GENERATE") {
			return fmt.Errorf("$GENERATE directive is not supported (line %d)", lineNum)
		}

		// Check for $INCLUDE - case insensitive
		if strings.HasPrefix(lineUpper, "$INCLUDE") {
			if !opts.AllowIncludes {
				return fmt.Errorf("$INCLUDE directive is not allowed (line %d)", lineNum)
			}
			includeCount++
			// Warn: We can only count includes in the top-level file
			// Nested includes in included files cannot be detected by pre-scan
			if includeCount > 1 {
				return fmt.Errorf("multiple $INCLUDE directives not supported (only single file include allowed, line %d)", lineNum)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan zone file: %w", err)
	}

	return nil
}

// lineNumber extracts line number from miekg/dns error message
// Error format: "dns: bad SOA zone parameter: \"example.com\" at line: 5:10"
func lineNumber(errStr string) int {
	// Try to extract line number from error message
	parts := strings.Split(errStr, "line:")
	if len(parts) < 2 {
		return 0
	}

	linePart := strings.TrimSpace(parts[1])
	var line int
	fmt.Sscanf(linePart, "%d", &line)
	return line
}
