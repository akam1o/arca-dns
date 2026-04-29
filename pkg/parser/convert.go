package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
)

// BindToModel converts a BIND zone file to a model.Zone
// This is the main entry point for parsing raw zone files
func BindToModel(raw string, origin string) (*model.Zone, error) {
	// Parse the BIND zone file
	reader := strings.NewReader(raw)
	opts := DefaultParseOptions()

	parsed, err := ParseBINDZone(reader, origin, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse zone file: %w", err)
	}

	// Normalize to model.Zone
	normOpts := DefaultNormalizeOptions()
	zone, err := NormalizeParsedZone(parsed, normOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize zone: %w", err)
	}

	// Validate the result
	if err := model.ValidateZone(zone); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return zone, nil
}

// ModelToBind converts a model.Zone to BIND zone file format
// This uses the existing generator to maintain consistency
func ModelToBind(zone *model.Zone) (string, error) {
	if zone == nil {
		return "", fmt.Errorf("zone is nil")
	}

	// Validate before generation
	if err := model.ValidateZone(zone); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	// Use existing BIND generator
	return GenerateBINDZoneFile(zone)
}

// ModelToBindWriter writes a model.Zone to a writer in BIND format
func ModelToBindWriter(zone *model.Zone, w io.Writer) error {
	content, err := ModelToBind(zone)
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(content))
	return err
}

// BindToModelWithDefaults is a convenience function that uses sensible defaults
// for origin extraction from the zone file itself
func BindToModelWithDefaults(raw string) (*model.Zone, error) {
	// Try to extract origin from $ORIGIN directive or SOA record
	origin, err := extractOrigin(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract origin: %w", err)
	}

	return BindToModel(raw, origin)
}

// extractOrigin attempts to extract the zone origin from a BIND zone file
func extractOrigin(raw string) (string, error) {
	lines := strings.Split(raw, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for $ORIGIN directive
		if strings.HasPrefix(line, "$ORIGIN") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				origin := parts[1]
				// Ensure trailing dot
				if !strings.HasSuffix(origin, ".") {
					origin += "."
				}
				return origin, nil
			}
		}

		// Check for SOA record (format: <origin> IN SOA ...)
		if strings.Contains(line, " SOA ") || strings.Contains(line, "\tSOA\t") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				origin := parts[0]
				// Handle @ symbol
				if origin == "@" {
					return "", fmt.Errorf("cannot determine origin from @ symbol without $ORIGIN directive")
				}
				// Ensure trailing dot
				if !strings.HasSuffix(origin, ".") {
					origin += "."
				}
				return origin, nil
			}
		}
	}

	return "", fmt.Errorf("no $ORIGIN directive or SOA record found")
}
