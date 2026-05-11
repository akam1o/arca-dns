package sync

import (
	"fmt"
	"strings"

	"github.com/akam1o/arca-dns/pkg/parser"
	"github.com/miekg/dns"
)

func parseZoneSOASerial(zoneName, zoneContent string) (uint32, error) {
	parsed, err := parser.ParseBINDZone(strings.NewReader(zoneContent), zoneName, parser.DefaultParseOptions())
	if err != nil {
		return 0, err
	}

	for _, rr := range parsed.Records {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, nil
		}
	}

	return 0, fmt.Errorf("missing SOA record")
}

func zoneSerialBefore(candidate, current uint32) bool {
	return candidate != current && current-candidate < 1<<31
}
