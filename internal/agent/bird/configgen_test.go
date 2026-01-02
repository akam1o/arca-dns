package bird

import (
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
)

func TestRenderAnycastConfig_Basic(t *testing.T) {
	cfg := config.BIRDConfig{
		Protocols: []config.BIRDProtocolConfig{
			{Name: "anycast_1", NeighborAddress: "10.0.0.1", NeighborASN: 64512},
			{Name: "anycast_2", NeighborAddress: "10.0.0.2", NeighborASN: 64512},
		},
		AnycastPrefixes: []string{
			"192.0.2.53/32",
			"2001:db8::53/128",
		},
		ConfigureOnStart: config.BIRDConfigGenerationConfig{
			Enabled:  true,
			Path:     "/etc/bird/arca-dns.conf",
			RouterID: "10.0.0.5",
			LocalAS:  65001,
			SourceIP: "10.0.0.5",
			BFD: config.BIRDBFDConfig{
				Enabled:    true,
				MinRx:      300 * time.Millisecond,
				MinTx:      300 * time.Millisecond,
				Multiplier: 5,
			},
		},
	}

	out, protos, err := RenderAnycastConfig(cfg)
	if err != nil {
		t.Fatalf("RenderAnycastConfig returned error: %v", err)
	}
	if len(protos) != 2 {
		t.Fatalf("expected 2 protocol names, got %d", len(protos))
	}
	if protos[0] != "anycast_1" || protos[1] != "anycast_2" {
		t.Fatalf("unexpected protocol names: %v", protos)
	}

	mustContain := []string{
		"router id 10.0.0.5;",
		"protocol bfd {",
		"local as 65001;",
		"source address 10.0.0.5;",
		"route 192.0.2.53/32 blackhole;",
		"route 2001:db8::53/128 blackhole;",
		"protocol bgp anycast_1",
		"neighbor 10.0.0.1 as 64512;",
		"protocol bgp anycast_2",
		"neighbor 10.0.0.2 as 64512;",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Fatalf("expected output to contain %q\n\noutput:\n%s", s, out)
		}
	}
}
