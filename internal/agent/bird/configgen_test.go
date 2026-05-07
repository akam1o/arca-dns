package bird

import (
	"strings"
	"testing"
	"time"

	"github.com/akam1o/arca-dns/pkg/config"
)

func TestRenderAnycastConfig_Basic(t *testing.T) {
	cfg := testAnycastConfig()

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

func TestRenderAnycastConfig_RejectsInvalidAnycastPrefix(t *testing.T) {
	cfg := testAnycastConfig()
	cfg.AnycastPrefixes = []string{"192.0.2.53/32; import all;"}

	_, _, err := RenderAnycastConfig(cfg)
	if err == nil {
		t.Fatal("expected invalid prefix error")
	}
	if !strings.Contains(err.Error(), "bird.anycast_prefixes") {
		t.Fatalf("expected anycast prefix error, got %v", err)
	}
}

func TestRenderAnycastConfig_RejectsInvalidProtocolIdentifier(t *testing.T) {
	tests := map[string]func(*config.BIRDConfig){
		"protocols": func(cfg *config.BIRDConfig) {
			cfg.Protocols[0].Name = "anycast-1"
		},
		"protocol_names": func(cfg *config.BIRDConfig) {
			cfg.Protocols = nil
			cfg.ProtocolNames = []string{"anycast; disable all;"}
			cfg.ConfigureOnStart.Neighbors = []config.BIRDNeighborConfig{
				{Address: "10.0.0.1", ASN: 64512},
			}
		},
		"protocol_name": func(cfg *config.BIRDConfig) {
			cfg.Protocols = nil
			cfg.ProtocolName = "1anycast"
			cfg.ConfigureOnStart.Neighbors = []config.BIRDNeighborConfig{
				{Address: "10.0.0.1", ASN: 64512},
			}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testAnycastConfig()
			mutate(&cfg)

			_, _, err := RenderAnycastConfig(cfg)
			if err == nil {
				t.Fatal("expected invalid protocol identifier error")
			}
			if !strings.Contains(err.Error(), "bird.protocol") {
				t.Fatalf("expected protocol identifier error, got %v", err)
			}
		})
	}
}

func testAnycastConfig() config.BIRDConfig {
	return config.BIRDConfig{
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
}
