package model

import "testing"

func TestNormalizeZoneName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "already normalized",
			input: "example.com.",
			want:  "example.com.",
		},
		{
			name:  "uppercase",
			input: "EXAMPLE.COM.",
			want:  "example.com.",
		},
		{
			name:  "mixed case",
			input: "Example.COM.",
			want:  "example.com.",
		},
		{
			name:  "missing trailing dot",
			input: "example.com",
			want:  "example.com.",
		},
		{
			name:  "uppercase without dot",
			input: "EXAMPLE.COM",
			want:  "example.com.",
		},
		{
			name:  "subdomain",
			input: "SUB.Example.COM",
			want:  "sub.example.com.",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "single label",
			input: "localhost",
			want:  "localhost.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeZoneName(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeZoneName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomainName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "already normalized",
			input: "www.example.com.",
			want:  "www.example.com.",
		},
		{
			name:  "uppercase",
			input: "WWW.EXAMPLE.COM.",
			want:  "www.example.com.",
		},
		{
			name:  "missing trailing dot",
			input: "www.example.com",
			want:  "www.example.com.",
		},
		{
			name:  "zone apex marker",
			input: "@",
			want:  "@",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "wildcard",
			input: "*.example.com",
			want:  "*.example.com.",
		},
		{
			name:  "wildcard uppercase",
			input: "*.EXAMPLE.COM",
			want:  "*.example.com.",
		},
		{
			name:  "wildcard with dot",
			input: "*.example.com.",
			want:  "*.example.com.",
		},
		{
			name:  "relative name",
			input: "mail",
			want:  "mail.",
		},
		{
			name:  "subdomain relative",
			input: "mail.sub",
			want:  "mail.sub.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDomainName(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeDomainName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomainName_Idempotent(t *testing.T) {
	inputs := []string{
		"EXAMPLE.COM",
		"www.example.com",
		"*.EXAMPLE.COM",
		"@",
		"",
	}

	for _, input := range inputs {
		first := NormalizeDomainName(input)
		second := NormalizeDomainName(first)

		if first != second {
			t.Errorf("NormalizeDomainName not idempotent for %q: first=%q, second=%q", input, first, second)
		}
	}
}

func TestNormalizeRecordOwnerName(t *testing.T) {
	tests := []struct {
		name       string
		ownerName  string
		zoneOrigin string
		want       string
	}{
		{
			name:       "relative name",
			ownerName:  "www",
			zoneOrigin: "example.com.",
			want:       "www.example.com.",
		},
		{
			name:       "FQDN with trailing dot",
			ownerName:  "www.example.com.",
			zoneOrigin: "example.com.",
			want:       "www.example.com.",
		},
		{
			name:       "FQDN without trailing dot",
			ownerName:  "www.example.com",
			zoneOrigin: "example.com.",
			want:       "www.example.com.",
		},
		{
			name:       "apex marker",
			ownerName:  "@",
			zoneOrigin: "example.com.",
			want:       "example.com.",
		},
		{
			name:       "apex without trailing dot",
			ownerName:  "example.com",
			zoneOrigin: "example.com.",
			want:       "example.com.",
		},
		{
			name:       "subdomain FQDN without trailing dot",
			ownerName:  "mail.sub.example.com",
			zoneOrigin: "example.com.",
			want:       "mail.sub.example.com.",
		},
		{
			name:       "subdomain relative",
			ownerName:  "mail.sub",
			zoneOrigin: "example.com.",
			want:       "mail.sub.example.com.",
		},
		{
			name:       "wildcard FQDN without trailing dot",
			ownerName:  "*.www.example.com",
			zoneOrigin: "example.com.",
			want:       "*.www.example.com.",
		},
		{
			name:       "uppercase FQDN without trailing dot",
			ownerName:  "WWW.EXAMPLE.COM",
			zoneOrigin: "example.com.",
			want:       "www.example.com.",
		},
		{
			name:       "origin without trailing dot",
			ownerName:  "www",
			zoneOrigin: "example.com",
			want:       "www.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeRecordOwnerName(tt.ownerName, tt.zoneOrigin)
			if got != tt.want {
				t.Errorf("NormalizeRecordOwnerName(%q, %q) = %q, want %q", tt.ownerName, tt.zoneOrigin, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomainTargetName(t *testing.T) {
	tests := []struct {
		name       string
		targetName string
		zoneOrigin string
		want       string
	}{
		{
			name:       "relative target",
			targetName: "mail",
			zoneOrigin: "example.com.",
			want:       "mail.example.com.",
		},
		{
			name:       "relative dotted target",
			targetName: "mail.sub",
			zoneOrigin: "example.com.",
			want:       "mail.sub.example.com.",
		},
		{
			name:       "FQDN with trailing dot",
			targetName: "mail.example.com.",
			zoneOrigin: "example.com.",
			want:       "mail.example.com.",
		},
		{
			name:       "FQDN without trailing dot under origin",
			targetName: "mail.example.com",
			zoneOrigin: "example.com.",
			want:       "mail.example.com.",
		},
		{
			name:       "uppercase target under origin",
			targetName: "MAIL.EXAMPLE.COM",
			zoneOrigin: "example.com.",
			want:       "mail.example.com.",
		},
		{
			name:       "external target without trailing dot is relative",
			targetName: "mail.external.net",
			zoneOrigin: "example.com.",
			want:       "mail.external.net.example.com.",
		},
		{
			name:       "apex shorthand is preserved for validation",
			targetName: "@",
			zoneOrigin: "example.com.",
			want:       "@",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDomainTargetName(tt.targetName, tt.zoneOrigin)
			if got != tt.want {
				t.Errorf("NormalizeDomainTargetName(%q, %q) = %q, want %q", tt.targetName, tt.zoneOrigin, got, tt.want)
			}
		})
	}
}
