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
