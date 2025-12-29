package bird

import (
	"strings"
	"testing"
)

func TestParseResponse_Success(t *testing.T) {
	input := `0001-BIRD 2.0.8 ready.
0013 Router ID is 192.168.1.1
`
	reader := strings.NewReader(input)
	resp, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse failed: %v", err)
	}

	if resp.Code != 13 {
		t.Errorf("expected code 13, got %d", resp.Code)
	}

	if !resp.IsSuccess() {
		t.Error("expected success response")
	}

	if len(resp.Lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(resp.Lines))
	}

	expected := []string{"BIRD 2.0.8 ready.", "Router ID is 192.168.1.1"}
	for i, line := range resp.Lines {
		if line != expected[i] {
			t.Errorf("line %d: expected %q, got %q", i, expected[i], line)
		}
	}
}

func TestParseResponse_Error(t *testing.T) {
	input := `9001 syntax error
`
	reader := strings.NewReader(input)
	resp, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse failed: %v", err)
	}

	if resp.Code != 9001 {
		t.Errorf("expected error code 9001, got %d", resp.Code)
	}

	if len(resp.Lines) != 1 {
		t.Errorf("expected 1 line, got %d", len(resp.Lines))
	}

	// First line should contain the error message
	if !strings.Contains(resp.Lines[0], "syntax error") {
		t.Error("expected 'syntax error' in response")
	}
}

func TestParseResponse_RuntimeError(t *testing.T) {
	input := `8003 Protocol not found
0000
`
	reader := strings.NewReader(input)
	resp, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse failed: %v", err)
	}

	if resp.Code != 8003 {
		t.Errorf("expected code 8003, got %d", resp.Code)
	}

	if !resp.IsError() {
		t.Error("expected IsError() to be true for 8003")
	}
}

func TestParseResponse_SyntaxError_WithTerminator(t *testing.T) {
	input := `9001 syntax error
0000
`
	reader := strings.NewReader(input)
	resp, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse failed: %v", err)
	}

	if resp.Code != 9001 {
		t.Errorf("expected code 9001, got %d", resp.Code)
	}

	if !resp.IsError() {
		t.Error("expected IsError() to be true for 9001")
	}
}

func TestParseResponse_SingleLine(t *testing.T) {
	input := `0000
`
	reader := strings.NewReader(input)
	resp, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse failed: %v", err)
	}

	if resp.Code != 0 {
		t.Errorf("expected code 0, got %d", resp.Code)
	}

	if !resp.IsSuccess() {
		t.Error("expected success")
	}
}

func TestParseResponse_ShowStatus(t *testing.T) {
	input := `1000-BIRD 2.0.8
1011-Router ID is 192.168.1.1
1013-Current server time is 2025-12-29 03:00:00
0013 Daemon is up and running
0000
`
	reader := strings.NewReader(input)
	resp, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse failed: %v", err)
	}

	if !resp.IsSuccess() {
		t.Error("expected success")
	}

	if len(resp.Lines) < 3 {
		t.Errorf("expected at least 3 lines, got %d", len(resp.Lines))
	}
}

func TestParseGreeting(t *testing.T) {
	input := `0001 BIRD 2.0.8 ready.
`
	reader := strings.NewReader(input)
	greeting, err := ParseGreeting(reader)
	if err != nil {
		t.Fatalf("ParseGreeting failed: %v", err)
	}

	expected := "BIRD 2.0.8 ready."
	if greeting != expected {
		t.Errorf("expected %q, got %q", expected, greeting)
	}
}

func TestResponse_IsSuccess(t *testing.T) {
	tests := []struct {
		code    int
		success bool
	}{
		{0, true},
		{1000, true},
		{7999, true},
		{8000, false},
		{9001, false},
		{9999, false},
	}

	for _, tt := range tests {
		resp := &Response{Code: tt.code}
		if resp.IsSuccess() != tt.success {
			t.Errorf("code %d: expected IsSuccess=%v, got %v", tt.code, tt.success, resp.IsSuccess())
		}
	}
}

func TestResponse_IsError(t *testing.T) {
	tests := []struct {
		code  int
		error bool
	}{
		{0, false},
		{1000, false},
		{7999, false},
		{8000, true},
		{9001, true},
		{9999, true},
	}

	for _, tt := range tests {
		resp := &Response{Code: tt.code}
		if resp.IsError() != tt.error {
			t.Errorf("code %d: expected IsError=%v, got %v", tt.code, tt.error, resp.IsError())
		}
	}
}
