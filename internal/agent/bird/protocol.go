package bird

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Response represents a BIRD control protocol response.
type Response struct {
	Code    int      // Status code from the last line (0000-9999)
	Lines   []string // All response lines (without status codes)
	RawText string   // Full raw response text
}

// IsSuccess returns true if the response indicates success.
// BIRD uses codes 0000-0999 for success, 8000-9999 for errors.
func (r *Response) IsSuccess() bool {
	return r.Code < 8000
}

// IsError returns true if the response indicates an error.
func (r *Response) IsError() bool {
	return r.Code >= 8000
}

// ParseResponse parses a BIRD control protocol response.
// BIRD protocol format:
// - Each line starts with a 4-digit code followed by a space or dash
// - Code ending with space indicates the last line (terminal)
// - Code ending with dash indicates continuation
// - 0000-0999: Success codes
// - 8000-8999: Runtime errors
// - 9000-9999: Syntax errors
//
// Example:
//
//	0001-BIRD 2.0.8 ready.
//	0000
//
// Example error:
//
//	9001 syntax error
//	0000
func ParseResponse(reader io.Reader) (*Response, error) {
	scanner := bufio.NewScanner(reader)
	var lines []string
	var rawLines []string
	var lastCode int

	for scanner.Scan() {
		line := scanner.Text()
		rawLines = append(rawLines, line)

		// BIRD lines are either "CCCC" or "CCCC " or "CCCC-content" where C is a digit
		if len(line) < 4 {
			// Invalid line format, but continue reading
			continue
		}

		// Extract code (first 4 characters)
		codeStr := line[0:4]
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			// Not a valid code line, but continue
			continue
		}

		// Check separator (5th character if present)
		separator := " " // Default to terminal for 4-char lines like "0000"
		if len(line) > 4 {
			separator = line[4:5]
		}

		// Extract content (after code and separator)
		content := ""
		if len(line) > 5 {
			content = line[5:]
		}
		lines = append(lines, content)

		// Terminal line: space separator (not dash) or exactly 4 chars
		if separator == " " {
			// 0000 is the terminator, don't overwrite the actual status code
			if code == 0 {
				break
			}
			// Non-zero terminal line: this is the actual status code
			lastCode = code
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return &Response{
		Code:    lastCode,
		Lines:   lines,
		RawText: strings.Join(rawLines, "\n"),
	}, nil
}

// ParseGreeting parses the initial BIRD greeting message.
// Example: "0001 BIRD 2.0.8 ready."
func ParseGreeting(reader io.Reader) (string, error) {
	resp, err := ParseResponse(reader)
	if err != nil {
		return "", fmt.Errorf("parse greeting: %w", err)
	}

	if len(resp.Lines) == 0 {
		return "", fmt.Errorf("empty greeting")
	}

	return resp.Lines[0], nil
}
