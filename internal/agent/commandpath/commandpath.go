package commandpath

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Validate checks an executable path before it is passed to os/exec.
func Validate(field string, path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("invalid %s: empty", field)
	}
	if trimmed != path {
		return fmt.Errorf("invalid %s: must not contain surrounding whitespace", field)
	}
	if strings.ContainsFunc(path, unsafePathChar) {
		return fmt.Errorf("invalid %s: contains control characters", field)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("invalid %s: must be an absolute path", field)
	}
	return nil
}

func unsafePathChar(r rune) bool {
	return r < ' ' || r == 0x7f
}
