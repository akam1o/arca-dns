package dnssec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validateKeyStorageDirectoryPath(label string, path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	if trimmed != path {
		return fmt.Errorf("%s must not contain surrounding whitespace", label)
	}
	if strings.ContainsFunc(path, unsafeKeyStoragePathChar) {
		return fmt.Errorf("%s contains control characters", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path: %s", label, path)
	}
	return nil
}

func validateKeyStorageFilePath(label string, path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	if trimmed != path {
		return fmt.Errorf("%s must not contain surrounding whitespace", label)
	}
	if strings.ContainsFunc(path, unsafeKeyStoragePathChar) {
		return fmt.Errorf("%s contains control characters", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path: %s", label, path)
	}
	if base := filepath.Base(path); base == "." || base == string(filepath.Separator) {
		return fmt.Errorf("%s must include a filename: %s", label, path)
	}
	return nil
}

func validateKeyStorageFileName(label string, fileName string) error {
	trimmed := strings.TrimSpace(fileName)
	if trimmed == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	if trimmed != fileName {
		return fmt.Errorf("%s must not contain surrounding whitespace", label)
	}
	if strings.ContainsFunc(fileName, unsafeKeyStoragePathChar) {
		return fmt.Errorf("%s contains control characters", label)
	}
	if filepath.IsAbs(fileName) || filepath.Base(fileName) != fileName || fileName == "." || fileName == ".." {
		return fmt.Errorf("%s must be a filename, not a path: %s", label, fileName)
	}
	return nil
}

func validateKeyStorageDirectoryIfExists(path string, label string) error {
	if err := validateExistingKeyDirectory(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", label, err)
	}
	return nil
}

func unsafeKeyStoragePathChar(r rune) bool {
	return r < ' ' || r == 0x7f
}
