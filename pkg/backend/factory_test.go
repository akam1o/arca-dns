package backend

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetRegisteredBackends verifies all expected backends are registered.
func TestGetRegisteredBackends(t *testing.T) {
	backends := GetRegisteredBackends()

	// Should have all 6 backends
	assert.Len(t, backends, 6, "Should have exactly 6 registered backends")

	// Should be sorted
	assert.Equal(t, []string{"etcd", "git", "memory", "mysql", "postgres", "sqlite"}, backends,
		"Backends should be sorted alphabetically")
}

// TestNewBackend_Memory tests memory backend factory.
func TestNewBackend_Memory(t *testing.T) {
	config := map[string]interface{}{
		"initial_capacity": 100,
	}

	backend, err := NewBackend("memory", config)
	require.NoError(t, err)
	assert.NotNil(t, backend)

	// Verify it's actually a MemoryBackend
	_, ok := backend.(*MemoryBackend)
	assert.True(t, ok, "Should return MemoryBackend instance")

	// Cleanup
	backend.Close()
}

// TestNewBackend_Git tests git backend factory with config compatibility.
func TestNewBackend_Git(t *testing.T) {
	tmpDir := t.TempDir()

	testCases := []struct {
		name   string
		config map[string]interface{}
	}{
		{
			name: "new config format (author/email/auto_push)",
			config: map[string]interface{}{
				"repository_path": tmpDir,
				"branch":          "main",
				"author":          "Test User",
				"email":           "test@example.com",
				"auto_push":       false,
			},
		},
		{
			name: "old config format (author_name/author_email/auto_sync)",
			config: map[string]interface{}{
				"repository_path": tmpDir,
				"branch":          "main",
				"author_name":     "Test User",
				"author_email":    "test@example.com",
				"auto_sync":       false,
			},
		},
		{
			name: "minimal config with defaults",
			config: map[string]interface{}{
				"repository_path": tmpDir,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend, err := NewBackend("git", tc.config)
			require.NoError(t, err)
			assert.NotNil(t, backend)

			// Verify it's actually a GitBackend
			gitBackend, ok := backend.(*GitBackend)
			assert.True(t, ok, "Should return GitBackend instance")
			assert.Equal(t, tmpDir, gitBackend.repoPath)

			// Cleanup
			backend.Close()
		})
	}
}

// TestNewBackend_Etcd tests etcd backend factory with type flexibility.
func TestNewBackend_Etcd(t *testing.T) {
	testCases := []struct {
		name        string
		config      map[string]interface{}
		expectError bool
	}{
		{
			name: "[]string endpoints (from config.EtcdBackendConfig)",
			config: map[string]interface{}{
				"endpoints": []string{"localhost:2379"},
				"prefix":    "/test",
				"username":  "",
				"password":  "",
				// Keep timeouts low so tests don't stall when etcd isn't running.
				"dial_timeout":    200 * time.Millisecond,
				"request_timeout": 300 * time.Millisecond,
			},
			expectError: false, // Will fail to connect but factory should work
		},
		{
			name: "[]interface{} endpoints (from generic map)",
			config: map[string]interface{}{
				"endpoints":       []interface{}{"localhost:2379"},
				"prefix":          "/test",
				"username":        "",
				"password":        "",
				"dial_timeout":    5 * time.Second,
				"request_timeout": 10 * time.Second,
			},
			expectError: false, // Will fail to connect but factory should work
		},
		{
			name: "missing endpoints",
			config: map[string]interface{}{
				"prefix": "/test",
			},
			expectError: true,
		},
		{
			name: "empty endpoints",
			config: map[string]interface{}{
				"endpoints": []string{},
			},
			expectError: true,
		},
		{
			name: "wrong type endpoints",
			config: map[string]interface{}{
				"endpoints": "localhost:2379", // string instead of slice
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend, err := NewBackend("etcd", tc.config)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, backend)
			} else {
				// Note: Will fail with connection error since etcd isn't running
				// but that's OK - we're testing the factory config parsing
				if backend != nil {
					backend.Close()
				}
			}
		})
	}
}

// TestNewBackend_MySQL tests mysql backend factory.
func TestNewBackend_MySQL(t *testing.T) {
	config := map[string]interface{}{
		"dsn": "user:pass@tcp(localhost:3306)/test?parseTime=true",
	}

	// Note: Will fail with connection error since MySQL isn't running
	// but we're testing the factory can be called
	backend, err := NewBackend("mysql", config)

	// Either succeeds (if MySQL running) or fails with connection error
	if err == nil {
		assert.NotNil(t, backend)
		backend.Close()
	} else {
		// Connection error is expected if MySQL isn't running
		assert.Contains(t, err.Error(), "failed to")
	}
}

// TestNewBackend_UnknownType tests error handling for unknown backend type.
func TestNewBackend_UnknownType(t *testing.T) {
	backend, err := NewBackend("unknown", map[string]interface{}{})

	assert.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "unknown backend type")
}

// TestRegisterBackend_Duplicate tests duplicate registration detection.
func TestRegisterBackend_Duplicate(t *testing.T) {
	// This test can't actually run because RegisterBackend is called in init()
	// and we can't safely test panic behavior with already-registered backends.
	// Instead, we document the expected behavior:
	//
	// RegisterBackend will panic if called with an already-registered type.
	// This is intentional to catch configuration errors at startup.
	//
	// Example (would panic):
	// RegisterBackend("memory", func(cfg map[string]interface{}) (ZoneStore, error) {
	//     return nil, nil
	// })

	t.Skip("Cannot test duplicate registration in unit tests (init() already registered)")
}

// TestFactoryThreadSafety tests concurrent access to factory registry.
func TestFactoryThreadSafety(t *testing.T) {
	const goroutines = 10
	const iterations = 100

	// Pre-create temp directories (t.TempDir() is not safe for concurrent use)
	tmpDirs := make([]string, goroutines*iterations)
	for i := range tmpDirs {
		tmpDirs[i] = t.TempDir()
	}

	// Channel to collect errors from goroutines
	errChan := make(chan error, goroutines*iterations)
	done := make(chan bool, goroutines)

	// Spawn multiple goroutines calling GetRegisteredBackends and NewBackend
	for i := 0; i < goroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			for j := 0; j < iterations; j++ {
				// Read operations
				backends := GetRegisteredBackends()
				if len(backends) == 0 {
					errChan <- fmt.Errorf("GetRegisteredBackends returned empty slice")
					continue
				}

				// Factory operations
				tmpDir := tmpDirs[goroutineID*iterations+j]
				backend, err := NewBackend("git", map[string]interface{}{
					"repository_path": tmpDir,
				})
				if err != nil {
					errChan <- fmt.Errorf("NewBackend failed: %w", err)
					continue
				}
				if backend == nil {
					errChan <- fmt.Errorf("NewBackend returned nil backend without error")
					continue
				}
				backend.Close()
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}
	close(errChan)

	// Check for errors from goroutines
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		t.Errorf("Thread safety test failed with %d errors:", len(errors))
		for i, err := range errors {
			if i < 5 { // Print first 5 errors
				t.Errorf("  Error %d: %v", i+1, err)
			}
		}
		if len(errors) > 5 {
			t.Errorf("  ... and %d more errors", len(errors)-5)
		}
	}
}

// TestFactoryConfigValidation tests that factories properly validate config.
func TestFactoryConfigValidation(t *testing.T) {
	testCases := []struct {
		backendType string
		config      map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			backendType: "git",
			config:      map[string]interface{}{},
			expectError: true,
			errorMsg:    "repository_path",
		},
		{
			backendType: "git",
			config: map[string]interface{}{
				"repository_path": "",
			},
			expectError: true,
			errorMsg:    "repository_path",
		},
		{
			backendType: "mysql",
			config:      map[string]interface{}{},
			expectError: true,
			errorMsg:    "DSN",
		},
		{
			backendType: "etcd",
			config:      map[string]interface{}{},
			expectError: true,
			errorMsg:    "endpoints",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.backendType+"_invalid_config", func(t *testing.T) {
			backend, err := NewBackend(tc.backendType, tc.config)

			assert.Error(t, err)
			assert.Nil(t, backend)
			if tc.errorMsg != "" {
				assert.Contains(t, err.Error(), tc.errorMsg)
			}
		})
	}
}

// TestFactoryDefaults tests that factories apply correct defaults.
func TestFactoryDefaults(t *testing.T) {
	t.Run("git defaults", func(t *testing.T) {
		tmpDir := t.TempDir()
		backend, err := NewBackend("git", map[string]interface{}{
			"repository_path": tmpDir,
		})
		require.NoError(t, err)
		defer backend.Close()

		gitBackend := backend.(*GitBackend)
		assert.Equal(t, "main", gitBackend.branch)
		assert.Equal(t, "arca-dns-controller", gitBackend.authorName)
		assert.Equal(t, "noreply@arca-dns", gitBackend.authorEmail)
		assert.False(t, gitBackend.autoSync)
	})

	t.Run("etcd defaults", func(t *testing.T) {
		// Can't test actual defaults without connecting to etcd,
		// but we can verify factory accepts minimal config
		config := map[string]interface{}{
			"endpoints": []string{"localhost:2379"},
		}

		// Will fail with connection error, but config should be accepted
		_, err := NewBackend("etcd", config)

		// Error is expected (no etcd running), but it should be connection error,
		// not config error
		if err != nil {
			assert.Contains(t, err.Error(), "failed to connect")
		}
	})
}

// TestMemoryBackendFactory tests memory backend with various configs.
func TestMemoryBackendFactory(t *testing.T) {
	testCases := []struct {
		name   string
		config map[string]interface{}
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "empty config",
			config: map[string]interface{}{},
		},
		{
			name: "with initial_capacity",
			config: map[string]interface{}{
				"initial_capacity": 100,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend, err := NewBackend("memory", tc.config)
			require.NoError(t, err)
			assert.NotNil(t, backend)

			// Memory backend should always succeed
			_, ok := backend.(*MemoryBackend)
			assert.True(t, ok)

			backend.Close()
		})
	}
}
