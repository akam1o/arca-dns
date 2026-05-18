package dnstap

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	dnstaplib "github.com/dnstap/golang-dnstap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestReceiver_ReadsBidirectionalFrameStreamFrames(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "d.sock")
	receiver := NewReceiver(ReceiverConfig{
		SocketPath: socketPath,
		BufferSize: 1,
	}, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	frameChan := make(chan Frame, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- receiver.Run(ctx, frameChan)
	}()

	waitForSocket(t, socketPath, errCh)

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	writer, err := dnstaplib.NewWriter(conn, &dnstaplib.WriterOptions{
		Bidirectional: true,
		Timeout:       time.Second,
	})
	require.NoError(t, err)

	payload := []byte("dnstap-payload")
	_, err = writer.WriteFrame(payload)
	require.NoError(t, err)
	flusher, ok := writer.(interface{ Flush() error })
	require.True(t, ok)
	require.NoError(t, flusher.Flush())

	select {
	case frame := <-frameChan:
		require.Equal(t, payload, frame.Data)
		require.False(t, frame.Timestamp.IsZero())
	case <-time.After(time.Second):
		t.Fatal("receiver did not emit frame")
	}

	require.NoError(t, writer.Close())
	cancel()
	requireRunCanceled(t, errCh)
}

func TestReceiver_RunClosesActiveConnectionsOnCancel(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "d.sock")
	receiver := NewReceiver(ReceiverConfig{
		SocketPath: socketPath,
		BufferSize: 1,
	}, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	frameChan := make(chan Frame, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- receiver.Run(ctx, frameChan)
	}()

	waitForSocket(t, socketPath, errCh)

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	cancel()

	requireRunCanceled(t, errCh)
}

func TestReceiver_RunRestrictsSocketPermissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "d.sock")
	receiver := NewReceiver(ReceiverConfig{
		SocketPath: socketPath,
		BufferSize: 1,
	}, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	frameChan := make(chan Frame, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- receiver.Run(ctx, frameChan)
	}()

	waitForSocket(t, socketPath, errCh)

	info, err := os.Lstat(socketPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(defaultSocketMode), info.Mode().Perm())

	cancel()
	requireRunCanceled(t, errCh)
}

func TestReceiver_RunUsesConfiguredSocketMode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "d.sock")
	receiver := NewReceiver(ReceiverConfig{
		SocketPath: socketPath,
		SocketMode: 0o600,
		BufferSize: 1,
	}, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	frameChan := make(chan Frame, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- receiver.Run(ctx, frameChan)
	}()

	waitForSocket(t, socketPath, errCh)

	info, err := os.Lstat(socketPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	cancel()
	requireRunCanceled(t, errCh)
}

func TestResolveSocketOwnership_NumericIDs(t *testing.T) {
	uid, gid, err := resolveSocketOwnership(strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()))
	require.NoError(t, err)
	require.Equal(t, os.Getuid(), uid)
	require.Equal(t, os.Getgid(), gid)
}

func TestResolveSocketOwnership_EmptyKeepsCurrentOwnership(t *testing.T) {
	uid, gid, err := resolveSocketOwnership("", "")
	require.NoError(t, err)
	require.Equal(t, -1, uid)
	require.Equal(t, -1, gid)
}

func TestReceiver_RunRejectsSymlinkedSocketDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	targetDir := filepath.Join(tmpDir, "target")
	socketDir := filepath.Join(tmpDir, "run")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	if err := os.Symlink(targetDir, socketDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	receiver := NewReceiver(ReceiverConfig{
		SocketPath: filepath.Join(socketDir, "dnstap.sock"),
		BufferSize: 1,
	}, zap.NewNop())

	err = receiver.Run(context.Background(), make(chan Frame, 1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "dnstap socket directory")
	require.Contains(t, err.Error(), "symlink")
	_, statErr := os.Stat(filepath.Join(targetDir, "dnstap.sock"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestSetSocketPermissionsRejectsSymlinkedSocketPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	realPath := filepath.Join(tmpDir, "target")
	linkPath := filepath.Join(tmpDir, "dnstap.sock")
	require.NoError(t, os.WriteFile(realPath, []byte("keep"), 0600))
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	err = setSocketPermissions(linkPath, "", "", 0660)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dnstap socket path")
	require.Contains(t, err.Error(), "symlink")
	info, statErr := os.Stat(realPath)
	require.NoError(t, statErr)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestRemoveStaleSocket_RemovesUnixSocket(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "stale.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	require.NoError(t, removeStaleSocket(socketPath))
	_, err = os.Lstat(socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRemoveStaleSocketRejectsSymlinkedSocketPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	realPath := filepath.Join(tmpDir, "target")
	linkPath := filepath.Join(tmpDir, "dnstap.sock")
	require.NoError(t, os.WriteFile(realPath, []byte("keep"), 0600))
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	err = removeStaleSocket(linkPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dnstap socket path")
	require.Contains(t, err.Error(), "symlink")
	contents, readErr := os.ReadFile(realPath)
	require.NoError(t, readErr)
	require.Equal(t, []byte("keep"), contents)
}

func TestRemoveStaleSocketRejectsSymlinkedSocketDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	targetDir := filepath.Join(tmpDir, "target")
	socketDir := filepath.Join(tmpDir, "run")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	if err := os.Symlink(targetDir, socketDir); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	targetSocket := filepath.Join(targetDir, "stale.sock")
	listener, err := net.Listen("unix", targetSocket)
	require.NoError(t, err)
	defer listener.Close()

	err = removeStaleSocket(filepath.Join(socketDir, "stale.sock"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "dnstap socket directory")
	require.Contains(t, err.Error(), "symlink")
	_, statErr := os.Lstat(targetSocket)
	require.NoError(t, statErr)
}

func TestRemoveStaleSocket_RefusesRegularFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "not-a-socket")
	require.NoError(t, os.WriteFile(socketPath, []byte("keep"), 0600))

	err = removeStaleSocket(socketPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-socket")
	contents, readErr := os.ReadFile(socketPath)
	require.NoError(t, readErr)
	require.Equal(t, []byte("keep"), contents)
}

func TestReceiver_CleanupRefusesRegularFileAtSocketPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "dtap-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "not-a-socket")
	require.NoError(t, os.WriteFile(socketPath, []byte("keep"), 0600))

	receiver := NewReceiver(ReceiverConfig{
		SocketPath: socketPath,
		BufferSize: 1,
	}, zap.NewNop())

	receiver.cleanup()

	contents, readErr := os.ReadFile(socketPath)
	require.NoError(t, readErr)
	require.Equal(t, []byte("keep"), contents)
}

func TestRemoveStaleSocket_RefusesEmptyPath(t *testing.T) {
	err := removeStaleSocket(" ")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func requireRunCanceled(t *testing.T, errCh <-chan error) {
	t.Helper()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("receiver did not stop after context cancellation")
	}
}

func waitForSocket(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()

	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-errCh:
			t.Fatalf("receiver exited before socket was ready: %v", err)
		case <-deadline:
			t.Fatalf("socket was not created: %s", socketPath)
		case <-ticker.C:
			if _, err := os.Stat(socketPath); err == nil {
				return
			}
		}
	}
}
