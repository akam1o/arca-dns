package dnstap

import (
	"context"
	"net"
	"os"
	"path/filepath"
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
