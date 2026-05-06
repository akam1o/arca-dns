package dnstap

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

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
