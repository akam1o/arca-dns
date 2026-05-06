package dnstap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	dnstaplib "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"go.uber.org/zap"
)

const maxDNSTapFrameSize = 1024 * 1024

// Receiver listens on a Unix socket and receives DNSTap frames from DNS servers.
type Receiver struct {
	socketPath string
	logger     *zap.Logger
	listener   net.Listener
	conns      map[net.Conn]struct{}
	bufferSize int
	mu         sync.Mutex
	closed     bool
}

// ReceiverConfig configures the DNSTap receiver.
type ReceiverConfig struct {
	SocketPath string
	BufferSize int // Buffer size for the frame channel
}

// Frame represents a DNSTap frame.
type Frame struct {
	Data      []byte
	Timestamp time.Time
}

// NewReceiver creates a new DNSTap receiver.
func NewReceiver(config ReceiverConfig, logger *zap.Logger) *Receiver {
	if config.BufferSize <= 0 {
		config.BufferSize = 1000 // Default buffer size
	}

	return &Receiver{
		socketPath: config.SocketPath,
		logger:     logger,
		bufferSize: config.BufferSize,
	}
}

// Run starts the DNSTap receiver and sends frames to the channel.
// It blocks until the context is canceled.
func (r *Receiver) Run(ctx context.Context, frameChan chan<- Frame) error {
	// Remove stale socket file if it exists
	if err := os.Remove(r.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", r.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create unix socket listener: %w", err)
	}

	r.mu.Lock()
	r.listener = listener
	r.conns = make(map[net.Conn]struct{})
	r.closed = false
	r.mu.Unlock()
	defer r.cleanup()

	r.logger.Info("DNSTap receiver started", zap.String("socket", r.socketPath))

	stopCleanupWatcher := make(chan struct{})
	defer close(stopCleanupWatcher)
	go func() {
		select {
		case <-ctx.Done():
			r.cleanup()
		case <-stopCleanupWatcher:
		}
	}()

	// Accept connections in a goroutine
	connChan := make(chan net.Conn)
	errChan := make(chan error, 1)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case errChan <- err:
				default:
				}
				return
			}
			select {
			case connChan <- conn:
			case <-ctx.Done():
				conn.Close()
				return
			}
		}
	}()

	// Process connections
	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			r.cleanup()
			wg.Wait()
			return ctx.Err()

		case err := <-errChan:
			r.mu.Lock()
			if r.closed {
				r.mu.Unlock()
				wg.Wait()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return nil
			}
			r.mu.Unlock()
			r.logger.Error("Accept error", zap.Error(err))
			wg.Wait()
			return err

		case conn := <-connChan:
			r.addConn(conn)
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer r.removeConn(c)
				defer c.Close()
				r.handleConnection(ctx, c, frameChan)
			}(conn)
		}
	}
}

// handleConnection reads DNSTap frames from a connection.
func (r *Receiver) handleConnection(ctx context.Context, conn net.Conn, frameChan chan<- Frame) {
	r.logger.Debug("New DNSTap connection", zap.String("remote", conn.RemoteAddr().String()))

	reader, err := dnstaplib.NewReader(conn, &dnstaplib.ReaderOptions{
		Bidirectional: true,
	})
	if err != nil {
		if ctx.Err() == nil {
			r.logger.Warn("Failed to establish DNSTap Frame Streams session", zap.Error(err))
		}
		return
	}

	buf := make([]byte, maxDNSTapFrameSize)
	dropped := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := reader.ReadFrame(buf)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				r.logger.Debug("DNSTap connection closed")
			case errors.Is(err, framestream.ErrDataFrameTooLarge):
				r.logger.Warn("DNSTap frame too large, dropping frame")
				continue
			default:
				r.logger.Warn("Failed to read DNSTap frame", zap.Error(err))
			}
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		// Send frame to channel (non-blocking)
		frame := Frame{
			Data:      data,
			Timestamp: time.Now(),
		}

		select {
		case frameChan <- frame:
		default:
			// Channel full, drop frame
			dropped++
			if dropped%1000 == 0 {
				r.logger.Warn("DNSTap buffer full, dropping frames",
					zap.Int("dropped", dropped))
			}
		}
	}
}

func (r *Receiver) addConn(conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		_ = conn.Close()
		return
	}
	if r.conns == nil {
		r.conns = make(map[net.Conn]struct{})
	}
	r.conns[conn] = struct{}{}
}

func (r *Receiver) removeConn(conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.conns, conn)
}

// cleanup closes the listener and removes the socket file.
func (r *Receiver) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}
	r.closed = true

	if r.listener != nil {
		r.listener.Close()
	}
	for conn := range r.conns {
		_ = conn.Close()
		delete(r.conns, conn)
	}

	// Explicitly remove socket file on shutdown
	if err := os.Remove(r.socketPath); err != nil && !os.IsNotExist(err) {
		r.logger.Warn("Failed to remove socket file", zap.Error(err))
	}

	r.logger.Info("DNSTap receiver stopped")
}
