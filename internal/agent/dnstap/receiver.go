package dnstap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	osuser "os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	dnstaplib "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
	"go.uber.org/zap"
)

const (
	maxDNSTapFrameSize = 1024 * 1024
	defaultSocketMode  = 0o660
)

// Receiver listens on a Unix socket and receives DNSTap frames from DNS servers.
type Receiver struct {
	socketPath  string
	socketMode  os.FileMode
	socketOwner string
	socketGroup string
	logger      *zap.Logger
	listener    net.Listener
	conns       map[net.Conn]struct{}
	bufferSize  int
	mu          sync.Mutex
	closed      bool
}

// ReceiverConfig configures the DNSTap receiver.
type ReceiverConfig struct {
	SocketPath  string
	SocketMode  os.FileMode
	SocketOwner string
	SocketGroup string
	BufferSize  int // Buffer size for the frame channel
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
	if config.SocketMode == 0 {
		config.SocketMode = defaultSocketMode
	}

	return &Receiver{
		socketPath:  config.SocketPath,
		socketMode:  config.SocketMode,
		socketOwner: config.SocketOwner,
		socketGroup: config.SocketGroup,
		logger:      logger,
		bufferSize:  config.BufferSize,
	}
}

// Run starts the DNSTap receiver and sends frames to the channel.
// It blocks until the context is canceled.
func (r *Receiver) Run(ctx context.Context, frameChan chan<- Frame) error {
	if err := removeStaleSocket(r.socketPath); err != nil {
		return err
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", r.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create unix socket listener: %w", err)
	}
	if err := setSocketPermissions(r.socketPath, r.socketOwner, r.socketGroup, r.socketMode); err != nil {
		_ = listener.Close()
		_ = os.Remove(r.socketPath)
		return err
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

func removeStaleSocket(socketPath string) error {
	return removeDNSTapSocketFile(socketPath, "stale")
}

func removeDNSTapSocketFile(socketPath string, description string) error {
	if strings.TrimSpace(socketPath) == "" {
		return fmt.Errorf("dnstap socket path is empty")
	}

	info, err := os.Lstat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat dnstap socket path: %w", err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket dnstap path %q (mode %s)", socketPath, info.Mode())
	}

	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("failed to remove %s dnstap socket: %w", description, err)
	}
	return nil
}

func setSocketPermissions(socketPath, owner, group string, mode os.FileMode) error {
	uid, gid, err := resolveSocketOwnership(owner, group)
	if err != nil {
		return err
	}

	if uid != -1 || gid != -1 {
		if err := os.Chown(socketPath, uid, gid); err != nil {
			return fmt.Errorf("failed to set dnstap socket ownership: %w", err)
		}
	}

	if err := os.Chmod(socketPath, mode.Perm()); err != nil {
		return fmt.Errorf("failed to set dnstap socket permissions: %w", err)
	}
	return nil
}

func resolveSocketOwnership(owner, group string) (int, int, error) {
	uid := -1
	gid := -1

	owner = strings.TrimSpace(owner)
	if owner != "" {
		resolvedUID, err := lookupUID(owner)
		if err != nil {
			return -1, -1, err
		}
		uid = resolvedUID
	}

	group = strings.TrimSpace(group)
	if group != "" {
		resolvedGID, err := lookupGID(group)
		if err != nil {
			return -1, -1, err
		}
		gid = resolvedGID
	}

	return uid, gid, nil
}

func lookupUID(value string) (int, error) {
	if id, err := strconv.Atoi(value); err == nil {
		if id < 0 {
			return -1, fmt.Errorf("invalid negative uid for dnstap socket owner %q", value)
		}
		return id, nil
	}

	u, err := osuser.Lookup(value)
	if err != nil {
		return -1, fmt.Errorf("failed to resolve dnstap socket owner %q: %w", value, err)
	}

	id, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, fmt.Errorf("invalid uid for dnstap socket owner %q: %w", value, err)
	}
	return id, nil
}

func lookupGID(value string) (int, error) {
	if id, err := strconv.Atoi(value); err == nil {
		if id < 0 {
			return -1, fmt.Errorf("invalid negative gid for dnstap socket group %q", value)
		}
		return id, nil
	}

	g, err := osuser.LookupGroup(value)
	if err != nil {
		return -1, fmt.Errorf("failed to resolve dnstap socket group %q: %w", value, err)
	}

	id, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, fmt.Errorf("invalid gid for dnstap socket group %q: %w", value, err)
	}
	return id, nil
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

	// Explicitly remove the socket file on shutdown, but do not unlink an
	// attacker-replaced regular file at the same path.
	if err := removeDNSTapSocketFile(r.socketPath, "shutdown"); err != nil {
		r.logger.Warn("Failed to remove socket file", zap.Error(err))
	}

	r.logger.Info("DNSTap receiver stopped")
}
