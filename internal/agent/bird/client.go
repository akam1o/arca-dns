package bird

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Client provides an interface for communicating with BIRD via control socket.
type Client interface {
	// Exec executes a command and returns the response.
	Exec(ctx context.Context, cmd string) (*Response, error)
	// Close closes the connection.
	Close() error
}

// ClientConfig configures the BIRD client.
type ClientConfig struct {
	SocketPath string
	Timeout    time.Duration
}

// client implements the Client interface.
type client struct {
	socketPath string
	timeout    time.Duration
	conn       net.Conn
	mu         sync.Mutex
	connected  bool
}

// NewClient creates a new BIRD control socket client.
func NewClient(config ClientConfig) (Client, error) {
	c := &client{
		socketPath: config.SocketPath,
		timeout:    config.Timeout,
	}

	if c.timeout == 0 {
		c.timeout = 5 * time.Second
	}

	// Connect immediately
	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("initial connection failed: %w", err)
	}

	return c, nil
}

// connect establishes a connection to BIRD control socket.
func (c *client) connect() error {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return fmt.Errorf("dial unix socket: %w", err)
	}

	// Read greeting
	if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		conn.Close()
		return fmt.Errorf("set read deadline: %w", err)
	}

	greeting, err := ParseGreeting(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("parse greeting: %w", err)
	}

	// Reset deadline
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.Close()
		return fmt.Errorf("reset read deadline: %w", err)
	}

	c.conn = conn
	c.connected = true

	// Log greeting (in production, use logger)
	_ = greeting

	return nil
}

// reconnect attempts to reconnect to BIRD.
func (c *client) reconnect() error {
	if c.conn != nil {
		c.conn.Close()
		c.connected = false
	}
	return c.connect()
}

// Exec executes a command and returns the response.
// This method is thread-safe (uses mutex for serialization).
func (c *client) Exec(ctx context.Context, cmd string) (*Response, error) {
	if err := validateCommand(cmd); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if connection is alive, reconnect if needed
	if !c.connected {
		if err := c.reconnect(); err != nil {
			return nil, fmt.Errorf("reconnect failed: %w", err)
		}
	}

	// Set deadline from context
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}

	if err := c.conn.SetDeadline(deadline); err != nil {
		c.connected = false
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Send command (must end with newline)
	cmdLine := cmd + "\n"
	if err := writeFull(c.conn, []byte(cmdLine)); err != nil {
		c.connected = false
		return nil, fmt.Errorf("write command: %w", err)
	}

	// Read response
	resp, err := ParseResponse(c.conn)
	if err != nil {
		c.connected = false
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// Reset deadline
	if err := c.conn.SetDeadline(time.Time{}); err != nil {
		c.connected = false
		return nil, fmt.Errorf("reset deadline: %w", err)
	}

	return resp, nil
}

func validateCommand(cmd string) error {
	if strings.ContainsAny(cmd, "\r\n") {
		return fmt.Errorf("invalid BIRD command: contains line break")
	}
	return nil
}

// Close closes the connection.
func (c *client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.connected = false
		return c.conn.Close()
	}
	return nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
