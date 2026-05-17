package bird

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type partialWriteConn struct {
	read     *strings.Reader
	written  bytes.Buffer
	maxWrite int
}

func newPartialWriteConn(response string, maxWrite int) *partialWriteConn {
	return &partialWriteConn{
		read:     strings.NewReader(response),
		maxWrite: maxWrite,
	}
}

func (c *partialWriteConn) Read(p []byte) (int, error) {
	return c.read.Read(p)
}

func (c *partialWriteConn) Write(p []byte) (int, error) {
	if c.maxWrite <= 0 {
		return 0, nil
	}
	if len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.written.Write(p)
}

func (c *partialWriteConn) Close() error {
	return nil
}

func (c *partialWriteConn) LocalAddr() net.Addr {
	return nil
}

func (c *partialWriteConn) RemoteAddr() net.Addr {
	return nil
}

func (c *partialWriteConn) SetDeadline(time.Time) error {
	return nil
}

func (c *partialWriteConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *partialWriteConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestClientExecWritesFullCommandAcrossPartialWrites(t *testing.T) {
	conn := newPartialWriteConn("0000\n", 3)
	client := &client{
		timeout:   time.Second,
		conn:      conn,
		connected: true,
	}

	resp, err := client.Exec(context.Background(), "disable anycast_1")
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if resp.Code != 0 {
		t.Fatalf("response code=%d, want 0", resp.Code)
	}

	if got, want := conn.written.String(), "disable anycast_1\n"; got != want {
		t.Fatalf("written command mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestClientExecRejectsZeroByteCommandWrite(t *testing.T) {
	conn := newPartialWriteConn("0000\n", 0)
	client := &client{
		timeout:   time.Second,
		conn:      conn,
		connected: true,
	}

	_, err := client.Exec(context.Background(), "disable anycast_1")
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected ErrShortWrite, got %v", err)
	}
	if client.connected {
		t.Fatalf("client should be marked disconnected after write failure")
	}
}
