package dnstap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger writes DNSTap frames to a rotating log file.
type Logger struct {
	writer  *lumberjack.Logger
	logger  *zap.Logger
	sampler *Sampler
	mu      sync.Mutex
	queue   chan LogEntry
	closed  bool
}

// LoggerConfig configures the DNSTap logger.
type LoggerConfig struct {
	LogFile    string
	MaxSize    int  // MB
	MaxBackups int  // Number of old log files to keep
	MaxAge     int  // Days
	Compress   bool // Compress rotated files
	QueueSize  int  // Async write queue size
}

// LogEntry represents a DNS query log entry.
type LogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	QueryType    string    `json:"query_type"`
	QueryName    string    `json:"query_name"`
	ResponseCode string    `json:"response_code"`
	ClientIP     string    `json:"client_ip"`
	Transport    string    `json:"transport"` // TCP or UDP
	Latency      float64   `json:"latency_ms"`
	DNSSEC       bool      `json:"dnssec,omitempty"`
}

// NewLogger creates a new DNSTap logger with rotation.
func NewLogger(config LoggerConfig, sampler *Sampler, logger *zap.Logger) *Logger {
	if config.MaxSize <= 0 {
		config.MaxSize = 100 // Default 100MB
	}
	if config.MaxBackups <= 0 {
		config.MaxBackups = 10 // Default keep 10 files
	}
	if config.QueueSize <= 0 {
		config.QueueSize = 1000 // Default queue size
	}

	rotatingWriter := &lumberjack.Logger{
		Filename:   config.LogFile,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge,
		Compress:   config.Compress,
	}

	return &Logger{
		writer:  rotatingWriter,
		logger:  logger,
		sampler: sampler,
		queue:   make(chan LogEntry, config.QueueSize),
	}
}

// Run starts the async log writer.
func (l *Logger) Run(ctx context.Context) error {
	l.logger.Info("DNSTap logger started", zap.String("file", l.writer.Filename))

	encoder := json.NewEncoder(l.writer)
	dropped := 0

	for {
		select {
		case <-ctx.Done():
			// Drain remaining entries
			close(l.queue)
			for entry := range l.queue {
				if err := encoder.Encode(entry); err != nil {
					l.logger.Warn("Failed to write log entry", zap.Error(err))
				}
			}
			l.writer.Close()
			l.logger.Info("DNSTap logger stopped")
			return ctx.Err()

		case entry, ok := <-l.queue:
			if !ok {
				return nil
			}

			if err := encoder.Encode(entry); err != nil {
				l.logger.Warn("Failed to write log entry", zap.Error(err))
				dropped++
				if dropped%100 == 0 {
					l.logger.Warn("Log write errors", zap.Int("dropped", dropped))
				}
			}
		}
	}
}

// Log queues a log entry for async writing.
func (l *Logger) Log(entry LogEntry) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()

	// Non-blocking send
	select {
	case l.queue <- entry:
	default:
		// Queue full, drop entry
	}
}

// LogQuery logs a DNS query (with sampling).
func (l *Logger) LogQuery(query *Query) {
	if query == nil {
		return
	}

	// Convert to string representations
	qtype := QueryTypeToString(query.QueryType)
	rcode := RCodeToString(query.ResponseCode)

	// Check if we should sample this query
	if !l.sampler.ShouldSample(qtype, rcode) {
		return
	}

	// Convert client IP to string
	clientIP := ""
	if query.ClientIP != nil {
		clientIP = query.ClientIP.String()
	}

	entry := LogEntry{
		Timestamp:    query.Timestamp,
		QueryType:    qtype,
		QueryName:    query.QueryName,
		ResponseCode: rcode,
		ClientIP:     clientIP,
		Transport:    query.Transport,
		Latency:      query.Latency, // Already in milliseconds
		DNSSEC:       query.DNSSECValid,
	}

	l.Log(entry)
}

// Rotate triggers log rotation manually.
func (l *Logger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.writer == nil {
		return fmt.Errorf("logger not initialized")
	}

	return l.writer.Rotate()
}

// Close marks the logger as closed (actual cleanup happens in Run).
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true

	// Don't close channel here - Run() will handle it on ctx.Done()

	return nil
}

// GetLogFile returns the current log file path.
func (l *Logger) GetLogFile() string {
	return l.writer.Filename
}

// GetStats returns logger statistics.
func (l *Logger) GetStats() map[string]interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Get file info
	var fileSize int64
	if info, err := os.Stat(l.writer.Filename); err == nil {
		fileSize = info.Size()
	}

	return map[string]interface{}{
		"log_file":     l.writer.Filename,
		"file_size_mb": float64(fileSize) / (1024 * 1024),
		"queue_len":    len(l.queue),
		"queue_cap":    cap(l.queue),
	}
}
