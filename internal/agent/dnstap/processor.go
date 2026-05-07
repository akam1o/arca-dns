package dnstap

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Processor processes DNSTap frames through the entire pipeline:
// Receiver → Decoder → Sampler → Metrics/Logger
type Processor struct {
	receiver   *Receiver
	decoder    *Decoder
	metrics    *MetricsAggregator
	logger     *Logger
	sampler    *Sampler
	prometheus *PrometheusExporter
	zapLogger  *zap.Logger
}

// ProcessorConfig configures the DNSTap processor.
type ProcessorConfig struct {
	ReceiverConfig    ReceiverConfig
	LoggerConfig      LoggerConfig
	SamplerConfig     SamplerConfig
	PrometheusEnabled bool
}

// NewProcessor creates a new DNSTap processor.
func NewProcessor(config ProcessorConfig, logger *zap.Logger) *Processor {
	receiver := NewReceiver(config.ReceiverConfig, logger)
	decoder := NewDecoder()
	metrics := NewMetricsAggregator(logger)
	sampler := NewSampler(config.SamplerConfig)

	var logWriter *Logger
	if config.LoggerConfig.LogFile != "" {
		logWriter = NewLogger(config.LoggerConfig, sampler, logger)
	}

	var prometheus *PrometheusExporter
	if config.PrometheusEnabled {
		prometheus = NewPrometheusExporter(metrics)
	}

	return &Processor{
		receiver:   receiver,
		decoder:    decoder,
		metrics:    metrics,
		logger:     logWriter,
		sampler:    sampler,
		prometheus: prometheus,
		zapLogger:  logger,
	}
}

// Run starts the DNSTap processing pipeline.
// It blocks until the context is canceled.
func (p *Processor) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create frame channel
	frameChan := make(chan Frame, p.receiver.bufferSize)

	// Start logger if configured
	var wg sync.WaitGroup
	if p.logger != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.logger.Run(runCtx)
		}()
	}

	// Start processor goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.processFrames(runCtx, frameChan)
	}()

	// Start receiver (blocks until context is canceled)
	err := p.receiver.Run(runCtx, frameChan)
	// Ensure all goroutines stop even if receiver exits early with an error.
	cancel()

	// Wait for processor and logger to finish
	close(frameChan)
	wg.Wait()

	// Close logger
	if p.logger != nil {
		p.logger.Close()
	}

	return err
}

// processFrames processes incoming DNSTap frames.
func (p *Processor) processFrames(ctx context.Context, frameChan <-chan Frame) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame, ok := <-frameChan:
			if !ok {
				return
			}
			p.processFrame(frame)
		}
	}
}

// processFrame processes a single DNSTap frame.
func (p *Processor) processFrame(frame Frame) {
	// Decode DNSTap protobuf
	query, err := p.decoder.Decode(frame.Data)
	if err != nil {
		p.zapLogger.Warn("Failed to decode DNSTap frame", zap.Error(err))
		return
	}

	// Skip non-client messages
	if query == nil {
		return
	}

	if !query.IsResponse {
		return
	}

	// Convert transport to boolean
	isTCP := query.Transport == "tcp"

	// Convert latency from milliseconds to time.Duration
	latency := time.Duration(query.Latency * float64(time.Millisecond))

	// Update metrics
	p.metrics.RecordQuery(
		QueryTypeToString(query.QueryType),
		RCodeToString(query.ResponseCode),
		isTCP,
		latency,
	)

	// Record DNSSEC validation (both valid and invalid)
	p.metrics.RecordDNSSEC(query.DNSSECValid)

	// Log response (via sampler)
	if p.logger != nil {
		p.logger.LogQuery(query)
	}
}

// GetMetrics returns a snapshot of current metrics.
func (p *Processor) GetMetrics() MetricsSnapshot {
	return p.metrics.GetSnapshot()
}

// GetPrometheusMetrics returns Prometheus-formatted metrics.
func (p *Processor) GetPrometheusMetrics() (string, error) {
	if p.prometheus == nil {
		return "", nil
	}
	return p.prometheus.Export(), nil
}
