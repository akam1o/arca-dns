package dnstap

import (
	"math/rand"
	"sync"
)

// Sampler implements query sampling logic.
type Sampler struct {
	sampleRate      float64 // Base sample rate (0.0-1.0)
	alwaysLogErrors bool    // Always log error responses
	stratifyByType  bool    // Balance sampling across query types
	mu              sync.RWMutex
	typeCounts      map[string]int64 // Track samples per type
	totalSamples    int64
	alwaysLogRCodes map[string]bool // RCodes to always log
}

// SamplerConfig configures the sampler.
type SamplerConfig struct {
	SampleRate      float64  // Base sample rate (0.001 = 1/1000)
	AlwaysLogErrors bool     // Always log SERVFAIL, REFUSED, etc.
	StratifyByType  bool     // Balance sampling across query types
	AlwaysLogRCodes []string // RCodes to always log (e.g., SERVFAIL, REFUSED)
}

// NewSampler creates a new query sampler.
func NewSampler(config SamplerConfig) *Sampler {
	if config.SampleRate <= 0 {
		config.SampleRate = 0.001 // Default 1/1000
	}
	if config.SampleRate > 1.0 {
		config.SampleRate = 1.0
	}

	// Default: always log errors
	alwaysLogRCodes := make(map[string]bool)
	if config.AlwaysLogErrors {
		alwaysLogRCodes["SERVFAIL"] = true
		alwaysLogRCodes["REFUSED"] = true
		alwaysLogRCodes["FORMERR"] = true
		alwaysLogRCodes["NOTIMP"] = true
		alwaysLogRCodes["BADVERS"] = true
	}

	// Add user-specified rcodes
	for _, rcode := range config.AlwaysLogRCodes {
		alwaysLogRCodes[rcode] = true
	}

	return &Sampler{
		sampleRate:      config.SampleRate,
		alwaysLogErrors: config.AlwaysLogErrors,
		stratifyByType:  config.StratifyByType,
		typeCounts:      make(map[string]int64),
		alwaysLogRCodes: alwaysLogRCodes,
	}
}

// ShouldSample determines if a query should be sampled/logged.
func (s *Sampler) ShouldSample(qtype, rcode string) bool {
	// Always log if rcode is in the always-log list
	if s.alwaysLogRCodes[rcode] {
		return true
	}

	// Apply base sampling
	if rand.Float64() > s.sampleRate {
		return false
	}

	// If stratification is enabled, balance across query types
	if s.stratifyByType {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.typeCounts[qtype]++
		s.totalSamples++

		// Simple stratification: if this type is overrepresented, reduce sampling
		if s.totalSamples > 1000 {
			typeRatio := float64(s.typeCounts[qtype]) / float64(s.totalSamples)
			expectedRatio := 1.0 / float64(len(s.typeCounts))

			// If this type is more than 3x expected, skip
			if typeRatio > expectedRatio*3 {
				return false
			}
		}
	}

	return true
}

// GetStats returns sampler statistics.
func (s *Sampler) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	typeCounts := make(map[string]int64)
	for qtype, count := range s.typeCounts {
		typeCounts[qtype] = count
	}

	return map[string]interface{}{
		"sample_rate":     s.sampleRate,
		"total_samples":   s.totalSamples,
		"samples_by_type": typeCounts,
	}
}

// Reset resets sampling statistics.
func (s *Sampler) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.typeCounts = make(map[string]int64)
	s.totalSamples = 0
}
