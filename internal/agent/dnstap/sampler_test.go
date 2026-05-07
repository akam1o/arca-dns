package dnstap

import "testing"

func TestSampler_AlwaysLogErrors(t *testing.T) {
	sampler := NewSampler(SamplerConfig{
		SampleRate:      0.000001,
		AlwaysLogErrors: true,
	})

	if !sampler.ShouldSample("A", "SERVFAIL") {
		t.Fatal("SERVFAIL should always be sampled when AlwaysLogErrors is enabled")
	}
}
