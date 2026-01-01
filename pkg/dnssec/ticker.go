package dnssec

import "time"

// RealTicker wraps time.Ticker to implement the Ticker interface.
type RealTicker struct {
	ticker *time.Ticker
}

// NewRealTicker creates a new RealTicker with the given interval.
func NewRealTicker(interval time.Duration) *RealTicker {
	return &RealTicker{
		ticker: time.NewTicker(interval),
	}
}

// C returns the ticker's channel.
func (t *RealTicker) C() <-chan time.Time {
	return t.ticker.C
}

// Stop stops the ticker.
func (t *RealTicker) Stop() {
	t.ticker.Stop()
}

// RealClock implements Clock using time.Now.
type RealClock struct{}

// Now returns the current time.
func (c *RealClock) Now() time.Time {
	return time.Now()
}
