package miner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Timeout bounds are part of the documented fail-closed validation contract.
// Values below 1ms must be rejected before any network I/O, rather than
// reaching http.Client and failing nondeterministically with a request error.
func TestProbeTimeoutBoundsRejectBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	tests := []struct {
		name  string
		value time.Duration
	}{
		{"zero", 0},
		{"negative", -time.Millisecond},
		{"one_nanosecond", time.Nanosecond},
		{"submillisecond", 500 * time.Microsecond},
		{"one_ns_below_minimum", time.Millisecond - time.Nanosecond},
		{"one_ns_above_maximum", 10*time.Second + time.Nanosecond},
		{"too_large", 11 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := requests.Load()
			_, err := Probe(context.Background(), ProbeOptions{
				Target: server.URL, Candidates: []byte("test\n"), Authorized: true, Timeout: tc.value,
			})
			if err == nil || err.Error() != "timeout must be within 1ms to 10s" {
				t.Fatalf("timeout %v: got error %v, want bounded-timeout validation error", tc.value, err)
			}
			if got := requests.Load(); got != before {
				t.Fatalf("invalid timeout emitted %d requests", got-before)
			}
		})
	}
}

func TestProbeTimeoutValidationAllowedBounds(t *testing.T) {
	for _, d := range []time.Duration{time.Millisecond, time.Millisecond + time.Nanosecond, time.Second, 10 * time.Second} {
		if err := validateProbeTimeout(d); err != nil {
			t.Fatalf("valid timeout %v rejected: %v", d, err)
		}
	}
}
