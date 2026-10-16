package miner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A query-insensitive endpoint has an unrelated two-request transient that
// precisely overlaps the first two candidate probes, then returns to normal.
func TestProbeRejectsUnrelatedTwoRequestBurst152(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 3 || n == 4 {
			fmt.Fprint(w, "transient")
		} else {
			fmt.Fprint(w, "baseline")
		}
	}))
	defer srv.Close()
	out, err := Probe(context.Background(), ProbeOptions{Target: srv.URL, Candidates: []byte("synthetic_flag\n"), Authorized: true, Timeout: time.Second})
	if err == nil || len(out.Findings) != 0 {
		t.Fatalf("query ignored but false inferred: findings=%v err=%v", out.Findings, err)
	}
	if got := hits.Load(); got != 6 {
		t.Fatalf("want six bounded probes; got %d", got)
	}
}
