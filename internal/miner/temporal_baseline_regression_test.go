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

// A response that drifts solely because of time must never be attributed to
// the candidate parameter. Both initial baseline requests can agree while the
// following pair disagrees due to an unrelated deployment/rotation event.
func TestProbeRejectsTemporalBaselineDrift(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n <= 2 {
			fmt.Fprint(w, "before-deployment")
		} else {
			fmt.Fprint(w, "after-deployment")
		}
	}))
	defer srv.Close()
	out, err := Probe(context.Background(), ProbeOptions{Target: srv.URL, Candidates: []byte("candidate\n"), Authorized: true, Timeout: time.Second})
	if err == nil {
		t.Fatalf("should fail closed when unmodified baseline drifts; findings=%+v hits=%d", out.Findings, hits.Load())
	}
	if len(out.Findings) != 0 {
		t.Fatalf("drift generated false evidence: %+v", out.Findings)
	}
	if hits.Load() < 5 {
		t.Fatalf("missing post-probe baseline: requests=%d", hits.Load())
	}
}

func TestProbeBracketedStablePositive(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Query().Has("candidate") {
			fmt.Fprint(w, "changed")
		} else {
			fmt.Fprint(w, "baseline")
		}
	}))
	defer srv.Close()
	out, err := Probe(context.Background(), ProbeOptions{Target: srv.URL, Candidates: []byte("candidate\n"), Authorized: true, Timeout: time.Second})
	if err != nil || len(out.Findings) != 1 || out.Findings[0].Name != "candidate" {
		t.Fatalf("stable positive rejected: %+v %v", out.Findings, err)
	}
	if hits.Load() != 7 {
		t.Fatalf("expected baselines, candidate repeats and bracket controls: got %d", hits.Load())
	}
}

func TestProbeBracketedStableNegative(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "baseline")
	}))
	defer srv.Close()
	out, err := Probe(context.Background(), ProbeOptions{Target: srv.URL, Candidates: []byte("candidate\n"), Authorized: true, Timeout: time.Second})
	if err != nil || len(out.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v %v", out.Findings, err)
	}
	if hits.Load() != 4 {
		t.Fatalf("unnecessary probe controls: got %d", hits.Load())
	}
}
