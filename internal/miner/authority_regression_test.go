package miner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Inputs with bracketed non-IPv6 authorities are not valid supported HTTP URLs.
// A generic URL parser can nevertheless return a non-empty Hostname, so both
// passive evidence and the loopback-only probe must reject before processing.
func TestRejectsBracketedNonIPv6Authority202(t *testing.T) {
	negativeInventory := []string{
		"http://[example.test]/?x=1",
		"http://[127.0.0.1]/?x=1",
		"http://[v1.fe80]/?x=1",
	}
	for _, raw := range negativeInventory {
		t.Run("inventory_"+raw, func(t *testing.T) {
			input, _ := json.Marshal(requestSet{Requests: []requestRecord{{Method: "GET", URL: raw}}})
			res, err := Inventory(input)
			if err == nil {
				t.Fatalf("invalid authority accepted as evidence: %+v", res.Findings)
			}
			if strings.Contains(err.Error(), "example.test") {
				t.Fatal("input URL leaked in diagnostic")
			}
		})
	}
	for _, raw := range []string{
		"http://[127.0.0.1]:1234/", "http://[127.1.2.3]:1234/",
		"http://[::ffff:127.0.0.1]:1234/", // mapped address is separately refused
	} {
		t.Run("probe_"+raw, func(t *testing.T) {
			if _, err := validateLoopbackURL(raw); err == nil {
				t.Fatal("invalid loopback authority accepted")
			}
		})
	}
	for _, raw := range []string{
		"http://127.0.0.1:8080/", "http://127.2.3.4/", "http://[::1]:8080/",
		"http://[0:0:0:0:0:0:0:1]/", "https://example.test/?a=1",
	} {
		t.Run("positive_"+raw, func(t *testing.T) {
			if strings.HasPrefix(raw, "http://127.") || strings.HasPrefix(raw, "http://[") {
				if _, err := validateLoopbackURL(raw); err != nil {
					t.Fatalf("valid loopback rejected: %v", err)
				}
			}
			input, _ := json.Marshal(requestSet{Requests: []requestRecord{{Method: "GET", URL: raw}}})
			if _, err := Inventory(input); err != nil {
				t.Fatalf("valid inventory URL rejected: %v", err)
			}
		})
	}
}

// A malformed-but-loopback-routing authority must be refused before any HTTP
// request, not merely treated as harmless after the socket has been opened.
func TestBracketedIPv4NeverReachesSyntheticServer202(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("constant"))
	}))
	defer server.Close()
	target := strings.Replace(server.URL, "127.0.0.1", "[127.0.0.1]", 1)
	if target == server.URL {
		t.Skip("httptest did not return literal IPv4 loopback")
	}
	_, err := Probe(context.Background(), ProbeOptions{Target: target, Authorized: true, Candidates: []byte("probe_key\n"), Timeout: 500 * time.Millisecond})
	if err == nil {
		t.Fatal("accepted malformed target")
	}
	if count := hits.Load(); count != 0 {
		t.Fatalf("sent %d unauthorized observations to malformed URL", count)
	}
}
