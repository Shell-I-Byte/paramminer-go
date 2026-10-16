package miner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInventoryGoodAndRedacted(t *testing.T) {
	input := []byte(`{"requests":[{"method":"GET","url":"https://alice:pass@example.invalid/api?secret=private&lang=nl"}]}`)
	// Credentials within source input are forbidden to prevent misleading provenance of sensitive URLs.
	if _, err := Inventory(input); err == nil {
		t.Fatal("userinfo must reject")
	}
	input = []byte(`{"requests":[{"method":"GET","url":"https://example.invalid/api?secret=private&lang=nl&lang=de"},{"method":"POST","url":"http://[::1]:8080/x?lang=it"}]}`)
	r, err := Inventory(input)
	if err != nil {
		t.Fatal(err)
	}
	if r.Schema != Schema || r.Mode != "inventory" || len(r.Findings) != 2 {
		t.Fatalf("bad result: %+v", r)
	}
	if r.Findings[0].Name != "lang" || r.Findings[0].Count != 2 || r.Findings[0].Status != "observed" {
		t.Fatal(r.Findings)
	}
	b, _ := json.Marshal(r)
	if bytes.Contains(b, []byte("private")) || bytes.Contains(b, []byte("example.invalid")) || bytes.Contains(b, []byte("/api")) {
		t.Fatal("sensitive input leaked")
	}
	second, e := Inventory(input)
	if e != nil {
		t.Fatal(e)
	}
	b2, _ := json.Marshal(second)
	if !bytes.Equal(b, b2) {
		t.Fatal("non-deterministic JSON")
	}
}
func TestInventoryRejections(t *testing.T) {
	cases := map[string]string{
		"not json": `{`, "unknown field": `{"requests":[],"secret":1}`,
		"duplicate root":     `{"requests":[],"requests":[]}`,
		"duplicate nested":   `{"requests":[{"method":"GET","method":"POST","url":"http://localhost"}]}`,
		"trailing":           `{"requests":[]} {"requests":[]}`,
		"invalid method":     `{"requests":[{"method":"TRACE","url":"https://example.invalid/"}]}`,
		"malformed encoding": `{"requests":[{"method":"GET","url":"https://example.invalid/?bad=%GG"}]}`,
		"unsupported name":   `{"requests":[{"method":"GET","url":"https://example.invalid/?bad%0A=x"}]}`,
		"userinfo":           `{"requests":[{"method":"GET","url":"https://user:pwd@example.invalid/"}]}`,
		"scheme":             `{"requests":[{"method":"GET","url":"file:///etc/passwd?x=1"}]}`,
		"relative":           `{"requests":[{"method":"GET","url":"/api?a=b"}]}`,
		"empty":              `{"requests":[{"method":"GET","url":""}]}`,
		"extra field":        `{"requests":[{"method":"GET","url":"http://localhost/","headers":{"Cookie":"a"}}]}`,
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Inventory([]byte(value)); err == nil {
				t.Fatalf("accepted %s", value)
			}
		})
	}
	many := make([]requestRecord, 1001)
	for i := range many {
		many[i] = requestRecord{URL: "http://127.0.0.1/", Method: "GET"}
	}
	body, _ := json.Marshal(requestSet{Requests: many})
	if _, err := Inventory(body); err == nil {
		t.Fatal("accepted 1001 records")
	}
	if _, err := Inventory(bytes.Repeat([]byte("x"), maxInput+1)); err == nil {
		t.Fatal("accepted oversized input")
	}
}
func TestCandidates(t *testing.T) {
	names, err := candidateNames([]byte("# comment\nalpha\nbeta\nalpha\nZeta\n"))
	if err != nil || strings.Join(names, ",") != "Zeta,alpha,beta" {
		t.Fatalf("%v: %v", names, err)
	}
	for _, s := range []string{"", "#only\n", "hello=world\n", "bad\x1bvalue\n", "💥\n", strings.Repeat("x", 65), func() string {
		var a strings.Builder
		for i := 0; i < 66; i++ {
			fmt.Fprintf(&a, "q%d\n", i)
		}
		return a.String()
	}()} {
		if _, err := candidateNames([]byte(s)); err == nil {
			t.Fatalf("accepted invalid candidate input %q", s[:min(len(s), 60)])
		}
	}
	if _, err := candidateNames(bytes.Repeat([]byte("x"), 64<<10+1)); err == nil {
		t.Fatal("oversize")
	}
}
func TestLoopbackValidation(t *testing.T) {
	good := []string{"http://127.0.0.1/", "http://127.0.0.2:4321/a", "http://[::1]:8080/x"}
	for _, s := range good {
		if _, e := validateLoopbackURL(s); e != nil {
			t.Errorf("valid %s: %v", s, e)
		}
	}
	bad := []string{"https://127.0.0.1/", "http://localhost/", "http://127.0.0.1.evil.invalid/", "http://8.8.8.8/", "http://[::2]/", "file:///x", "http://user:pwd@127.0.0.1/", "http://127.0.0.1/?secret=one", "http://127.0.0.1/path#frag", "http://127.0.0.1:0/", "http://127.0.0.1:65536/", "http://127.0.0.1:abc/", "http://127.0.0.1:80/path\nInjected", "http://0177.0.0.1/", "http://2130706433/"}
	for _, s := range bad {
		if _, e := validateLoopbackURL(s); e == nil {
			t.Errorf("unsafe URL accepted: %q", s)
		}
	}
}
func TestProbeDifferentialAndPrivacy(t *testing.T) {
	var cookieSeen atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			cookieSeen.Store(true)
		}
		http.SetCookie(w, &http.Cookie{Name: "secret", Value: "do_not_output"})
		if r.URL.Query().Has("magic") {
			fmt.Fprint(w, "different")
		} else {
			fmt.Fprint(w, "baseline")
		}
	}))
	defer srv.Close()
	opt := ProbeOptions{Target: srv.URL + "/path", Candidates: []byte("magic\nnoise\n"), Authorized: true, Timeout: time.Second}
	r, err := Probe(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Name != "magic" || r.Findings[0].Status != "inferred" {
		t.Fatalf("unexpected findings: %+v", r.Findings)
	}
	serialized, _ := json.Marshal(r)
	if bytes.Contains(serialized, []byte("do_not_output")) || bytes.Contains(serialized, []byte("/path")) || bytes.Contains(serialized, []byte("127.0.0.1")) {
		t.Fatal("privacy leak")
	}
	if cookieSeen.Load() {
		t.Fatal("cookie sent")
	}
	second, err := Probe(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := json.Marshal(second)
	if !bytes.Equal(serialized, s2) {
		t.Fatal("probe output nondeterministic")
	}
}
func TestProbeNoRedirectAndNoProxy(t *testing.T) {
	var externalCalls atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { externalCalls.Add(1); w.WriteHeader(200) }))
	defer outside.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", outside.URL)
		w.WriteHeader(302)
	}))
	defer local.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	r, err := Probe(context.Background(), ProbeOptions{Target: local.URL, Candidates: []byte("x\n"), Authorized: true, Timeout: time.Second})
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("redirect/proxy: %v %+v", err, r.Findings)
	}
	if externalCalls.Load() != 0 {
		t.Fatal("followed redirect")
	}
}
func TestProbeUnstableOversizeTimeoutCancellation(t *testing.T) {
	var n atomic.Int32
	unstable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, n.Add(1)) }))
	defer unstable.Close()
	if _, err := Probe(context.Background(), ProbeOptions{Target: unstable.URL, Candidates: []byte("x"), Authorized: true, Timeout: time.Second}); err == nil {
		t.Fatal("unstable baseline accepted")
	}
	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(bytes.Repeat([]byte("x"), maxResponse+5)) }))
	defer large.Close()
	if _, err := Probe(context.Background(), ProbeOptions{Target: large.URL, Candidates: []byte("x"), Authorized: true, Timeout: time.Second}); err == nil {
		t.Fatal("oversize accepted")
	}
	wait := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(100 * time.Millisecond):
		case <-r.Context().Done():
		}
		fmt.Fprint(w, "ok")
	}))
	defer wait.Close()
	if _, err := Probe(context.Background(), ProbeOptions{Target: wait.URL, Candidates: []byte("x"), Authorized: true, Timeout: time.Millisecond}); err == nil {
		t.Fatal("timeout accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Probe(ctx, ProbeOptions{Target: wait.URL, Candidates: []byte("x"), Authorized: true, Timeout: time.Second}); err == nil {
		t.Fatal("cancelled context accepted")
	}
}
func TestProbeRequiresConsentAndRejectsExternal(t *testing.T) {
	for _, o := range []ProbeOptions{{Target: "http://127.0.0.1:1", Candidates: []byte("x"), Timeout: time.Second}, {Target: "http://93.184.216.34/", Candidates: []byte("x"), Authorized: true, Timeout: time.Second}, {Target: "http://localhost:1", Candidates: []byte("x"), Authorized: true, Timeout: time.Second}, {Target: "http://127.0.0.1:1", Candidates: []byte("x"), Authorized: true, Timeout: 11 * time.Second}, {Target: "http://127.0.0.1:1", Candidates: []byte("bad=1"), Authorized: true, Timeout: time.Second}} {
		if _, err := Probe(context.Background(), o); err == nil {
			t.Fatalf("unsafe probe permitted: %+v", o)
		}
	}
}
func TestProbeIPv6WhenAvailable(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 unavailable: " + err.Error())
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("v6") {
			w.Write([]byte("different"))
		} else {
			w.Write([]byte("base"))
		}
	}))
	srv.Listener = l
	srv.Start()
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Probe(context.Background(), ProbeOptions{Target: u.String(), Candidates: []byte("v6"), Authorized: true, Timeout: time.Second})
	if err != nil || len(r.Findings) != 1 {
		t.Fatalf("IPv6: %v %+v", err, r.Findings)
	}
}
func TestConcurrentInventoryDeterminism(t *testing.T) {
	data := []byte(`{"requests":[{"method":"GET","url":"http://127.0.0.1/?z=1&a=2"}]}`)
	var wg sync.WaitGroup
	errCh := make(chan error, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := Inventory(data)
			if e != nil {
				errCh <- e
				return
			}
			b, _ := json.Marshal(r)
			if !bytes.Contains(b, []byte(`"name":"a"`)) {
				errCh <- fmt.Errorf("missing name")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
}
func FuzzInventory(f *testing.F) {
	f.Add([]byte(`{"requests":[]}`))
	f.Add([]byte(`{"requests":[{"method":"GET","url":"https://example.invalid/?a=1"}]}`))
	f.Add([]byte(`{"requests":[{"method":"GET","url":"https://example.invalid/?x=%ZZ"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 40000 {
			return
		}
		_, _ = Inventory(b)
	})
}

func TestInventoryRejectsInvalidUTF8(t *testing.T) {
	data := append([]byte(`{"requests":[{"method":"GET","url":"https://example.invalid/?key=`), 0xff)
	data = append(data, []byte(`"}]}`)...)
	if _, err := Inventory(data); err == nil {
		t.Fatal("invalid UTF-8 input must fail closed across Go JSON versions")
	}
}
