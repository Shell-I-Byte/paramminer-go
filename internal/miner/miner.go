// Package miner implements passive parameter inventory and strictly loopback-only
// response-differential probes. It must never contact non-loopback addresses.
package miner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const Schema = "paramminer.result/v1"
const maxInput = 8 << 20
const maxCandidates = 64

// Bound raw query fields prior to parsing; Go versions/configurations may
// enforce different ParseQuery resource limits.
const maxQueryParameters = 10000
const maxResponse = 1 << 20

var validName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// Result never contains observed parameter values or response bodies.
type Result struct {
	Schema      string    `json:"schema"`
	Version     string    `json:"version"`
	Mode        string    `json:"mode"`
	InputSHA256 string    `json:"input_sha256"`
	Findings    []Finding `json:"findings"`
	Notes       []string  `json:"notes"`
}
type Finding struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Count    int    `json:"count,omitempty"`
	Evidence string `json:"evidence"`
}

type requestRecord struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}
type requestSet struct {
	Requests []requestRecord `json:"requests"`
}

func base(mode string, input []byte) Result {
	h := sha256.Sum256(input)
	return Result{Schema: Schema, Version: "v0.1.0-rc11", Mode: mode, InputSHA256: hex.EncodeToString(h[:]), Findings: []Finding{}, Notes: []string{}}
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, errors.New("input read failed")
	}
	if int64(len(data)) > max {
		return nil, errors.New("input limit exceeded")
	}
	return data, nil
}

func readFile(path string, max int64) ([]byte, error) {
	if path == "-" {
		return readBounded(os.Stdin, max)
	}
	// Reject non-regular files BEFORE opening them: os.Open on a FIFO can
	// block indefinitely when no writer exists. The opened descriptor is
	// checked again to guard against ordinary path replacement. Unix opens
	// with O_NONBLOCK to avoid a symlink-swap-to-FIFO blocking at open time.
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("cannot inspect input")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	f, err := openInputNoBlock(path)
	if err != nil {
		return nil, errors.New("cannot open input")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	return readBounded(f, max)
}

// validateInventoryShape enforces exact JSON member names and the presence of
// a non-null request array before decoding into Go structs. encoding/json v1
// otherwise also accepts case-insensitive aliases, even with
// DisallowUnknownFields, and later aliases can overwrite earlier values.
// Input is already capped at 8 MiB; all errors are value-free diagnostics.
func validateInventoryShape(data []byte) error {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return errors.New("invalid JSON input")
	}
	if len(envelope) != 1 {
		return errors.New("expected requests array")
	}
	raw, ok := envelope["requests"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("expected requests array")
	}
	var requests []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &requests); err != nil || requests == nil {
		return errors.New("invalid requests array")
	}
	for _, record := range requests {
		if record == nil {
			return errors.New("invalid request record")
		}
		for key := range record {
			if key != "method" && key != "url" {
				return errors.New("unexpected request field")
			}
		}
	}
	return nil
}

// parseStrict rejects unknown fields, duplicate JSON object keys, trailing bytes,
// case-insensitive aliases, and absent/null request collections.
func parseStrict(data []byte, value any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	if err := validateInventoryShape(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return errors.New("invalid JSON input")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON input")
	}
	return nil
}

// Streaming token walk catches duplicate keys even in nested request objects.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type state struct {
		kind      json.Delim
		keys      map[string]bool
		expectKey bool
	}
	stack := []state{}
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("invalid JSON input")
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, state{kind: '{', keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, state{kind: '['})
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("invalid JSON structure")
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
					stack[len(stack)-1].expectKey = true
				}
			}
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
			top := &stack[len(stack)-1]
			if top.expectKey {
				key, ok := token.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if top.keys[key] {
					return errors.New("duplicate JSON key")
				}
				top.keys[key] = true
				top.expectKey = false
			} else {
				top.expectKey = true
			}
		}
	}
	return nil
}

// validHTTPAuthority rejects bracketed hostnames that are not IPv6 literals.
// url.Parse is deliberately permissive for some bracketed authorities, while
// RFC 3986 reserves brackets for IP-literals. IPvFuture is unsupported here.
// Do not use URL.Hostname alone as proof that an authority is well-formed.
func validHTTPAuthority(u *url.URL) bool {
	host := u.Host
	if strings.HasPrefix(host, "[") {
		closing := strings.IndexByte(host, ']')
		if closing <= 1 || strings.ContainsAny(host[1:closing], "[]") {
			return false
		}
		remainder := host[closing+1:]
		if remainder != "" && !strings.HasPrefix(remainder, ":") {
			return false
		}
		parsed, err := netip.ParseAddr(u.Hostname())
		return err == nil && parsed.Is6()
	}
	return !strings.ContainsAny(host, "[]")
}

func Inventory(data []byte) (Result, error) {
	result := base("inventory", data)
	if !utf8.Valid(data) {
		return result, errors.New("invalid UTF-8 input")
	}
	if len(data) > maxInput {
		return result, errors.New("input limit exceeded")
	}
	var input requestSet
	if err := parseStrict(data, &input); err != nil {
		return result, err
	}
	if len(input.Requests) > 1000 {
		return result, errors.New("too many request records")
	}
	counts := map[string]int{}
	for _, item := range input.Requests {
		if item.URL == "" {
			return result, errors.New("missing request URL")
		}
		switch item.Method {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		default:
			return result, errors.New("unsupported method")
		}
		u, err := url.Parse(item.URL)
		if err != nil || u == nil || !u.IsAbs() || u.Opaque != "" || u.User != nil || u.Hostname() == "" || !validHTTPAuthority(u) || (u.Scheme != "https" && u.Scheme != "http") {
			return result, errors.New("invalid request URL")
		}
		// Cap query-pair work independent of Go toolchain/GODEBUG behavior.
		// Count the raw separators, not encoded %26, before allocating values.
		if u.RawQuery != "" && strings.Count(u.RawQuery, "&")+1 > maxQueryParameters {
			return result, errors.New("too many query parameters")
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return result, errors.New("malformed query encoding")
		}
		for key := range q {
			if !validName.MatchString(key) {
				return result, errors.New("unsupported parameter name")
			}
			counts[key]++
		}
	}
	names := make([]string, 0, len(counts))
	for k := range counts {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		result.Findings = append(result.Findings, Finding{Name: name, Status: "observed", Count: counts[name], Evidence: "present in supplied offline request records"})
	}
	result.Notes = []string{"Values, URL paths, domains, headers and request bodies are excluded from output.", "Observed means present in the provided dataset, not verified by a target."}
	return result, nil
}

// ReadInventory reads only local files, with strict size bounds.
func ReadInventory(path string) (Result, error) {
	data, err := readFile(path, maxInput)
	if err != nil {
		return Result{}, err
	}
	return Inventory(data)
}

func candidateNames(data []byte) ([]string, error) {
	if len(data) > 64<<10 {
		return nil, errors.New("candidate file limit exceeded")
	}
	lines := strings.Split(string(data), "\n")
	names := []string{}
	seen := map[string]bool{}
	for _, line := range lines {
		word := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if !validName.MatchString(word) {
			return nil, errors.New("invalid candidate name")
		}
		if !seen[word] {
			names = append(names, word)
			seen[word] = true
		}
		if len(names) > maxCandidates {
			return nil, errors.New("too many candidates")
		}
	}
	if len(names) == 0 {
		return nil, errors.New("no candidates")
	}
	sort.Strings(names)
	return names, nil
}

func validateLoopbackURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "http" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Hostname() == "" || !validHTTPAuthority(u) {
		return nil, errors.New("invalid loopback target URL")
	}
	// Enforce the declared allowlist by address FAMILY, not just by the
	// underlying route. net.ParseIP.IsLoopback treats ::ffff:127.0.0.1 as
	// 127.0.0.1; an IPv4-mapped IPv6 authority is not literal IPv4 or ::1.
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" {
		return nil, errors.New("target must be a literal loopback IP")
	}
	if u.Port() != "" {
		port := u.Port()
		var n int
		if _, err := fmt.Sscanf(port, "%d", &n); err != nil || n < 1 || n > 65535 || fmt.Sprint(n) != port {
			return nil, errors.New("invalid port")
		}
	}
	return u, nil
}

type ProbeOptions struct {
	Target     string
	Candidates []byte
	Authorized bool
	Timeout    time.Duration
}

// Probe tests ONLY loopback HTTP using a direct connection. A response difference
// is a hint and must never be marked a confirmed vulnerability.
func validateProbeTimeout(timeout time.Duration) error {
	if timeout < time.Millisecond || timeout > 10*time.Second {
		return errors.New("timeout must be within 1ms to 10s")
	}
	return nil
}

func Probe(ctx context.Context, opts ProbeOptions) (Result, error) {
	seed := append([]byte(opts.Target+"\n"), opts.Candidates...)
	res := base("probe", seed)
	if !opts.Authorized {
		return res, errors.New("explicit authorization required")
	}
	u, err := validateLoopbackURL(opts.Target)
	if err != nil {
		return res, err
	}
	names, err := candidateNames(opts.Candidates)
	if err != nil {
		return res, err
	}
	timeout := opts.Timeout
	if err := validateProbeTimeout(timeout); err != nil {
		return res, err
	}
	// Additional defense: verify the dialed target address, disable proxies,
	// redirects, cookies, and implicit retries. No hostnames or TLS accepted.
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, errors.New("invalid dial address")
			}
			ip, parseErr := netip.ParseAddr(host)
			if parseErr != nil || !ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" {
				return nil, errors.New("non-loopback dial blocked")
			}
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(c, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	fingerprint := func(target *url.URL) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return "", errors.New("cannot construct request")
		}
		req.Header.Set("User-Agent", "ParamMiner-Go/0.1 local-authorized")
		r, err := client.Do(req)
		if err != nil {
			return "", errors.New("local request failed")
		}
		defer r.Body.Close()
		b, err := readBounded(r.Body, maxResponse)
		if err != nil {
			return "", errors.New("response exceeds size or read limit")
		}
		h := sha256.Sum256(b)
		return fmt.Sprintf("%d:%x", r.StatusCode, h), nil
	}
	// Two identical baselines are mandatory, to suppress unstable endpoints.
	a, err := fingerprint(u)
	if err != nil {
		return res, err
	}
	b, err := fingerprint(u)
	if err != nil {
		return res, err
	}
	if a != b {
		return res, errors.New("unstable baseline; cannot infer parameters")
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return res, errors.New("probe cancelled")
		}
		testURL := *u
		vals := url.Values{name: {"paramminer_probe_v1"}}
		testURL.RawQuery = vals.Encode()
		p1, err := fingerprint(&testURL)
		if err != nil {
			return res, err
		}
		p2, err := fingerprint(&testURL)
		if err != nil {
			return res, err
		}
		if p1 == p2 && p1 != a {
			// An endpoint can change independently of parameters just after the
			// initial two baseline requests (deployments, time-based rotation,
			// etc.). Bracket every would-be positive with a fresh unmodified
			// control, rather than silently promoting background drift into
			// inferred parameter evidence. Do not add an extra request for
			// stable negatives. This is a falsification control, not proof of
			// causality under arbitrary time-dependent server behavior.
			control, err := fingerprint(u)
			if err != nil {
				return res, err
			}
			if control != a {
				return res, errors.New("unstable baseline; cannot infer parameters")
			}
			// A short unrelated response burst can occupy exactly the first two
			// candidate requests while the immediate unmodified control has
			// already recovered. Demand a separate repeat observation bracketed
			// by another unmodified control before making even an inference.
			// This mitigates a finite transient; it cannot prove causality.
			confirmation, err := fingerprint(&testURL)
			if err != nil {
				return res, err
			}
			if confirmation != p1 {
				return res, errors.New("unstable candidate response; cannot infer parameters")
			}
			lastControl, err := fingerprint(u)
			if err != nil {
				return res, err
			}
			if lastControl != a {
				return res, errors.New("unstable baseline; cannot infer parameters")
			}
			res.Findings = append(res.Findings, Finding{Name: name, Status: "inferred", Evidence: "repeatable response fingerprint changed relative to stable baseline"})
		}
	}
	res.Notes = []string{"Only literal loopback HTTP targets are permitted; redirects are never followed.", "Differences are inferred response sensitivities, not confirmed vulnerabilities.", "No response body, parameter value, cookies, URL query or secret is emitted."}
	return res, nil
}

func ReadCandidates(path string) ([]byte, error) { return readFile(path, 64<<10) }
