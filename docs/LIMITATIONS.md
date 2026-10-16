> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Known limitations

- No target discovery, mutation of remote applications, POST parameter probing, JavaScript execution, authentication, TLS probing or automatic vulnerability determination.
- Response-differential checking compares only status and SHA-256 of bounded response bodies, **not headers**; false positives and false negatives remain possible. An unmodified control is repeated after each prospective finding to detect baseline drift, but time-dependent/periodic server behavior can still yield false positives. A stable pair of responses does not prove a stable application.
- Only ASCII parameter names matching strict safe pattern. Query values are discarded. Duplicate keys in URL query count once per record; malformed percent-encoding aborts rather than skipping.
- No replay of full HTTP transactions. Optional TLS, cookies, remote scope or custom methods are out of scope for this release.
- Loopback-only test protects against unintended outbound traffic but does not prove consent for another local service.
- `go.mod` module path is temporary; supported toolchain/Staticcheck/govulncheck and native macOS/Windows CI await execution.

- Named-file FIFO/device/socket inputs are rejected; Unix has additional nonblocking-open protection, but active modification of a regular file during read is not covered. Non-Unix malicious path races are unverified. Standard input (`-`) intentionally permits streaming and may await data.

- Offline inventory rejects any single URL with more than 10,000 raw query fields (separators `&` counted before parsing); accepted results count presence per request rather than each repeated value. Raw HTTP parameter observations are not verified vulnerabilities.

The CLI enforces a timeout range of 1ms to 10s; 1ms is a valid configuration but may fail in real requests because it is extremely short.

## Temporal falsification tightening (RC7)

A burst confined to the initial candidate pair can return to normal at the first postbaseline. RC6 would infer a candidate even if the endpoint ignored every query parameter. RC7 requires a separate candidate confirmation and a final unmodified control; one short-lived two-request burst is now rejected. Arbitrary periodic, workload-correlated or maliciously synchronized responses can still produce misleading `inferred` output. Do not treat the heuristic as causal proof or a confirmed vulnerability.

## Round 179 release-verification limitation

Portable filename validation reduces ambiguous or unsafe source ZIP layouts but is **not** proof that native Windows/macOS extraction or execution works. An attacker who can replace the ZIP and embedded digest manifest can change both; no publisher signature or external trust anchor is provided. Only files checked against a separately trusted digest have byte-level provenance.

## Run 192 mapped-address policy

IPv4-mapped IPv6 URL authorities are intentionally rejected even if they resolve to 127/8. Only literal 127/8 IPv4 hosts and native IPv6 ::1 hosts are eligible for authorized local probes. The rejection is an address-family policy distinction, **not evidence that a mapped loopback address could reach an external network**.

## RC11 authority parsing boundary

`inventory` treats non-IPv6 bracketed authority forms as malformed input and returns no report. IPvFuture authorities are explicitly unsupported. `probe` rejects bracketed IPv4 authorities even when the destination would otherwise route to local loopback. This rejects ambiguous textual forms; it is not evidence of remote SSRF or a bypass of loopback socket restrictions. Native Windows/macOS runtime validation and separate publisher provenance remain open.
