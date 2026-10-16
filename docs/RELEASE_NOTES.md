> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ParamMiner-Go release history

## RC11 / audit 202: strict bracketed HTTP authorities (2026-10-15)

Offline inventory and the authorized local probe now reject bracketed DNS names, bracketed IPv4 literals, and unsupported IPvFuture forms. `net/url.Parse` accepted several of these while preserving a nonempty `URL.Hostname`; the previous inventory produced `observed` parameter evidence for invalid URLs, and the loopback-only probe could contact an owned local listener using an invalid bracketed IPv4 authority. Valid DNS, literal IPv4, IPv6 and IPv4-mapped IPv6 in **passive inventory only** continue to be supported. Probe still accepts only literal 127/8 IPv4 or native `::1`, never IPv4-mapped IPv6.

No external systems were contacted. `paramminer.result/v1` remains unchanged; the result software version is now `v0.1.0-rc11`. Historical RC10 reports from bracketed invalid URLs are not silently upgraded or treated as valid.

Red-before-green regressions: `internal/miner/authority_regression_test.go` and `tests/authority_cli_probes.py` (Go RC10: 5 invalid authorities unexpectedly accepted; RC10 synthetic loopback test failed; CLI RC10 accepted bracketed DNS with exit 0; RC11 Go and CLI regressions PASS). Actual supported-Go/Staticcheck/Govulncheck and native non-Linux CI remain BLOCKED/UNTESTED.

# Release notes: v0.1.0-rc10 / round 192 (2026-10-15)

- **BUG-PM-192-001 (authorization policy identity)**: Explicitly reject IPv4-mapped IPv6 target authorities (`[::ffff:127.0.0.1]` and hexadecimal equivalents). RC9 treated these as literal IPv4 loopback through `net.ParseIP.IsLoopback`, contrary to the documented allowlist of literal 127.0.0.0/8 or native ::1. No external destination was contacted; the mapped address still routes to loopback.
- Validate IP family and zone using `netip.ParseAddr`, `Is4In6`, and `IsLoopback` at both the URL validator and the final dial guard. Existing allowed IPv4 127/8 and native IPv6 ::1 remain accepted.
- Regression: red-before-green Go unit test (2 failing subcases before fix); compiled CLI red-before-green positive IPv4 and mapped-negative probes on a synthetic loopback HTTP server; independent sealed-source and Git retests.
- Add GitHub Actions Linux ARM64 native runner job (`ubuntu-24.04-arm`). Configuration only: **no workflow run has occurred**.
- Evidence contract remains `paramminer.result/v1`; emitted product `version` advances to v0.1.0-rc10. No remote scanning, cookies, redirects or new probe methods added.
- Stable v1 remains BLOCKED by supported toolchain/analyzers and native platform execution, real CI outcomes, permanent approved module identity, and signed publisher provenance.

# Release notes: v0.1.0-rc9 / round 179 (2026-10-14)

- **BUG-PM-179-001**: portable release ZIP verification previously accepted seven unsafe/ambiguous path classes even when the embedded manifest hashes matched. Reproduced against unmodified RC8 in normal and optimized Python (14 unexpected `VERIFY PASS` outcomes). RC9 now rejects backslash traversal forms, case/Unicode normalized name conflicts, repeated separators, file/directory path overlaps, Windows reserved names and Windows alternate-data-stream colon characters.
- New falsification regression: `tests/test_release_seal_portability.py`, seven malicious archive variants × two Python execution modes. No changes to network operation, authorization, scope or `paramminer.result/v1` evidence structure.
- Supported Go 1.26.9/1.27.2, Staticcheck/Govulncheck, native macOS/Windows tests and signed publisher provenance remain unverified release gates. Archive structural validation alone is **not** release authentication.

# Release notes: v0.1.0-rc8 / round 156

- BUG-PM-156-001: fixed CLI output integrity: short or failed stdout writes during JSON or help delivery are now detected and return exit code 3. RC7 returned success for short writes (JSON) and for short and failing help writes. Added six negative Go subtests.
- BUG-PM-156-002: preserve two tracked executable shell/Python script modes in source ZIP; bind mode policy in source manifest and reject tampered mode metadata. RC7 discarded executable bits.
- No changes to the HTTP probe, request scope or `paramminer.result/v1` contract. Go 1.26/1.27, Staticcheck, Govulncheck, native macOS/Windows and signed provenance remain open gates.

## Historical RC7 notes (round 152)

- Reproduced false `inferred` parameter evidence against a completely query-insensitive synthetic HTTP server when the response temporarily changes **only on HTTP requests 3 and 4**. RC6 returned exit 0 with one false finding after 5 requests.
- Added a second candidate confirmation and a final baseline control before inferring candidate sensitivity. Any disagreement fails closed with a fixed non-sensitive diagnostic; stable positive uses 7 requests, stable negative 4, two-request transient fails at 6.
- Absolute upper bound for 64 candidates is 322 loopback HTTP requests (2 initial + at most 5 per candidate). Every request remains bounded by the existing 1ms–10s per-request timeout. No third-party requests, redirects, cookies or proxy access.
- This is a mitigation of one concrete temporal falsification pattern, **not causal proof**: a suitably correlated server can still emulate candidate effects. All findings stay `inferred`.
- Evidence schema identity remains `paramminer.result/v1`; emitted `version` becomes `v0.1.0-rc8`. Source/CLI version changes do not retroactively upgrade v1 historical reports.
- Supported Go 1.26.9/1.27.2, Staticcheck, Govulncheck and native macOS/Windows run evidence remain BLOCKED/UNTESTED and no stable v1 is claimed.
