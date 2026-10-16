> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Threat model

Assets: local operator's credentials, HTTP request metadata and test target. Threats: SSRF via redirects, DNS rebinding, HTTP proxy variables, unbounded responses, malformed JSON, malicious parameter names, console injection, inconsistent dynamic baselines, privacy leaks, overclaiming evidence. Controls: loopback-literal-only `probe`; secondary DialContext IP check; no redirects/proxy/cookies; bounded inputs and response; strict names/flags; baseline repeated and a post-probe unmodified control for candidate positives; status `inferred`; sanitized stderr; no values or raw URLs in output. This is not a sandbox; target server can still perform its own side effects and the user MUST own/control it. HTTP GET may mutate misconfigured endpoints. No internet access in inventory. Known limitations in `LIMITATIONS.md`.

Input-file denial-of-service: OS file-open can block forever on POSIX FIFO. v0.1.0-rc2 checks named files before open and uses Unix O_NONBLOCK with post-open fstat; socket/device/directory paths are rejected. There is no guarantee of atomic content snapshots or malicious Windows path-race resistance.
