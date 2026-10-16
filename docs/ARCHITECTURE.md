> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Architecture

CLI (command + strict flag parser) -> `internal/miner` -> immutable JSON result. Inventory uses stdlib strict JSON decoder, duplicate-key detection, URL parser, bounded local file read and sorted names. Probe enforces `http` + literal loopback address + no URL query/userinfo/fragment + explicit flag, then uses an independent direct `http.Transport` with network dial IP validation, disabled proxy, no cookie jar, no redirects, sequential GETs and tight body/time limits. SHA-256 source digest is a provenance hint and output is deterministic for identical stable responses. No request or response bodies, credential values or HTTP headers are retained in output.

Each tool has its own module and Git repository. ProofGraph integration is **future work** via the explicit versioned `paramminer.result/v1` JSON evidence interface; nothing is written to a shared graph or silently elevated to `confirmed`.
