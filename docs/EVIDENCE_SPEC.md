> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Versioned evidence contract

`schema: "paramminer.result/v1"` is the only contract. Findings contain `name`, `status` (`observed` for offline supplied requests or `inferred` for repeatable localhost response change with a contemporaneous unmodified baseline control), `evidence` (fixed text), and optional `count`. `input_sha256` hashes the exact supplied inventory JSON bytes or target string + newline + exact candidate bytes; it is NOT proof of original network provenance. Results contain no request URL, response contents, parameter values or secrets. Arrays are sorted by name, and no current timestamp appears to preserve deterministic serialization.

A future ProofGraph adapter may ingest these as typed **hints** with the source hash and unchanged status only. It must not label a finding confirmed, verified, exploitable, or in-scope without independent human-supplied validation. No shared IR is shipped here.

## RC11 input-authenticity boundary

An invalid bracketed authority is not valid passive HTTP request evidence. Rejecting it does not constitute a positive finding or change observed/inferred status; previous reports with such inputs must be regenerated from valid data rather than silently rewritten.
