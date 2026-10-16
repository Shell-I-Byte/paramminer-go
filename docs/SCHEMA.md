> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Schema and upgrades

`schema/result.schema.json` describes JSON output `paramminer.result/v1`. Changes to evidence meanings, field removals or new sensitive outputs require a new version (`/v2`) and explicit migration; no silent upgrades. `name` is max 64 characters with restricted ASCII syntax. `status` is observed or inferred, never confirmed. `count` counts presence per request record, not frequency of duplicate key occurrences inside one URL. Empty findings are an empty array.

## Request query field bound (v0.1.0-rc4)

`inventory` accepts at most 10,000 raw query fields per individual input URL; one additional field fails before `net/url.ParseQuery`. This rule makes the accepted input bound explicit across Go toolchain versions. The public `paramminer.result/v1` result shape is unchanged.

## RC11 input policy (output schema v1 unchanged)

Malformed bracketed DNS and IPv4 authorities or unsupported IPvFuture authorities are rejected without producing `paramminer.result/v1` evidence. The output `version` field records `v0.1.0-rc11`; the `schema` identity remains `paramminer.result/v1`.
