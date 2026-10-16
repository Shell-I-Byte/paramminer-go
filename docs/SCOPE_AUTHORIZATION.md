> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Scope and authorization

Use only on files you are permitted to inspect and loopback web applications you own or are explicitly authorized to assess. `probe` is **hard restricted** to literal IPv4 loopback addresses in 127.0.0.0/8 or IPv6 ::1, HTTP only; no scanning remote systems even when authorized. `--authorize` is an operator declaration, not a legal proof. The CLI cannot bypass its scope restrictions. No dynamic URL/IP fallbacks, no redirection, proxy or cookie forwarding. The tool cannot confirm exploitability.

Brackets in HTTP URL authorities are accepted only for valid IPv6 literals; bracketed DNS, bracketed IPv4, and unsupported IPvFuture forms are rejected before passive evidence processing or loopback requests.
