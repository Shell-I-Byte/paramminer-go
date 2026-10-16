> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Primary references checked 2026-10-09

- Go release history: https://go.dev/doc/devel/release — go1.26.9 and go1.27.2 security revisions (2026-10-08).
- RFC 3986 URI syntax: https://www.rfc-editor.org/rfc/rfc3986 — queries and percent encoding.
- OWASP WSTG HTTP Parameter Pollution: https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/04-HTTP_Parameter_Pollution/ — real HPP vulnerability conclusions require manual verification; automated probes generate false positives.

- POSIX `open()` O_NONBLOCK semantics for FIFO (IEEE/Open Group): https://pubs.opengroup.org/onlinepubs/9799919799/functions/open.html (reviewed 2026-10-10).

## RC11 primary references rechecked 2026-10-15

- RFC 3986 section 3.2.2 host / IP-literal grammar: https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2 . IPv6 addresses use brackets; DNS/IPv4 do not, IPvFuture needs explicit application support.
- Go `net/url` URL.Hostname and URL.Host / URL.Port behavior: https://pkg.go.dev/net/url . Applications still validate policy-specific authority syntax.
- Go stable release policy/history: https://go.dev/doc/devel/release (supported 1.26/1.27; local Go 1.23.2 does not establish stable v1 qualification).
