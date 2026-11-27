# Changelog

## Unreleased

- Reject IPv4 parts that start with `0` but contain `8` or `9` (for example `127.0.0.08`) instead of decoding them as decimal, matching the WHATWG URL parser and `inet_aton`.
- Add a table-driven IPv4 mutation fixture covering decimal, octal, hex, binary, shorthand, overlong and malformed-separator forms.

## 1.0.0

Initial release.

- Strict SSRF URL, IP literal, DNS resolution set and redirect-chain auditing.
- Legacy IPv4 integer, octal, hexadecimal and shorthand decoding.
- IPv4-mapped, IPv4-compatible, NAT64, 6to4, Teredo, translated and ISATAP transition defenses.
- Cloud metadata endpoint and special-purpose range blocking.
- Redirect downgrade, loop, hop-limit and cross-origin credential stripping checks.
- Dual ESM and CommonJS entry points with TypeScript declarations.
