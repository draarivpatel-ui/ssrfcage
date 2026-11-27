# ssrfcage

`ssrfcage` is a zero-dependency Node.js 18+ SSRF security firewall. It validates URLs, IP literals, resolver answers and redirect chains before server-side fetch code can reach loopback, private networks, cloud metadata endpoints, link-local services or parser-confusing transition addresses.

The package has no runtime dependencies and ships both ESM and CommonJS entry points plus TypeScript declarations.

## What it blocks

- RFC 1918, RFC 4193, RFC 6598, loopback, link-local, multicast, unspecified, benchmark, documentation, protocol and reserved IPv4 and IPv6 ranges.
- Cloud metadata endpoints including `169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`, Alibaba `100.100.100.200`, Azure `168.63.129.16`, `metadata.google.internal` and common local metadata names.
- Decimal integer IPv4 such as `2130706433`, octal IPv4 such as `0177.0.0.1`, hexadecimal IPv4 such as `0x7f000001`, shorthand forms such as `127.1`, trailing-dot host bypasses and invalid numeric-looking hosts.
- IPv4-mapped, IPv4-compatible, translated, NAT64, 6to4, Teredo and ISATAP IPv6 transition forms, including forms that hide private IPv4 payloads.
- Zone identifiers, backslashes, embedded credentials, `@` authority confusion, unsafe schemes, noncanonical ports, missing authorities and non-default ports.
- DNS answers containing even one unsafe or invalid IP. `auditResolvedTarget` verifies every A and AAAA answer and enforces optional pinning and previous-answer consistency.
- Redirect loops, excessive hops, HTTPS to HTTP downgrade and cross-origin credential forwarding.

## API

```js
import {
  auditUrl,
  auditIp,
  auditResolvedTarget,
  auditRedirectChain,
  createSafeFetchGuard,
  normalizeHost,
} from 'ssrfcage';

const result = auditUrl('https://example.com/');
if (!result.ok) throw new Error(result.code);

console.log(normalizeHost('2130706433'));
// 127.0.0.1

const resolved = auditResolvedTarget(
  'https://example.com/',
  ['93.184.216.34'],
  { pinnedIp: '93.184.216.34' },
);
if (!resolved.ok) throw new Error(resolved.code);

const chain = await auditRedirectChain([
  'https://example.com/start',
  'https://example.com/final',
]);
```

### `auditUrl(input, options)`

Synchronous URL audit. The default policy allows only `https:` on port 443, forbids userinfo, and rejects non-public IP literals and local hostnames. It never resolves DNS or performs network I/O.

### `auditIp(input)`

Structured audit of one IPv4 or IPv6 literal. Legacy IPv4 spellings are canonicalized before classification.

### `normalizeHost(input)`

Canonicalizes a hostname or IP literal and returns `null` for malformed input. It lowercases DNS names, removes a root trailing dot, canonicalizes legacy IPv4 forms and compresses IPv6.

### `auditResolvedTarget(input, resolvedIps, options)`

Verifies a URL after DNS resolution. Every resolved address must parse, be globally public, satisfy CIDR policy and remain consistent with optional `pinnedIp` and `previousIps` values. For an IP literal URL, the resolution set must contain that exact canonical literal.

### `auditRedirectChain(urls, options)`

Validates every absolute URL in a redirect chain, enforces the maximum hop count, rejects loops and HTTPS downgrade, and reports which credential headers must be stripped when the origin changes.

### `createSafeFetchGuard(options)`

Wraps `fetch` with manual redirect handling. Every hop is validated and resolved again, redirect downgrade is rejected, methods and bodies follow redirect semantics, and credentials are removed rather than forwarded into an unsafe hop. For complete rebinding protection the injected transport must connect to the pinned validated address; ordinary `fetch` performs its own DNS lookup.

## CLI

```bash
ssrfcage audit-url https://example.com/
ssrfcage audit-ip 2130706433
ssrfcage normalize-host EXAMPLE.COM.
ssrfcage audit-resolved https://example.com/ 93.184.216.34
ssrfcage audit-chain https://example.com/a https://example.com/b
```

The same commands can be run locally with `node bin/ssrfcage.mjs`.

## Examples

```bash
node examples/basic.mjs
node examples/resolved-target.mjs
node examples/redirect-chain.mjs
```

## Threat model boundary

This library is a validation and policy layer. It cannot stop a resolver or transport that ignores the validated address. Production SSRF defense also needs resolver pinning at the connection layer, network egress policy, response size limits, content type validation and authentication-aware redirect handling.

## Development

The deterministic suite contains 663 `node:test` tests.


```bash
npm test
node --test tests/*.test.mjs
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/check-pack.mjs
```
