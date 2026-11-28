// Strict URL parser, policy engine and synchronous validator.
// The WHATWG parser is used only AFTER hostile-input checks, because it
// normalizes many SSRF payloads (decimal IP, shorthand, backslashes) silently.

import { guardError, fail, redactInput } from './errors.mjs';
import { classifyIp, normalizeIp, cidrContains, parseIpv4 } from './ip.mjs';

const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
const WHITESPACE_RE = /\s/;
const DEFAULT_MAX_INPUT_LENGTH = 8192;
const DEFAULT_SCHEMES = ['https:'];
const DEFAULT_PORTS = { 'http:': 80, 'https:': 443 };

const BLOCKED_HOSTNAMES = new Set([
  'localhost', 'metadata', 'metadata.google.internal', 'metadata.goog',
  'metadata.azure.com', 'instance-data', 'instance-data.ec2.internal',
  'kubernetes.default.svc', 'kubernetes.default', 'api.internal',
]);
const BLOCKED_HOST_SUFFIXES = [
  '.internal', '.localhost', '.local', '.localdomain', '.home.arpa',
  '.in-addr.arpa', '.ip6.arpa', '.onion',
];
const PUBLIC_SUFFIXES = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'ai', 'app', 'dev',
  'xyz', 'info', 'biz', 'me', 'tv', 'us', 'uk', 'de', 'fr', 'jp', 'cn', 'in', 'au',
  'ca', 'br', 'nl', 'se', 'no', 'fi', 'es', 'it', 'ru', 'ch', 'at', 'be', 'dk',
  'co.uk', 'org.uk', 'com.au', 'co.jp', 'co.nz', 'com.br', 'co.in',
]);

function normalizeSchemes(schemes) {
  const list = typeof schemes === 'string'
    ? [schemes]
    : (Array.isArray(schemes) ? schemes : DEFAULT_SCHEMES);
  const result = [];
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    let scheme = raw.trim().toLowerCase();
    if (!scheme) continue;
    if (!scheme.endsWith(':')) scheme += ':';
    if (!/^[a-z][a-z\d+.-]*:$/.test(scheme)) continue;
    result.push(scheme);
  }
  return Array.from(new Set(result));
}

/**
 * Read an option only when it is an own property. A polluted Object.prototype
 * must never be able to weaken a policy, inject a resolver or swap fetch.
 */
export function ownOption(source, key) {
  if (source === null || typeof source !== 'object') return undefined;
  return Object.hasOwn(source, key) ? source[key] : undefined;
}

function copyStrings(value) {
  return Array.isArray(value) ? value.filter((entry) => typeof entry === 'string') : [];
}

function normalizeHostPolicy(policy) {
  const source = policy && typeof policy === 'object' ? policy : {};
  const configuredAllow = ownOption(source, 'allow');
  return {
    allow: Array.isArray(configuredAllow) ? configuredAllow.slice() : [],
    deny: copyStrings(ownOption(source, 'deny')),
    allowPublicSuffix: ownOption(source, 'allowPublicSuffix') === true,
  };
}

function normalizeOptions(options) {
  const opts = options && typeof options === 'object' ? options : {};
  const allowedSchemes = normalizeSchemes(ownOption(opts, 'allowedSchemes'));
  const rawPorts = ownOption(opts, 'allowedPorts');
  const allowedPorts = rawPorts === undefined ? 'default-only' : rawPorts;
  const maxInputLength = ownOption(opts, 'maxInputLength');
  const rebindDelayMs = ownOption(opts, 'rebindDelayMs');
  const maxRedirects = ownOption(opts, 'maxRedirects');
  return {
    allowedSchemes,
    allowUserinfo: ownOption(opts, 'allowUserinfo') === true,
    allowedPorts: Array.isArray(allowedPorts) ? allowedPorts.slice() : allowedPorts,
    hostPolicy: normalizeHostPolicy(ownOption(opts, 'hostPolicy')),
    allowSingleLabelHostnames: ownOption(opts, 'allowSingleLabelHostnames') === true,
    maxInputLength: Number.isInteger(maxInputLength) && maxInputLength > 0
      ? maxInputLength : DEFAULT_MAX_INPUT_LENGTH,
    idna: ownOption(opts, 'idna') === 'allow-unicode' ? 'allow-unicode' : 'ascii-only',
    allowCidrs: copyStrings(ownOption(opts, 'allowCidrs')),
    denyCidrs: copyStrings(ownOption(opts, 'denyCidrs')),
    dns: ownOption(opts, 'dns'),
    checkRebinding: ownOption(opts, 'checkRebinding') === true,
    rebindDelayMs: Number.isFinite(rebindDelayMs) && rebindDelayMs >= 0
      ? rebindDelayMs : 50,
    maxRedirects: Number.isInteger(maxRedirects) && maxRedirects >= 0
      ? maxRedirects : 5,
  };
}

/** Reject hostile literal forms before the WHATWG parser can normalize them away. */
function precheck(input, opts) {
  if (typeof input !== 'string') return fail('INVALID_URL', 'URL must be a string', input);
  if (input.length === 0) return fail('INVALID_URL', 'URL is empty', input);
  if (input.length > opts.maxInputLength) return fail('INPUT_TOO_LARGE', `URL exceeds ${opts.maxInputLength} characters`, input);
  if (CONTROL_RE.test(input)) return fail('INVALID_URL', 'control character in URL', input);
  if (input.includes('\u0000')) return fail('INVALID_URL', 'null byte in URL', input);
  if (input.includes('\\')) return fail('INVALID_URL', 'backslash in URL', input);
  if (WHITESPACE_RE.test(input)) return fail('INVALID_URL', 'whitespace in URL', input);
  if (input.trim() !== input) return fail('INVALID_URL', 'leading or trailing whitespace in URL', input);
  if (input.startsWith('//')) return fail('INVALID_URL', 'scheme-relative URLs are not allowed', input);
  const schemePrefix = /^[a-z][a-z\d+.-]*:/i.exec(input);
  if (schemePrefix && opts.allowedSchemes.includes(schemePrefix[0].toLowerCase()) && !input.slice(schemePrefix[0].length).startsWith('//')) {
    return fail('INVALID_URL', 'hierarchical URL schemes require an explicit authority', input);
  }
  return null;
}

function stripSingleTrailingDot(host) {
  if (!host.endsWith('.')) return host;
  const result = host.slice(0, -1);
  return result.endsWith('.') ? null : result;
}

function endsInIpv4Number(host) {
  const finalLabel = host.slice(host.lastIndexOf('.') + 1);
  return /^\d+$/.test(finalLabel) || /^0x[0-9a-f]*$/i.test(finalLabel);
}

function trailingRootDotCount(host) {
  let count = 0;
  for (let index = host.length - 1; index >= 0; index -= 1) {
    const char = host[index];
    if (char !== '.' && char !== '\u3002' && char !== '\uff0e' && char !== '\uff61') break;
    count += 1;
  }
  return count;
}

function canonicalizeDnsOrIpHost(host, allowPunycode, urlCompatibleLabels = false) {
  if (!host || host.startsWith('.') || host.includes('..') || host.length > 253) return null;
  const ip = normalizeIp(host);
  if (ip !== null) return ip;
  if (host.includes(':')) return null;
  // WHATWG treats a host whose final label is ASCII digits or a 0x-prefixed
  // hexadecimal number as an IPv4 spelling. When strict parsing has already
  // failed, that spelling must not fall through as DNS. Hex-letter words such
  // as db and deadbeef are not numeric final labels, so they remain valid DNS
  // labels.
  if (endsInIpv4Number(host)) return null;
  const labels = host.split('.');
  if (labels.some((label) => label.length === 0 || label.length > 63)) return null;
  if (!allowPunycode && labels.some((label) => label.startsWith('xn--'))) return null;
  if (!urlCompatibleLabels && labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
  return host;
}

function canonicalizePatternHostname(host) {
  if (typeof host !== 'string' || host.length === 0) return null;
  const rootDots = trailingRootDotCount(host);
  if (rootDots > 1 || host.length - rootDots > 253) return null;
  if (CONTROL_RE.test(host) || WHITESPACE_RE.test(host) || host.includes('\\') || host.includes('%')) return null;
  if (/[/@?#]/.test(host)) return null;
  // IPv6 literals need the one tolerated trailing root dot stripped before
  // bracket handling because the WHATWG parser rejects it inside brackets.
  // DNS names keep it through IDNA normalization so a hidden second root dot
  // is still present for the post-normalization count below.
  const isIpv6Candidate = host.includes(':');
  const body = rootDots === 1 && isIpv6Candidate ? host.slice(0, -1) : host;
  const urlHost = body.includes(':') && !(body.startsWith('[') && body.endsWith(']')) ? `[${body}]` : body;
  let parsed;
  try {
    parsed = new URL(`https://${urlHost}/`);
  } catch {
    return null;
  }
  if (parsed.username || parsed.password || parsed.port) return null;
  let canonical = parsed.hostname.toLowerCase();
  if (canonical.startsWith('[') && canonical.endsWith(']')) canonical = canonical.slice(1, -1);
  const canonicalRootDots = trailingRootDotCount(canonical);
  if (canonicalRootDots > 1) return null;
  if (canonicalRootDots === 1) canonical = canonical.slice(0, -1);
  return canonicalizeDnsOrIpHost(canonical, true, true);
}

function normalizeHostPattern(pattern) {
  if (typeof pattern !== 'string') return null;
  let normalized = pattern.trim();
  if (!normalized) return null;
  const bare = !normalized.startsWith('*.') && !normalized.startsWith('.');
  if (normalized.startsWith('*.')) normalized = normalized.slice(2);
  else if (normalized.startsWith('.')) normalized = normalized.slice(1);
  if (!normalized) return null;
  const host = canonicalizePatternHostname(normalized);
  if (host === null) return null;
  return { host, bare };
}

function normalizedHostPatternMatches(host, normalized) {
  return host === normalized.host || host.endsWith(`.${normalized.host}`);
}

function hostPatternMatches(host, pattern) {
  const normalized = normalizeHostPattern(pattern);
  if (normalized === null) return false;
  return normalizedHostPatternMatches(host, normalized);
}

function allowlistPatternMatches(host, pattern, allowPublicSuffix) {
  const normalized = normalizeHostPattern(pattern);
  if (normalized === null) return false;
  if (
    normalized.bare
    && allowPublicSuffix !== true
    && isSingleLabelDnsHostname(normalized.host)
    && !PUBLIC_SUFFIXES.has(normalized.host)
  ) {
    return host === normalized.host;
  }
  return normalizedHostPatternMatches(host, normalized);
}

function isPublicSuffixPattern(pattern) {
  const normalized = normalizeHostPattern(pattern);
  if (normalized === null) return false;
  return PUBLIC_SUFFIXES.has(normalized.host) || isSingleLabelDnsHostname(normalized.host);
}

function isForbiddenBroadSuffixEntry(pattern) {
  const normalized = normalizeHostPattern(pattern);
  if (normalized === null || !isPublicSuffixPattern(pattern)) return false;
  if (isSingleLabelDnsHostname(normalized.host)) {
    return !normalized.bare || PUBLIC_SUFFIXES.has(normalized.host);
  }
  return true;
}

function isExactHostAllowlistEntry(host, pattern) {
  const normalized = normalizeHostPattern(pattern);
  return normalized !== null
    && normalized.bare
    && !PUBLIC_SUFFIXES.has(normalized.host)
    && normalized.host === host;
}

function isSingleLabelDnsHostname(host) {
  return !host.includes('.') && !host.includes(':') && normalizeIp(host) === null;
}

function checkHostPolicy(hostname, hostPolicy, allowSingleLabelHostnames) {
  const host = stripSingleTrailingDot(hostname.toLowerCase());
  if (host === null) return fail('INVALID_URL', 'hostname contains consecutive dots', hostname);
  const deny = Array.isArray(hostPolicy.deny) ? hostPolicy.deny : [];
  const allow = Array.isArray(hostPolicy.allow) ? hostPolicy.allow : [];
  if (BLOCKED_HOSTNAMES.has(host)) return fail('HOST_DENIED', 'hostname is on the built-in deny list', host);
  for (const suffix of BLOCKED_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) return fail('HOST_DENIED', `hostname ends with blocked suffix ${suffix}`, host);
  }
  for (const pattern of deny) {
    if (hostPatternMatches(host, pattern)) return fail('HOST_DENIED', `hostname denied by policy (${pattern})`, host);
  }
  if (allow.length > 0) {
    if (hostPolicy.allowPublicSuffix !== true) {
      const broadSuffix = allow.find((pattern) => isForbiddenBroadSuffixEntry(pattern));
      if (broadSuffix !== undefined) {
        return fail('HOST_NOT_ALLOWED', `public suffix cannot be allowlisted (${broadSuffix})`, host);
      }
    }
    let allowed = false;
    for (const pattern of allow) {
      if (allowlistPatternMatches(host, pattern, hostPolicy.allowPublicSuffix === true)) {
        allowed = true;
        break;
      }
    }
    if (!allowed) return fail('HOST_NOT_ALLOWED', 'hostname is not on the allow list', host);
  }
  if (
    isSingleLabelDnsHostname(host)
    && allowSingleLabelHostnames !== true
    && !allow.some((pattern) => isExactHostAllowlistEntry(host, pattern))
  ) {
    return fail('HOST_DENIED', 'single-label DNS hostnames are not public destinations', host);
  }
  return null;
}

/** Canonicalize a DNS host or IP literal, including legacy IPv4 spellings. */
export function normalizeHost(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 253) return null;
  if (CONTROL_RE.test(input) || WHITESPACE_RE.test(input) || input.includes('\\') || input.includes('%')) return null;
  let host = input.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  host = stripSingleTrailingDot(host);
  if (host === null) return null;
  if (!host || host.startsWith('.') || host.includes('..') || host.length > 253) return null;
  return canonicalizeDnsOrIpHost(host, false);
}

function addressesFromResolution(resolvedIps) {
  if (!Array.isArray(resolvedIps)) return null;
  const output = [];
  for (const entry of resolvedIps) {
    const value = typeof entry === 'string' ? entry : entry && typeof entry === 'object' && typeof entry.address === 'string' ? entry.address : null;
    if (value === null) return null;
    output.push(value);
  }
  return output;
}

/** Verify a URL against every already resolved A or AAAA answer and an optional pin. */
export function auditResolvedTarget(input, resolvedIps, options) {
  const validation = validateUrl(input, options);
  if (!validation.ok) return { ...validation, resolvedIps: [], pinned: false };
  const rawAddresses = addressesFromResolution(resolvedIps);
  if (!rawAddresses || rawAddresses.length === 0) {
    return { ok: false, code: 'RESOLUTION_FAILED', detail: 'resolvedIps must contain at least one address', resolvedIps: [], pinned: false };
  }
  const canonical = [];
  for (const address of rawAddresses) {
    const normalized = normalizeIp(address);
    if (normalized === null) {
      return { ok: false, code: 'INVALID_IP', detail: 'resolver returned an invalid IP address', resolvedIps: canonical, pinned: false };
    }
    const classification = classifyIp(normalized);
    if (classification !== 'public') {
      return { ok: false, code: 'PRIVATE_IP', detail: 'resolver returned a non-public IP address', classification, resolvedIps: canonical.concat(normalized), pinned: false };
    }
    const resolvedPolicy = normalizeOptions(options);
    for (const cidr of resolvedPolicy.denyCidrs) {
      if (cidrContains(cidr, normalized)) {
        return { ok: false, code: 'HOST_DENIED', detail: 'resolved IP is denied by CIDR policy', resolvedIps: canonical.concat(normalized), pinned: false };
      }
    }
    if (resolvedPolicy.allowCidrs.length > 0 && !resolvedPolicy.allowCidrs.some((cidr) => cidrContains(cidr, normalized))) {
      return { ok: false, code: 'HOST_NOT_ALLOWED', detail: 'resolved IP is outside the allowed CIDR set', resolvedIps: canonical.concat(normalized), pinned: false };
    }
    canonical.push(normalized);
  }
  const unique = Array.from(new Set(canonical)).sort();
  const literal = normalizeIp(validation.hostname);
  if (literal !== null && !unique.includes(literal)) {
    return { ok: false, code: 'PIN_MISMATCH', detail: 'resolved addresses do not include the URL IP literal', resolvedIps: unique, pinned: false };
  }
  const pinnedIp = ownOption(options, 'pinnedIp');
  if (pinnedIp !== undefined && typeof pinnedIp !== 'string') {
    return { ok: false, code: 'PIN_MISMATCH', detail: 'pinnedIp must be a string IP address', resolvedIps: unique, pinned: false };
  }
  if (typeof pinnedIp === 'string') {
    const normalizedPin = normalizeIp(pinnedIp);
    if (normalizedPin === null || !unique.includes(normalizedPin)) {
      return { ok: false, code: 'PIN_MISMATCH', detail: 'pinned IP is absent from the verified resolution set', resolvedIps: unique, pinned: false };
    }
  }
  const previous = ownOption(options, 'previousIps');
  if (previous !== undefined) {
    const oldAddresses = addressesFromResolution(previous);
    if (!oldAddresses) return { ok: false, code: 'DNS_REBIND', detail: 'previousIps is malformed', resolvedIps: unique, pinned: false };
    const oldCanonical = Array.from(new Set(oldAddresses.map((item) => normalizeIp(item)).filter((item) => item !== null))).sort();
    if (oldCanonical.join(',') !== unique.join(',')) {
      return { ok: false, code: 'DNS_REBIND', detail: 'resolved address set changed between lookups', resolvedIps: unique, pinned: false };
    }
  }
  return {
    ok: true,
    url: validation.normalized,
    hostname: validation.hostname,
    port: validation.port,
    resolvedIps: unique,
    pinnedIp: typeof pinnedIp === 'string' ? normalizeIp(pinnedIp) : unique[0],
    pinned: true,
    everyResolvedIpVerified: true,
  };
}

/** Validate the string and return a URL object. Synchronous, no network I/O. */
export function validateUrl(input, options) {
  const opts = normalizeOptions(options);
  const pre = precheck(input, opts);
  if (pre) return pre;

  // Check the raw scheme before WHATWG normalization or authority inspection.
  const rawSchemeMatch = /^([a-z][a-z\d+.-]*):/i.exec(input);
  const rawScheme = rawSchemeMatch ? `${rawSchemeMatch[1].toLowerCase()}:` : '';
  if (rawScheme && !opts.allowedSchemes.includes(rawScheme)) {
    return fail('UNSAFE_SCHEME', `scheme ${rawScheme} is not allowed`, input);
  }

  // Examine the raw authority before WHATWG normalization can hide encoded hosts.
  const authorityMatch = /^[a-z][a-z\d+.-]*:\/\/([^/?#]*)/i.exec(input);
  const rawAuthority = authorityMatch ? authorityMatch[1] : '';
  if (authorityMatch && rawAuthority.length === 0) {
    return fail('INVALID_URL', 'empty hostname', input);
  }
  if (/%[0-9a-f]{2}/i.test(rawAuthority)) {
    return fail('INVALID_URL', 'percent-encoded characters in authority are not allowed', input);
  }
  if (authorityMatch) {
    const hostPort = rawAuthority.slice(rawAuthority.lastIndexOf('@') + 1);
    let portText = null;
    if (hostPort.endsWith(':')) return fail('PORT_FORBIDDEN', 'port is empty', input);
    if (hostPort.startsWith('[')) {
      const close = hostPort.indexOf(']');
      const rest = close >= 0 ? hostPort.slice(close + 1) : '';
      if (rest.startsWith(':')) portText = rest.slice(1);
    } else if ((hostPort.match(/:/g) || []).length === 1) {
      portText = hostPort.slice(hostPort.lastIndexOf(':') + 1);
    }
    if (portText !== null && portText !== '' && (!/^[0-9]+$/.test(portText) || (portText.length > 1 && portText.startsWith('0')))) {
      return fail('PORT_FORBIDDEN', 'port must be canonical decimal digits', input);
    }
  }
  if (opts.idna === 'ascii-only' && /[^\x21-\x7e]/.test(rawAuthority)) {
    return fail('UNSUPPORTED_IDNA', 'unicode hostname requires idna: allow-unicode', input);
  }
  if (opts.idna === 'ascii-only' && /\bxn--/i.test(rawAuthority)) {
    return fail('UNSUPPORTED_IDNA', 'punycode hostname requires idna: allow-unicode', input);
  }

  let url;
  try {
    url = new URL(input);
  } catch {
    return fail('INVALID_URL', 'URL could not be parsed', input);
  }
  if (!opts.allowedSchemes.includes(url.protocol)) {
    return fail('UNSAFE_SCHEME', `scheme ${url.protocol} is not allowed`, input);
  }
  if ((url.username || url.password) && !opts.allowUserinfo) {
    return fail('USERINFO_FORBIDDEN', 'embedded credentials are not allowed', input);
  }

  let hostname = url.hostname.toLowerCase();
  if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);
  // A single trailing dot is a valid root-qualified FQDN. A second one leaves
  // an empty label that resolvers normalize inconsistently, so it is rejected.
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
    if (hostname.endsWith('.')) {
      return fail('INVALID_URL', 'hostname contains consecutive dots', input);
    }
  }
  if (!hostname) return fail('INVALID_URL', 'empty hostname', input);
  // A leading dot is an empty first label, which resolvers normalize inconsistently.
  if (hostname.startsWith('.')) return fail('INVALID_URL', 'hostname starts with an empty label', input);
  if (hostname.includes('%')) return fail('INVALID_URL', 'percent-encoded hostname is not allowed', input);
  if (opts.idna === 'ascii-only' && /[^\x21-\x7e]/.test(hostname)) {
    return fail('UNSUPPORTED_IDNA', 'unicode hostname requires idna: allow-unicode', input);
  }
  if (hostname.length > 253 || hostname.split('.').some((label) => label.length > 63)) {
    return fail('INVALID_URL', 'hostname or label is too long', input);
  }
  if (hostname.includes('..')) {
    return fail('INVALID_URL', 'hostname contains consecutive dots', input);
  }

  const ipClass = classifyIp(hostname);
  if (ipClass === 'private' || (ipClass !== 'public' && ipClass !== 'invalid')) {
    return fail('PRIVATE_IP', `host resolves to a non-public range (${ipClass})`, input);
  }
  if (ipClass === 'public') {
    for (const cidr of opts.denyCidrs) {
      if (cidrContains(cidr, hostname)) return fail('HOST_DENIED', `host denied by CIDR (${cidr})`, input);
    }
    if (opts.allowCidrs.length > 0 && !opts.allowCidrs.some((cidr) => cidrContains(cidr, hostname))) {
      return fail('HOST_NOT_ALLOWED', 'host is not in an allowed CIDR', input);
    }
  }

  const policyFailure = checkHostPolicy(hostname, hostPolicyOrEmpty(opts), opts.allowSingleLabelHostnames);
  if (policyFailure) return { ...policyFailure, input: redactInput(input) };

  const defaultPort = DEFAULT_PORTS[url.protocol];
  const port = url.port ? Number(url.port) : defaultPort;
  if (!url.port && defaultPort === undefined) {
    // Custom schemes have no well-known port; the absence of an explicit port is safe.
    return {
      ok: true,
      url,
      normalized: url.href,
      hostname,
      port: undefined,
      ipClass,
      normalizedIp: normalizeIp(hostname),
    };
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return fail('PORT_FORBIDDEN', 'port is outside 1-65535', input);
  }
  if (opts.allowedPorts === 'default-only') {
    if (port !== defaultPort) {
      return fail('PORT_FORBIDDEN', `only port ${defaultPort} is allowed for ${url.protocol}`, input);
    }
  } else if (Array.isArray(opts.allowedPorts)) {
    if (!opts.allowedPorts.includes(port)) return fail('PORT_FORBIDDEN', `port ${port} is not allowed`, input);
  } else if (opts.allowedPorts !== 'any') {
    return fail('PORT_FORBIDDEN', 'allowedPorts must be an array, default-only or any', input);
  }

  return {
    ok: true,
    url,
    normalized: url.href,
    hostname,
    port,
    ipClass,
    normalizedIp: normalizeIp(hostname),
  };
}

function hostPolicyOrEmpty(opts) {
  return opts.hostPolicy && typeof opts.hostPolicy === 'object' ? opts.hostPolicy : {};
}

/** Throwing variant. Error codes are stable; stacks contain no internal frames. */
export function assertSafeUrl(input, options) {
  const result = validateUrl(input, options);
  if (!result.ok) throw guardError(result.code, result.detail, input);
  return result;
}

/** Check a hostname against host policy only. Returns true when allowed. */
export function isPublicHostname(hostname, options) {
  if (typeof hostname !== 'string' || !hostname) return false;
  const opts = normalizeOptions(options);
  let host = stripSingleTrailingDot(hostname.toLowerCase().replace(/^\[|\]$/g, ''));
  if (host === null || !host || host.startsWith('.') || host.includes('..')) return false;
  // Only plain ASCII host characters count. Unicode dot and digit lookalikes
  // are folded into a different host by an IDNA-aware parser downstream, so a
  // policy check on the raw string would approve a host that resolves elsewhere.
  if (!/^[a-z0-9._:-]+$/.test(host)) return false;
  const normalizedIp = normalizeIp(host);
  if (normalizedIp !== null) host = normalizedIp;
  const ipClass = classifyIp(host);
  if (host.includes(':')) {
    // A colon-bearing host must be a public IPv6 literal, never a DNS name.
    if (ipClass !== 'public') return false;
  } else if (ipClass !== 'public' && ipClass !== 'invalid') {
    // IP literals must be public; plain DNS names are verified at resolution time.
    return false;
  }
  for (const cidr of opts.denyCidrs) if (cidrContains(cidr, host)) return false;
  if (opts.allowCidrs.length > 0 && !opts.allowCidrs.some((cidr) => cidrContains(cidr, host))) return false;
  return checkHostPolicy(host, hostPolicyOrEmpty(opts), opts.allowSingleLabelHostnames) === null;
}

/** Freeze a normalized policy, including every nested array, so a guard cannot drift. */
function freezePolicy(opts) {
  Object.freeze(opts.allowedSchemes);
  if (Array.isArray(opts.allowedPorts)) Object.freeze(opts.allowedPorts);
  Object.freeze(opts.allowCidrs);
  Object.freeze(opts.denyCidrs);
  Object.freeze(opts.hostPolicy.allow);
  Object.freeze(opts.hostPolicy.deny);
  Object.freeze(opts.hostPolicy);
  Object.freeze(opts);
  return opts;
}

/** Compile a reusable policy object. */
export function createGuard(options) {
  const opts = freezePolicy(normalizeOptions(options));
  return {
    validate: (input) => validateUrl(input, opts),
    assert: (input) => assertSafeUrl(input, opts),
    isPublicHostname: (host) => isPublicHostname(host, opts),
    options: Object.freeze({ ...opts }),
  };
}

export { normalizeOptions };

export const auditUrl = validateUrl;
