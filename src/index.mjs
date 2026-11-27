// ssrfcage: zero-dependency SSRF and URL-chain safety for Node and edge runtimes.

import { validateUrl, auditUrl, auditResolvedTarget, normalizeHost } from './url.mjs';
import { auditIp } from './ip.mjs';
import { auditRedirectChain, createSafeFetchGuard } from './chain.mjs';

export { SsrfCageError, guardError } from './errors.mjs';
export {
  parseIpv4, parseIpv6, normalizeIp, classifyIp, mappedIpv4,
  sixToFourIpv4, nat64Ipv4, isNat64LocalUse, ipv4CompatibleIpv4,
  siitIpv4, isatapIpv4, isTeredo, teredoClientIpv4, formatIpv6, ipv4ToUint32,
  parseCidr, cidrContains, auditIp,
} from './ip.mjs';
export {
  validateUrl, auditUrl, assertSafeUrl, isPublicHostname, createGuard, normalizeHost, auditResolvedTarget,
} from './url.mjs';
export { resolveSafe } from './dns.mjs';
export { validateRedirectChain, createSafeFetch, auditRedirectChain, createSafeFetchGuard } from './chain.mjs';
export { scanToolArguments } from './scan.mjs';

/** Default options object, frozen, useful as a documented baseline. */
export const DEFAULT_OPTIONS = Object.freeze({
  allowedSchemes: Object.freeze(['https:']),
  allowUserinfo: false,
  allowedPorts: 'default-only',
  idna: 'ascii-only',
  maxInputLength: 8192,
  checkRebinding: false,
  rebindDelayMs: 50,
  maxRedirects: 5,
});

export const VERSION = '1.0.0';


const ssrfcage = Object.freeze({
  VERSION,
  auditUrl,
  auditIp,
  auditResolvedTarget,
  auditRedirectChain,
  createSafeFetchGuard,
  normalizeHost,
});

export default ssrfcage;
