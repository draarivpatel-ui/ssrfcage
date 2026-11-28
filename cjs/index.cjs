// ssrfcage: zero-dependency SSRF and URL-chain safety for Node and edge runtimes.

const { validateUrl, auditUrl, auditResolvedTarget, normalizeHost } = require('./url.cjs');
const { auditIp } = require('./ip.cjs');
const { auditRedirectChain, createSafeFetchGuard } = require('./chain.cjs');

const __reexport___errors_mjs = require('./errors.cjs');
Object.defineProperty(exports, "SsrfCageError", { enumerable: true, get: () => __reexport___errors_mjs.SsrfCageError });
Object.defineProperty(exports, "guardError", { enumerable: true, get: () => __reexport___errors_mjs.guardError });
const __reexport___ip_mjs = require('./ip.cjs');
Object.defineProperty(exports, "parseIpv4", { enumerable: true, get: () => __reexport___ip_mjs.parseIpv4 });
Object.defineProperty(exports, "parseIpv6", { enumerable: true, get: () => __reexport___ip_mjs.parseIpv6 });
Object.defineProperty(exports, "normalizeIp", { enumerable: true, get: () => __reexport___ip_mjs.normalizeIp });
Object.defineProperty(exports, "classifyIp", { enumerable: true, get: () => __reexport___ip_mjs.classifyIp });
Object.defineProperty(exports, "mappedIpv4", { enumerable: true, get: () => __reexport___ip_mjs.mappedIpv4 });
Object.defineProperty(exports, "sixToFourIpv4", { enumerable: true, get: () => __reexport___ip_mjs.sixToFourIpv4 });
Object.defineProperty(exports, "nat64Ipv4", { enumerable: true, get: () => __reexport___ip_mjs.nat64Ipv4 });
Object.defineProperty(exports, "isNat64LocalUse", { enumerable: true, get: () => __reexport___ip_mjs.isNat64LocalUse });
Object.defineProperty(exports, "ipv4CompatibleIpv4", { enumerable: true, get: () => __reexport___ip_mjs.ipv4CompatibleIpv4 });
Object.defineProperty(exports, "siitIpv4", { enumerable: true, get: () => __reexport___ip_mjs.siitIpv4 });
Object.defineProperty(exports, "isatapIpv4", { enumerable: true, get: () => __reexport___ip_mjs.isatapIpv4 });
Object.defineProperty(exports, "isTeredo", { enumerable: true, get: () => __reexport___ip_mjs.isTeredo });
Object.defineProperty(exports, "teredoClientIpv4", { enumerable: true, get: () => __reexport___ip_mjs.teredoClientIpv4 });
Object.defineProperty(exports, "formatIpv6", { enumerable: true, get: () => __reexport___ip_mjs.formatIpv6 });
Object.defineProperty(exports, "ipv4ToUint32", { enumerable: true, get: () => __reexport___ip_mjs.ipv4ToUint32 });
Object.defineProperty(exports, "parseCidr", { enumerable: true, get: () => __reexport___ip_mjs.parseCidr });
Object.defineProperty(exports, "cidrContains", { enumerable: true, get: () => __reexport___ip_mjs.cidrContains });
Object.defineProperty(exports, "auditIp", { enumerable: true, get: () => __reexport___ip_mjs.auditIp });
const __reexport___url_mjs = require('./url.cjs');
Object.defineProperty(exports, "validateUrl", { enumerable: true, get: () => __reexport___url_mjs.validateUrl });
Object.defineProperty(exports, "auditUrl", { enumerable: true, get: () => __reexport___url_mjs.auditUrl });
Object.defineProperty(exports, "assertSafeUrl", { enumerable: true, get: () => __reexport___url_mjs.assertSafeUrl });
Object.defineProperty(exports, "isPublicHostname", { enumerable: true, get: () => __reexport___url_mjs.isPublicHostname });
Object.defineProperty(exports, "createGuard", { enumerable: true, get: () => __reexport___url_mjs.createGuard });
Object.defineProperty(exports, "normalizeHost", { enumerable: true, get: () => __reexport___url_mjs.normalizeHost });
Object.defineProperty(exports, "auditResolvedTarget", { enumerable: true, get: () => __reexport___url_mjs.auditResolvedTarget });
const __reexport___dns_mjs = require('./dns.cjs');
Object.defineProperty(exports, "resolveSafe", { enumerable: true, get: () => __reexport___dns_mjs.resolveSafe });
const __reexport___chain_mjs = require('./chain.cjs');
Object.defineProperty(exports, "validateRedirectChain", { enumerable: true, get: () => __reexport___chain_mjs.validateRedirectChain });
Object.defineProperty(exports, "createSafeFetch", { enumerable: true, get: () => __reexport___chain_mjs.createSafeFetch });
Object.defineProperty(exports, "auditRedirectChain", { enumerable: true, get: () => __reexport___chain_mjs.auditRedirectChain });
Object.defineProperty(exports, "createSafeFetchGuard", { enumerable: true, get: () => __reexport___chain_mjs.createSafeFetchGuard });
const __reexport___scan_mjs = require('./scan.cjs');
Object.defineProperty(exports, "scanToolArguments", { enumerable: true, get: () => __reexport___scan_mjs.scanToolArguments });

/** Default options object, frozen, useful as a documented baseline. */
const DEFAULT_OPTIONS = Object.freeze({
  allowedSchemes: Object.freeze(['https:']),
  allowUserinfo: false,
  allowedPorts: 'default-only',
  allowSingleLabelHostnames: false,
  idna: 'ascii-only',
  maxInputLength: 8192,
  checkRebinding: false,
  rebindDelayMs: 50,
  maxRedirects: 5,
});

const VERSION = '1.0.0';


const ssrfcage = Object.freeze({
  VERSION,
  auditUrl,
  auditIp,
  auditResolvedTarget,
  auditRedirectChain,
  createSafeFetchGuard,
  normalizeHost,
});



exports.DEFAULT_OPTIONS = DEFAULT_OPTIONS;
exports.VERSION = VERSION;
exports.default = ssrfcage;
