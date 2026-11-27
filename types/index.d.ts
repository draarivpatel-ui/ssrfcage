/** Stable error codes emitted by ssrfcage. */
export type SsrfCageErrorCode =
  | 'INVALID_URL'
  | 'INVALID_IP'
  | 'INVALID_HOST'
  | 'UNSAFE_SCHEME'
  | 'USERINFO_FORBIDDEN'
  | 'PRIVATE_IP'
  | 'DNS_REBIND'
  | 'HOST_DENIED'
  | 'HOST_NOT_ALLOWED'
  | 'PORT_FORBIDDEN'
  | 'PIN_MISMATCH'
  | 'SCHEME_DOWNGRADE'
  | 'TOO_MANY_HOPS'
  | 'REDIRECT_LOOP'
  | 'INPUT_TOO_LARGE'
  | 'UNSUPPORTED_IDNA'
  | 'RESOLUTION_FAILED';

export declare class SsrfCageError extends Error {
  readonly name: 'SsrfCageError';
  readonly code: SsrfCageErrorCode;
  readonly reason: string;
  readonly input: string;
  constructor(code: SsrfCageErrorCode, reason: string, input: unknown);
  toJSON(): { name: string; code: SsrfCageErrorCode; reason: string; input: string };
}

export declare function guardError(code: SsrfCageErrorCode, reason: string, input: unknown): SsrfCageError;

export interface DnsResolver {
  (hostname: string): Promise<readonly (string | { address: string; family?: number })[]>;
}

export interface HostPolicy {
  readonly allow?: readonly string[];
  readonly deny?: readonly string[];
  readonly allowPublicSuffix?: boolean;
}

export interface ValidateOptions {
  readonly allowedSchemes?: readonly string[];
  readonly allowUserinfo?: boolean;
  readonly allowedPorts?: readonly number[] | 'default-only' | 'any';
  readonly hostPolicy?: HostPolicy;
  readonly dns?: DnsResolver | false;
  readonly checkRebinding?: boolean;
  readonly rebindDelayMs?: number;
  readonly maxInputLength?: number;
  readonly idna?: 'ascii-only' | 'allow-unicode';
  readonly denyCidrs?: readonly string[];
  readonly allowCidrs?: readonly string[];
  readonly maxRedirects?: number;
  readonly allowSchemeDowngrade?: boolean;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface ValidationSuccess {
  readonly ok: true;
  readonly url: URL;
  readonly normalized: string;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly ipClass: string;
  readonly normalizedIp: string | null;
}

export interface ValidationFailure {
  readonly ok: false;
  readonly code: SsrfCageErrorCode;
  readonly detail: string;
  readonly input?: string;
}

export type ValidationResult = ValidationSuccess | ValidationFailure;

export interface IpAuditResult {
  readonly ok: boolean;
  readonly code: 'OK' | 'INVALID_IP' | 'PRIVATE_IP';
  readonly detail: string;
  readonly classification: string;
  readonly normalized: string | null;
}

export interface ResolvedTargetResult {
  readonly ok: boolean;
  readonly code?: SsrfCageErrorCode;
  readonly detail?: string;
  readonly url?: string;
  readonly hostname?: string;
  readonly port?: number;
  readonly resolvedIps: readonly string[];
  readonly pinnedIp?: string | null;
  readonly pinned: boolean;
  readonly everyResolvedIpVerified?: boolean;
}

export interface ResolvedTargetOptions extends ValidateOptions {
  readonly pinnedIp?: string;
  readonly previousIps?: readonly (string | { address: string })[];
}


export interface ResolveResult {
  readonly ok: boolean;
  readonly hostname: string;
  readonly addresses: readonly string[];
  readonly pinnedIp?: string | null;
  readonly code?: SsrfCageErrorCode;
  readonly detail?: string;
}

export interface HopResult {
  readonly url: string;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly addresses: readonly string[];
  readonly pinnedIp: string | null;
  readonly crossOrigin: boolean;
  readonly strippedHeaders: readonly string[];
  readonly credentialsRetained: boolean;
}

export interface ChainResult {
  readonly ok: boolean;
  readonly hops: readonly HopResult[];
  readonly finalUrl?: string;
  readonly code?: SsrfCageErrorCode;
  readonly detail?: string;
  readonly hop?: number;
  readonly input?: string;
}

export interface SafeFetchOptions extends ValidateOptions {
  readonly fetch?: typeof globalThis.fetch;
}

export interface Guard {
  validate(input: string): ValidationResult;
  assert(input: string): ValidationSuccess;
  isPublicHostname(hostname: string): boolean;
  readonly options: Readonly<ValidateOptions>;
}

export interface ScanFinding {
  readonly ok: boolean;
  readonly path: string;
  readonly value: string;
  readonly code?: SsrfCageErrorCode;
  readonly detail?: string;
}

export interface ScanResult {
  readonly ok: boolean;
  readonly findings: readonly ScanFinding[];
  readonly rejected: number;
  readonly scanned: number;
  readonly truncated: boolean;
}

export interface ScanOptions extends ValidateOptions {
  readonly maxDepth?: number;
  readonly maxNodes?: number;
}

export declare const VERSION: '1.0.0';
export declare const DEFAULT_OPTIONS: Readonly<{
  allowedSchemes: readonly string[];
  allowUserinfo: false;
  allowedPorts: 'default-only';
  idna: 'ascii-only';
  maxInputLength: number;
  checkRebinding: false;
  rebindDelayMs: number;
  maxRedirects: number;
}>;

export declare function auditUrl(input: unknown, options?: ValidateOptions): ValidationResult;
export declare function validateUrl(input: unknown, options?: ValidateOptions): ValidationResult;
export declare function assertSafeUrl(input: unknown, options?: ValidateOptions): ValidationSuccess;
export declare function auditIp(input: unknown): IpAuditResult;
export declare function normalizeHost(input: unknown): string | null;
export declare function auditResolvedTarget(
  input: unknown,
  resolvedIps: readonly (string | { address: string })[],
  options?: ResolvedTargetOptions
): ResolvedTargetResult;
export declare function auditRedirectChain(urls: string | Iterable<string>, options?: ValidateOptions): Promise<ChainResult>;
export declare function validateRedirectChain(urls: string | Iterable<string>, options?: ValidateOptions): Promise<ChainResult>;
export declare function createSafeFetchGuard(options?: SafeFetchOptions): (input: string | { url: string }, init?: RequestInit) => Promise<Response>;
export declare function createSafeFetch(options?: SafeFetchOptions): (input: string | { url: string }, init?: RequestInit) => Promise<Response>;
export declare function createGuard(options?: ValidateOptions): Guard;
export declare function scanToolArguments(value: unknown, options?: ScanOptions): ScanResult;
export declare function resolveSafe(hostname: string, options?: ValidateOptions): Promise<ResolveResult>;
export declare function isPublicHostname(hostname: string, options?: ValidateOptions): boolean;

export declare function parseIpv4(host: string): string | null;
export declare function parseIpv6(host: string): number[] | null;
export declare function normalizeIp(host: string): string | null;
export declare function classifyIp(host: string): string;
export declare function mappedIpv4(groups: readonly number[] | null): string | null;
export declare function sixToFourIpv4(groups: readonly number[] | null): string | null;
export declare function nat64Ipv4(groups: readonly number[] | null): string | null;
export declare function isNat64LocalUse(groups: readonly number[] | null): boolean;
export declare function ipv4CompatibleIpv4(groups: readonly number[] | null): string | null;
export declare function siitIpv4(groups: readonly number[] | null): string | null;
export declare function isTeredo(groups: readonly number[] | null): boolean;
export declare function teredoClientIpv4(groups: readonly number[] | null): string | null;
export declare function formatIpv6(groups: readonly number[]): string | null;
export declare function ipv4ToUint32(ip: string): number | null;
export declare function parseCidr(cidr: string): unknown;
export declare function cidrContains(cidr: string, address: string): boolean;

declare const ssrfcage: {
  readonly VERSION: typeof VERSION;
  readonly auditUrl: typeof auditUrl;
  readonly auditIp: typeof auditIp;
  readonly auditResolvedTarget: typeof auditResolvedTarget;
  readonly auditRedirectChain: typeof auditRedirectChain;
  readonly createSafeFetchGuard: typeof createSafeFetchGuard;
  readonly normalizeHost: typeof normalizeHost;
};
export default ssrfcage;
