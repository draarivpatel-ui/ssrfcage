/**
 * Node.js DNS adapter using node:dns/promises. Import only in Node runtimes.
 * Resolves all A and AAAA records as IP strings so every returned address is audited.
 */
export declare function nodeResolve(hostname: string): Promise<string[]>;
export default nodeResolve;
