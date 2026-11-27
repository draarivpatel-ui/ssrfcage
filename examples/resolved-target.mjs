import { auditResolvedTarget } from '../src/index.mjs';

const clean = auditResolvedTarget('https://example.com/', ['93.184.216.34'], { pinnedIp: '93.184.216.34' });
console.log('clean resolution', clean.ok, clean.resolvedIps);
const hostile = auditResolvedTarget('https://example.com/', ['93.184.216.34', '169.254.169.254']);
console.log('mixed resolution', hostile.ok, hostile.code);
