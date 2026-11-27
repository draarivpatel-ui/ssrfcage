import { auditRedirectChain } from '../src/index.mjs';

const chain = await auditRedirectChain([
  'https://example.com/start',
  'https://example.com/final',
], {
  headers: { Authorization: 'example-secret', 'X-Normal': 'kept' },
});
console.log('chain ok', chain.ok, 'hops', chain.hops.length);
const downgrade = await auditRedirectChain([
  'https://example.com/start',
  'http://example.com/final',
], { allowedSchemes: ['https:', 'http:'] });
console.log('downgrade blocked', downgrade.ok === false, downgrade.code);
