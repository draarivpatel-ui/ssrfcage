import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import { auditResolvedTarget, validateUrl } from '../src/index.mjs';

const propertyOptions = { seed: 20261127, numRuns: 100 };
const httpsOnly = { allowedSchemes: ['https:'] };
const hostLabel = fc.stringMatching(/^[a-z][a-z0-9]{0,16}$/);
const octet = fc.integer({ min: 0, max: 255 });
const publicOctet = fc.integer({ min: 1, max: 223 }).filter((value) => (
  value !== 10 && value !== 100 && value !== 127 && value !== 169 && value !== 172 && value !== 192 && value !== 198 && value !== 203
));

test('generated benign HTTPS hostnames are accepted without network access', () => {
  fc.assert(
    fc.property(hostLabel, (label) => {
      const input = `https://${label}.example.com/`;
      const result = validateUrl(input, httpsOnly);
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.hostname, `${label}.example.com`);
    }),
    propertyOptions,
  );
});

test('generated public IP literals and matching resolutions are accepted', () => {
  const publicIpv4 = fc.tuple(publicOctet, octet, octet, octet).map((parts) => parts.join('.'));
  fc.assert(
    fc.property(publicIpv4, (ip) => {
      const input = `https://${ip}/`;
      const direct = validateUrl(input, httpsOnly);
      assert.equal(direct.ok, true, JSON.stringify(direct));
      const resolved = auditResolvedTarget(input, [ip], { ...httpsOnly, pinnedIp: ip });
      assert.equal(resolved.ok, true, JSON.stringify(resolved));
      assert.equal(resolved.everyResolvedIpVerified, true);
    }),
    propertyOptions,
  );
});

test('generated private IPv4 literals are always rejected', () => {
  const privateIpv4 = fc.oneof(
    fc.tuple(fc.constant(10), octet, octet, octet),
    fc.tuple(fc.constant(127), octet, octet, octet),
    fc.tuple(fc.constant(169), fc.constant(254), octet, octet),
    fc.tuple(fc.constant(172), fc.integer({ min: 16, max: 31 }), octet, octet),
    fc.tuple(fc.constant(192), fc.constant(168), octet, octet),
  ).map((parts) => parts.join('.'));
  fc.assert(
    fc.property(privateIpv4, (ip) => {
      const result = validateUrl(`https://${ip}/`, httpsOnly);
      assert.equal(result.ok, false, ip);
      assert.equal(result.code, 'PRIVATE_IP');
    }),
    propertyOptions,
  );
});

test('generated non-public DNS answers are rejected during resolution pinning', () => {
  const metadataOctet = octet;
  fc.assert(
    fc.property(metadataOctet, hostLabel, (lastOctet, label) => {
      const input = `https://${label}.example.com/`;
      const result = auditResolvedTarget(input, [`169.254.169.${lastOctet}`], httpsOnly);
      assert.equal(result.ok, false);
      assert.equal(result.code, 'PRIVATE_IP');
    }),
    propertyOptions,
  );
});
