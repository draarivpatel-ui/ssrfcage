import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditResolvedTarget,
  classifyIp,
  createSafeFetch,
  scanToolArguments,
  validateUrl,
} from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'], dns: false };

function fakeResponse(status, location) {
  return {
    status,
    headers: { get: (name) => name.toLowerCase() === 'location' ? location : null },
  };
}

test('cross-origin redirects strip every credential-shaped header', async () => {
  const calls = [];
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url, init) => {
      calls.push({ url, init });
      return calls.length === 1 ? fakeResponse(307, 'https://other.example/collect') : fakeResponse(200);
    },
  });
  await safeFetch('https://example.com/start', {
    method: 'POST',
    body: 'body-secret',
    headers: {
      Authorization: 'Bearer secret',
      'Proxy-Authorization': 'Basic secret',
      Cookie: 'session=secret',
      Cookie2: 'legacy=secret',
      'X-Api-Key': 'api-secret',
      'X-Auth-Token': 'auth-secret',
      'X-Csrf-Token': 'csrf-secret',
      'X-Xsrf-Token': 'xsrf-secret',
      Referer: 'https://example.com/private',
      'X-Safe': 'keep',
    },
  });
  assert.equal(calls.length, 2);
  for (const call of calls) {
    const headers = new Headers(call.init.headers);
    for (const name of [
      'authorization', 'proxy-authorization', 'cookie', 'cookie2',
      'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token', 'referer',
    ]) {
      assert.equal(headers.get(name), null, `${name} leaked on ${call.url}`);
    }
  }
  const secondHeaders = new Headers(calls[1].init.headers);
  assert.equal(secondHeaders.get('x-safe'), 'keep');
  assert.equal(calls[1].init.body, undefined);
});

test('IETF protocol-assignment IPv6 descendants are not public fallthroughs', () => {
  for (const address of ['2001:1::1', '2001:1::2', '2001:1::3', '2001:4:112::1']) {
    assert.equal(classifyIp(address), 'ietf-protocol', address);
    assert.equal(validateUrl(`https://[${address}]/`, HTTP).ok, false, address);
  }
});

test('newer IANA special IPv6 ranges stay blocked', () => {
  const expected = new Map([
    ['2620:4f:8000::1', 'direct-delegation-as112'],
    ['5f00::1', 'srv6-sids'],
    ['100:0:0:1::1', 'dummy-v6'],
  ]);
  for (const [address, classification] of expected) {
    assert.equal(classifyIp(address), classification, address);
    assert.equal(validateUrl(`https://[${address}]/`, HTTP).ok, false, address);
  }
});

test('scanner reports depth truncation instead of silently incomplete scans', () => {
  const root = {};
  let cursor = root;
  for (let index = 0; index < 8; index += 1) {
    cursor.child = {};
    cursor = cursor.child;
  }
  cursor.url = 'http://127.0.0.1/admin';
  const result = scanToolArguments(root, { ...HTTP, maxDepth: 3 });
  assert.equal(result.truncated, true);
});

test('error redaction removes all userinfo even with repeated at-signs or spaces', () => {
  for (const [input, secret] of [
    ['https://user@pass@127.0.0.1/', 'pass'],
    ['https://user:pa ss@127.0.0.1/', 'user:pa ss'],
  ]) {
    const result = validateUrl(input, HTTP);
    assert.equal(result.ok, false);
    assert.equal(result.input.includes(secret), false, `${input} leaked ${secret} as ${result.input}`);
    assert.equal(result.input.includes('[redacted]@'), true, result.input);
  }
});

test('ISATAP interface identifiers cannot hide private IPv4 payloads', () => {
  for (const address of [
    '2606:4700::5efe:7f00:1',
    '2606:4700::5efe:a9fe:a9fe',
    '2606:4700::200:5efe:808:808',
  ]) {
    assert.notEqual(classifyIp(address), 'public', address);
    assert.equal(validateUrl(`https://[${address}]/`, HTTP).ok, false, address);
  }
  assert.equal(classifyIp('2606:4700::5efe:7f00:1'), 'loopback');
  assert.equal(classifyIp('2606:4700::200:5efe:808:808'), 'isatap');
});

test('malformed non-string pinnedIp values fail closed', () => {
  for (const pinnedIp of [0, {}, [], null, false]) {
    const result = auditResolvedTarget('https://example.com/', ['93.184.216.34'], { ...HTTP, pinnedIp });
    assert.equal(result.ok, false, String(pinnedIp));
    assert.equal(result.code, 'PIN_MISMATCH');
  }
});

test('single-slash special scheme forms cannot bypass raw-authority checks', () => {
  for (const input of [
    'https:/example.com/',
    'https:/example.com:0443/',
    'https:/%65xample.com/',
    'http:/127.0.0.1/',
  ]) {
    const result = validateUrl(input, HTTP);
    assert.equal(result.ok, false, input);
    assert.equal(result.code, 'INVALID_URL');
  }
});
