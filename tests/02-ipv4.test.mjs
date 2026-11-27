import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyIp, parseIpv4, normalizeIp, validateUrl } from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:'] };

test('parseIpv4 canonical forms', () => {
  assert.equal(parseIpv4('127.0.0.1'), '127.0.0.1');
  assert.equal(parseIpv4('8.8.8.8'), '8.8.8.8');
  assert.equal(parseIpv4('1.2.3.4'), '1.2.3.4');
  assert.equal(parseIpv4('0.0.0.0'), '0.0.0.0');
});

test('parseIpv4 decimal integer forms', () => {
  assert.equal(parseIpv4('2130706433'), '127.0.0.1');
  assert.equal(parseIpv4('3232235777'), '192.168.1.1');
  assert.equal(parseIpv4('0'), '0.0.0.0');
  assert.equal(parseIpv4('4294967295'), '255.255.255.255');
  assert.equal(parseIpv4('4294967296'), null);
  assert.equal(parseIpv4('-1'), null);
});

test('parseIpv4 hex forms', () => {
  assert.equal(parseIpv4('0x7f000001'), '127.0.0.1');
  assert.equal(parseIpv4('0X7F000001'), '127.0.0.1');
  assert.equal(parseIpv4('0x7f.1'), '127.0.0.1');
  assert.equal(parseIpv4('0xc0a80101'), '192.168.1.1');
});

test('parseIpv4 octal forms', () => {
  assert.equal(parseIpv4('0177.0.0.1'), '127.0.0.1');
  assert.equal(parseIpv4('0o177.0.0.1'), '127.0.0.1');
  assert.equal(parseIpv4('0b1111111000000000000000000000001'), '127.0.0.1');
  assert.equal(parseIpv4('010.0.0.1'), '8.0.0.1');
});

test('parseIpv4 shorthand forms', () => {
  assert.equal(parseIpv4('127.1'), '127.0.0.1');
  assert.equal(parseIpv4('127.0.1'), '127.0.0.1');
  assert.equal(parseIpv4('10.1'), '10.0.0.1');
  assert.equal(parseIpv4('192.168.1'), '192.168.0.1');
});

test('parseIpv4 rejects invalid forms', () => {
  for (const bad of ['256.1.1.1', '1.2.3.4.5', '1..2', 'abc', '', '1.2.3.-1', '0xGG']) {
    assert.equal(parseIpv4(bad), null, bad);
  }
});

test('classifyIp private IPv4 ranges', () => {
  const expectations = {
    '127.0.0.1': 'loopback', '127.1': 'loopback', '2130706433': 'loopback',
    '0177.0.0.1': 'loopback', '0x7f000001': 'loopback',
    '10.0.0.1': 'private-10', '172.16.0.1': 'private-172',
    '172.31.255.255': 'private-172', '192.168.1.1': 'private-192',
    '169.254.169.254': 'cloud-metadata', '169.254.1.1': 'link-local',
    '100.64.0.1': 'cgnat', '100.127.255.254': 'cgnat',
    '100.100.100.200': 'alibaba-metadata',
    '224.0.0.1': 'multicast', '239.255.255.255': 'multicast',
    '198.18.0.1': 'benchmark', '192.0.2.1': 'documentation-1',
    '198.51.100.1': 'documentation-2', '203.0.113.1': 'documentation-3',
    '0.0.0.0': 'unspecified', '255.255.255.255': 'broadcast',
    '240.0.0.1': 'blackhole-240',
    '8.8.8.8': 'public', '1.1.1.1': 'public',
  };
  for (const [ip, expected] of Object.entries(expectations)) {
    assert.equal(classifyIp(ip), expected, ip);
  }
});

test('classifyIp rejects invalid addresses', () => {
  assert.equal(classifyIp('not-an-ip'), 'invalid');
  assert.equal(classifyIp(''), 'invalid');
  assert.equal(classifyIp('256.1.1.1'), 'invalid');
});

test('normalizeIp canonicalizes odd IPv4 forms', () => {
  assert.equal(normalizeIp('2130706433'), '127.0.0.1');
  assert.equal(normalizeIp('0177.0.0.1'), '127.0.0.1');
  assert.equal(normalizeIp('0x7f000001'), '127.0.0.1');
  assert.equal(normalizeIp('127.1'), '127.0.0.1');
  assert.equal(normalizeIp('example.com'), null);
});

test('validateUrl blocks all odd IPv4 representations', () => {
  for (const url of [
    'http://2130706433/', 'http://0177.0.0.1/', 'http://0x7f000001/',
    'http://127.1/', 'http://0/', 'http://10.0.0.1/', 'http://169.254.169.254/',
    'http://100.100.100.200/', 'http://100.64.0.1/', 'http://192.0.2.1/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'PRIVATE_IP', url);
  }
});

test('leading-zero forms are decoded consistently, never smuggled past policy', () => {
  // Octal 0177.0.0.1 is 127.0.0.1 and must be blocked.
  assert.equal(classifyIp('127.000.000.001'), 'loopback');
  assert.equal(classifyIp('0177.0.0.1'), 'loopback');
  // WHATWG normalizes these consistently: 127.000.000.001 -> 127.0.0.1, blocked.
  assert.equal(validateUrl('http://127.000.000.001/', HTTP).code, 'PRIVATE_IP');
  assert.equal(validateUrl('http://0177.0.0.1/', HTTP).code, 'PRIVATE_IP');
  // 00127.0.0.1 is octal 87.0.0.1 (public); it decodes identically in both parsers.
  assert.equal(validateUrl('http://00127.0.0.1/', HTTP).ok, true);
});

// Deterministic IPv4 mutation table. Each row is [input, expected parseIpv4 result].
// null means the input is rejected. Rows agree with the WHATWG URL host parser
// except where noted: ssrfcage fails closed on overlong tokens, trailing dots and
// non-ASCII separators, and also decodes 0o/0b prefixes so they cannot be smuggled.
const IPV4_MUTATIONS = [
  // Decimal dotted and integer forms.
  ['127.0.0.1', '127.0.0.1'],
  ['2130706433', '127.0.0.1'],
  ['0', '0.0.0.0'],
  ['4294967295', '255.255.255.255'],
  ['4294967296', null],
  ['9999999999999999999', null],
  ['256.0.0.1', null],
  ['1.2.3.256', null],
  ['+1.0.0.1', null],
  ['1e2.0.0.1', null],
  // Octal: a leading 0 selects base 8 in every part.
  ['0177.0.0.1', '127.0.0.1'],
  ['0127.0.0.1', '87.0.0.1'],
  ['017700000001', '127.0.0.1'],
  ['02130706433', '17.99.141.27'],
  ['037777777777', '255.255.255.255'],
  ['040000000000', null],
  ['00', '0.0.0.0'],
  ['127.0.0.01', '127.0.0.1'],
  ['127.0.0.001', '127.0.0.1'],
  ['0o177.0.0.1', '127.0.0.1'],
  // Leading-zero parts with 8 or 9 are invalid octal, never decimal.
  ['09', null],
  ['08.0.0.1', null],
  ['127.0.0.08', null],
  ['127.0.0.09', null],
  ['0169.254.169.254', null],
  ['00000000004294967295', null],
  // Hexadecimal.
  ['0x7f000001', '127.0.0.1'],
  ['0X7F000001', '127.0.0.1'],
  ['0x7f.0.0.1', '127.0.0.1'],
  ['0x7F.0x0.0x0.0x1', '127.0.0.1'],
  ['127.0.0.0x1', '127.0.0.1'],
  ['0xff.0xff.0xff.0xff', '255.255.255.255'],
  ['0x0000000000000000000000000000ff', '0.0.0.255'],
  ['0x100.0.0.1', null],
  ['0x100000000', null],
  ['0x', null],
  ['0x.0.0.1', null],
  ['00x7f.0.0.1', null],
  ['0x0x7f.0.0.1', null],
  ['0xGG', null],
  ['0x7f.0.0.1a', null],
  // Binary.
  ['0b1.0.0.1', '1.0.0.1'],
  ['0b1111111000000000000000000000001', '127.0.0.1'],
  // Shorthand forms: the final part fills the remaining bits.
  ['127.1', '127.0.0.1'],
  ['127.0.1', '127.0.0.1'],
  ['127.0x0.1', '127.0.0.1'],
  ['127.16777215', '127.255.255.255'],
  ['127.16777216', null],
  ['127.0.65535', '127.0.255.255'],
  ['127.0.65536', null],
  // Overlong digit runs are rejected rather than truncated.
  ['0000000000000000000000177.0.0.1', null],
  ['0x00000000000000000000007f.0.0.1', null],
  ['000000000000000000000000000000000000000000000000000127.1', null],
  // Mixed and malformed separators.
  ['1.2.3.4.5', null],
  ['127..1', null],
  ['.127.0.0.1', null],
  ['127.1.', null],
  ['127.0.0.1.', null],
  ['127.0.0.1..', null],
  ['127,0,0,1', null],
  ['127:0:0:1', null],
  ['127.0.0.1/8', null],
  ['127。0。0。1', null],
  ['127．0．0．1', null],
  [' 1.0.0.1', null],
  ['1.0.0.1 ', null],
  ['127.0.0.1%25eth0', null],
];

test('parseIpv4 mutation table', () => {
  for (const [input, expected] of IPV4_MUTATIONS) {
    assert.equal(parseIpv4(input), expected, JSON.stringify(input));
  }
});

test('classifyIp and normalizeIp reject invalid leading-zero decimal parts', () => {
  for (const input of ['09', '127.0.0.08', '0169.254.169.254', '010.0.0.09']) {
    assert.equal(normalizeIp(input), null, input);
    assert.equal(classifyIp(input), 'invalid', input);
  }
});
