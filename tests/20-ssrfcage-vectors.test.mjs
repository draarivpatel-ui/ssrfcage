import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditIp,
  auditRedirectChain,
  auditResolvedTarget,
  auditUrl,
  normalizeHost,
} from '../src/index.mjs';

function rejectUrlTest(name, url, options) {
  test(name, () => {
    const result = auditUrl(url, options);
    assert.equal(result.ok, false, url + ' was accepted as ' + JSON.stringify(result));
  });
}

const badIpv4 = [
  '0.0.0.0', '0.1.2.3', '10.0.0.1', '10.1', '10.255.255.255', '100.64.0.1', '100.127.255.255',
  '127.0.0.1', '127.1', '127.0.1', '127.255.255.255', '169.254.0.1', '169.254.169.254',
  '169.254.170.2', '172.16.0.1', '172.31.255.255', '192.0.0.1', '192.0.2.1', '192.31.196.1',
  '192.52.193.1', '192.88.99.1', '192.168.0.1', '192.168.255.255', '192.175.48.1',
  '198.18.0.1', '198.19.255.255', '198.51.100.1', '203.0.113.1', '224.0.0.1',
  '239.255.255.255', '240.0.0.1', '255.255.255.255', '100.100.100.200', '168.63.129.16',
];
const obfuscatedLoopback = [
  '2130706433', '0x7f000001', '0x7f.0.0.1', '0X7F.0.0.1', '0177.0.0.1', '0177.1',
  '127.0.0.1.', '127.1.', '2130706433.', '0x7f000001.',
];
const badIpv4Urls = [];
for (const host of badIpv4.concat(obfuscatedLoopback)) {
  badIpv4Urls.push('https://' + host + '/');
  badIpv4Urls.push('https://' + host + ':443/');
  badIpv4Urls.push('https://' + host + '/admin?x=1');
}
badIpv4Urls.forEach((url, index) => rejectUrlTest('ipv4 special or obfuscated vector ' + index, url));

const badIpv6 = [
  '[::]', '[::1]', '[::ffff:127.0.0.1]', '[::ffff:7f00:1]', '[::127.0.0.1]',
  '[::ffff:8.8.8.8]', '[::ffff:0:127.0.0.1]', '[64:ff9b::169.254.169.254]',
  '[64:ff9b::7f00:1]', '[64:ff9b::808:808]', '[64:ff9b:1::1]', '[2002:7f00:0001::]',
  '[2002:a9fe:a9fe::]', '[2001:0:4136:e378:8000:63bf:3fff:fdd2]', '[fe80::1]',
  '[fe80::1%25eth0]', '[fc00::1]', '[fd00::1]', '[fd00:ec2::254]', '[ff02::1]',
  '[100::1]', '[100:0:0:1::]', '[2001:db8::1]', '[3fff::1]', '[5f00::1]',
  '[2001:2::1]', '[2001:3::1]', '[2001:10::1]', '[2001:20::1]', '[2001:30::1]',
];
for (const host of badIpv6) {
  rejectUrlTest('ipv6 special vector compressed ' + host, 'https://' + host + '/');
  rejectUrlTest('ipv6 special vector explicit port ' + host, 'https://' + host + ':443/');
}

const badAuthorityAndScheme = [];
for (const scheme of ['http', 'file', 'gopher', 'dict', 'ftp', 'data', 'javascript', 'ws', 'ssh']) {
  badAuthorityAndScheme.push(scheme + '://example.com/');
}
for (const suffix of [':1', ':22', ':80', ':444', ':8080', ':65535']) {
  badAuthorityAndScheme.push('https://example.com' + suffix + '/');
  badAuthorityAndScheme.push('https://93.184.216.34' + suffix + '/');
}
badAuthorityAndScheme.push(
  'https://user@example.com/', 'https://user:pass@example.com/', 'https://safe.example@127.0.0.1/',
  'https://127.0.0.1@safe.example/', 'https://127.0.0.1\\@safe.example/', 'https://safe.example\\@127.0.0.1/',
  'https://example.com\\@127.0.0.1/',
  'https://example.com:0/', 'https://example.com:65536/', 'https://example.com:/',
  'https:///example.com/', 'https://', '//example.com/', 'https:example.com', 'https:// example.com/',
  'https://example.com /', ' https://example.com/', 'https://localhost/', 'https://localhost./',
  'https://metadata.google.internal/', 'https://metadata.google.internal./', 'https://service.internal/',
  'https://host.local/', 'https://host.localhost/', 'https://host.home.arpa/', 'https://host.onion/'
);
badAuthorityAndScheme.forEach((url, index) => rejectUrlTest('scheme authority port vector ' + index, url));

const normalizeCases = [
  ['EXAMPLE.COM.', 'example.com'], ['example.com', 'example.com'], ['2130706433', '127.0.0.1'],
  ['0x7f000001', '127.0.0.1'], ['0177.0.0.1', '127.0.0.1'], ['127.1', '127.0.0.1'],
  ['[::1]', '::1'], ['::FFFF:7F00:1', '::ffff:7f00:1'], ['a-b.example-site.com.', 'a-b.example-site.com'],
];
normalizeCases.forEach(([input, expected], index) => {
  test('normalizeHost valid vector ' + index, () => {
    assert.equal(normalizeHost(input), expected);
  });
});
const badNormalize = [
  '', ' ', 'example.com ', ' example.com', 'exa mple.com', 'example..com', '.example.com', 'example.com..',
  'example_com', '-example.com', 'example-.com', 'ex_ample.com', 'example%.com', 'example\\com',
  '[::1', '::1]', ':::', '999.999.999.999', 'example..', 'bücher.example', 'xn--bcher-kva.example',
];
badNormalize.forEach((input, index) => {
  test('normalizeHost invalid vector ' + index, () => {
    assert.equal(normalizeHost(input), null);
  });
});

const publicIp = '93.184.216.34';
const resolvedBadIps = badIpv4.slice(0, 32).concat(['::1', 'fe80::1', 'fc00::1', 'fd00:ec2::254', '::ffff:127.0.0.1']);
resolvedBadIps.forEach((ip, index) => {
  test('auditResolvedTarget rejects nonpublic resolved ip ' + index, () => {
    const result = auditResolvedTarget('https://example.com/', [publicIp, ip]);
    assert.equal(result.ok, false, ip);
  });
});
for (let index = 0; index < 20; index += 1) {
  test('auditResolvedTarget valid pinning vector ' + index, () => {
    const second = '93.184.216.' + String(35 + index);
    const result = auditResolvedTarget('https://example.com/', [publicIp, second], { pinnedIp: publicIp });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.everyResolvedIpVerified, true);
  });
}
const malformedResolutions = [
  [], null, undefined, [''], ['not-an-ip'], [null], [{}], [{ address: '' }], [1], [[]],
];
malformedResolutions.forEach((value, index) => {
  test('auditResolvedTarget malformed resolution vector ' + index, () => {
    assert.equal(auditResolvedTarget('https://example.com/', value).ok, false);
  });
});
for (const [name, options] of [
  ['missing pin', { pinnedIp: '8.8.8.8' }],
  ['changed previous answer', { previousIps: ['8.8.8.8'] }],
  ['deny cidr', { denyCidrs: ['93.184.216.0/24'] }],
  ['outside allow cidr', { allowCidrs: ['8.8.8.0/24'] }],
]) {
  test('auditResolvedTarget policy failure ' + name, () => {
    assert.equal(auditResolvedTarget('https://example.com/', [publicIp], options).ok, false);
  });
}
test('auditResolvedTarget enforces literal pinning', () => {
  assert.equal(auditResolvedTarget('https://93.184.216.34/', ['8.8.8.8']).ok, false);
  assert.equal(auditResolvedTarget('https://93.184.216.34/', ['93.184.216.34']).ok, true);
});

const ipAuditInputs = badIpv4.slice(0, 30).concat(badIpv6.map((item) => item.replace(/^\[|\]$/g, '')).slice(0, 24));
ipAuditInputs.forEach((input, index) => {
  test('auditIp rejects special ip vector ' + index, () => {
    assert.equal(auditIp(input).ok, false, input);
  });
});
for (const input of [publicIp, '8.8.8.8', '2606:4700:4700::1111']) {
  test('auditIp accepts public ip ' + input, () => {
    assert.equal(auditIp(input).ok, true);
  });
}

for (let length = 2; length <= 10; length += 1) {
  test('redirect max hop vector ' + length, async () => {
    const chain = Array.from({ length }, (_item, index) => 'https://example.com/' + index);
    const result = await auditRedirectChain(chain, { maxRedirects: 1 });
    assert.equal(result.ok, length - 1 <= 1);
  });
}
for (let index = 0; index < 20; index += 1) {
  test('redirect downgrade vector ' + index, async () => {
    const result = await auditRedirectChain(['https://example.com/' + index, 'http://example.com/' + index], { allowedSchemes: ['https:', 'http:'] });
    assert.equal(result.ok, false);
    assert.equal(result.code, 'SCHEME_DOWNGRADE');
  });
}
for (let index = 0; index < 15; index += 1) {
  test('redirect loop vector ' + index, async () => {
    const result = await auditRedirectChain(['https://example.com/a' + index, 'https://example.com/a' + index]);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'REDIRECT_LOOP');
  });
}
for (let index = 0; index < 15; index += 1) {
  test('redirect cross origin header strip vector ' + index, async () => {
    const result = await auditRedirectChain(['https://example.com/a' + index, 'https://public.example.net/b' + index], {
      headers: { Authorization: 'secret', Cookie: 'secret', 'X-Api-Key': 'secret', 'X-Normal': 'keep' },
    });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(result.hops[1].strippedHeaders.sort(), ['authorization', 'cookie', 'x-api-key']);
    assert.equal(JSON.stringify(result).includes('secret'), false);
  });
}
