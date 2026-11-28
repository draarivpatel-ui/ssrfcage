import test from 'node:test';
import assert from 'node:assert/strict';
import { validateUrl, isPublicHostname, createGuard, normalizeHost } from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };

test('rejects backslash separators', () => {
  for (const url of [
    'https://example.com\\@evil.com/', 'https://example.com\\evil/',
    'http:\\\\example.com/', 'https://user\\@example.com/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'INVALID_URL', url);
  }
});

test('rejects userinfo and credentials', () => {
  for (const url of [
    'https://user:pass@example.com/', 'https://user@example.com/',
    'https://good.com@evil.com/', 'https://a:b:c@example.com/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'USERINFO_FORBIDDEN', url);
  }
});

test('allowUserinfo opt-in works', () => {
  assert.equal(validateUrl('https://user:pass@example.com/', { ...HTTP, allowUserinfo: true }).ok, true);
});

test('rejects encoded host characters', () => {
  assert.equal(validateUrl('https://example%2ecom/', HTTP).code, 'INVALID_URL');
  assert.equal(validateUrl('https://example.com%2f.evil.com/', HTTP).code, 'INVALID_URL');
});

test('rejects unicode hostnames by default, allows opt-in', () => {
  assert.equal(validateUrl('https://例え.テスト/', HTTP).code, 'UNSUPPORTED_IDNA');
  assert.equal(validateUrl('https://例え.テスト/', { ...HTTP, idna: 'allow-unicode' }).ok, true);
});

test('trailing dot in hostname is accepted and normalized', () => {
  assert.equal(validateUrl('https://example.com./', HTTP).ok, true);
});

test('empty host is rejected', () => {
  assert.equal(validateUrl('https:///path', HTTP).ok, false);
});

test('oversized hostname and labels are rejected', () => {
  const longLabel = `https://${'a'.repeat(64)}.com/`;
  assert.equal(validateUrl(longLabel, HTTP).code, 'INVALID_URL');
  const longHost = `https://${'a.'.repeat(140)}com/`;
  assert.equal(validateUrl(longHost, HTTP).code, 'INVALID_URL');
});

test('localhost and metadata hostnames are denied', () => {
  for (const host of [
    'localhost', 'metadata', 'metadata.google.internal', 'metadata.goog',
    'metadata.azure.com', 'instance-data', 'foo.internal', 'foo.localhost',
    'foo.local', 'foo.home.arpa',
  ]) {
    assert.equal(validateUrl(`https://${host}/`, HTTP).code, 'HOST_DENIED', host);
  }
});

test('single-label DNS hostnames are denied by default', () => {
  for (const host of ['intranet', 'router', 'nas', 'local', 'internal']) {
    assert.equal(validateUrl(`https://${host}/`, HTTP).code, 'HOST_DENIED', host);
    assert.equal(validateUrl(`https://${host}./`, HTTP).code, 'HOST_DENIED', `${host}.`);
    assert.equal(isPublicHostname(host, HTTP), false, host);
  }
  assert.equal(validateUrl('https://example.com/', HTTP).ok, true);
  assert.equal(validateUrl('https://sub.example.com/', HTTP).ok, true);
  assert.equal(isPublicHostname('example.com', HTTP), true);
});

test('single-label DNS hostnames allow only explicit opt-ins', () => {
  const optedIn = { ...HTTP, allowSingleLabelHostnames: true };
  assert.equal(validateUrl('https://intranet/', optedIn).ok, true);
  assert.equal(isPublicHostname('router', optedIn), true);

  const allowlisted = { ...HTTP, hostPolicy: { allow: ['intranet'] } };
  assert.equal(validateUrl('https://intranet/', allowlisted).ok, true);
  assert.equal(validateUrl('https://router/', allowlisted).code, 'HOST_NOT_ALLOWED');
  assert.equal(isPublicHostname('intranet', allowlisted), true);

  const localhostAllowed = { ...HTTP, hostPolicy: { allow: ['localhost'] } };
  assert.equal(validateUrl('https://localhost/', localhostAllowed).code, 'HOST_DENIED');
});

test('mixed single-label and domain allowlists are order independent', () => {
  for (const allow of [
    ['intranet', 'api.example.com'],
    ['api.example.com', 'intranet'],
  ]) {
    const opts = { ...HTTP, hostPolicy: { allow } };
    const order = allow.join(',');
    assert.equal(validateUrl('https://intranet/', opts).ok, true, order);
    assert.equal(validateUrl('https://api.example.com/', opts).ok, true, order);
    assert.equal(validateUrl('https://intranet./', opts).ok, true, order);
    assert.equal(validateUrl('https://api.example.com./', opts).ok, true, order);
    assert.equal(isPublicHostname('intranet', opts), true, order);
    assert.equal(isPublicHostname('api.example.com', opts), true, order);
    assert.equal(isPublicHostname('intranet.', opts), true, order);
    assert.equal(isPublicHostname('api.example.com.', opts), true, order);
    assert.equal(validateUrl('https://router/', opts).code, 'HOST_NOT_ALLOWED', order);
    assert.equal(isPublicHostname('router', opts), false, order);
  }
});

test('multiple single-label allowlist entries are order independent', () => {
  for (const allow of [
    ['intranet', 'router'],
    ['router', 'intranet'],
  ]) {
    const opts = { ...HTTP, hostPolicy: { allow } };
    const order = allow.join(',');
    assert.equal(validateUrl('https://intranet/', opts).ok, true, order);
    assert.equal(validateUrl('https://router/', opts).ok, true, order);
    assert.equal(isPublicHostname('intranet', opts), true, order);
    assert.equal(isPublicHostname('router', opts), true, order);
    assert.equal(validateUrl('https://nas/', opts).code, 'HOST_NOT_ALLOWED', order);
    assert.equal(isPublicHostname('nas', opts), false, order);
  }
});

test('allowlist pattern spelling is canonicalized consistently', () => {
  const domainOpts = { ...HTTP, hostPolicy: { allow: ['  API.EXAMPLE.COM.  '] } };
  assert.equal(validateUrl('https://api.example.com/', domainOpts).ok, true);
  assert.equal(validateUrl('https://api.example.com./', domainOpts).ok, true);
  assert.equal(isPublicHostname('api.example.com.', domainOpts), true);

  for (const pattern of ['INTRANET.', '  intranet.  ']) {
    const opts = { ...HTTP, hostPolicy: { allow: [pattern] } };
    assert.equal(validateUrl('https://intranet/', opts).ok, true, pattern);
    assert.equal(validateUrl('https://intranet./', opts).ok, true, pattern);
    assert.equal(isPublicHostname('intranet.', opts), true, pattern);
    assert.equal(validateUrl('https://sub.intranet/', opts).code, 'HOST_NOT_ALLOWED', pattern);
    assert.equal(isPublicHostname('sub.intranet', opts), false, pattern);
  }
});

test('allowlist patterns canonicalize IDNA and punycode spellings', () => {
  const unicodeHost = '例え.テスト';
  const punycodeHost = 'xn--r8jz45g.xn--zckzah';
  for (const pattern of [unicodeHost, punycodeHost]) {
    const opts = { ...HTTP, idna: 'allow-unicode', hostPolicy: { allow: [pattern] } };
    assert.equal(validateUrl(`https://${unicodeHost}/`, opts).ok, true, pattern);
    assert.equal(validateUrl(`https://${punycodeHost}/`, opts).ok, true, pattern);
    assert.equal(isPublicHostname(punycodeHost, opts), true, pattern);
  }
});

test('denylist patterns canonicalize IDNA and punycode spellings', () => {
  const unicodeHost = '例え.テスト';
  const punycodeHost = 'xn--r8jz45g.xn--zckzah';
  for (const pattern of [unicodeHost, punycodeHost]) {
    const opts = { ...HTTP, idna: 'allow-unicode', hostPolicy: { deny: [pattern] } };
    assert.equal(validateUrl(`https://${unicodeHost}/`, opts).code, 'HOST_DENIED', pattern);
    assert.equal(validateUrl(`https://${punycodeHost}/`, opts).code, 'HOST_DENIED', pattern);
    assert.equal(isPublicHostname(punycodeHost, opts), false, pattern);
  }
});

test('IDNA caller denies outrank matching allows', () => {
  const unicodeHost = '例え.テスト';
  const punycodeHost = 'xn--r8jz45g.xn--zckzah';
  const opts = {
    ...HTTP,
    idna: 'allow-unicode',
    hostPolicy: { allow: [unicodeHost], deny: [unicodeHost] },
  };
  assert.equal(validateUrl(`https://${unicodeHost}/`, opts).code, 'HOST_DENIED');
  assert.equal(validateUrl(`https://${punycodeHost}/`, opts).code, 'HOST_DENIED');
  assert.equal(isPublicHostname(punycodeHost, opts), false);
});

test('hex-letter DNS labels are not mistaken for IP literals', () => {
  for (const host of ['db', 'de', 'ca', 'be', 'deadbeef', 'cafe', 'abc123', '123abc', 'x', 'xxxx']) {
    assert.equal(normalizeHost(host), host, host);
  }

  const exactDb = { ...HTTP, hostPolicy: { allow: ['db'] } };
  assert.equal(validateUrl('https://db/', exactDb).ok, true);
  assert.equal(isPublicHostname('db', exactDb), true);

  for (const suffix of ['de', 'ca', 'be']) {
    const exactOnly = { ...HTTP, hostPolicy: { allow: [`example.${suffix}`] } };
    assert.equal(validateUrl(`https://example.${suffix}/`, exactOnly).ok, true, suffix);
  }
});

test('hex-letter public suffixes still trigger the broad suffix guard', () => {
  for (const suffix of ['de', 'ca', 'be']) {
    for (const allow of [
      [suffix, `example.${suffix}`],
      [`example.${suffix}`, suffix],
    ]) {
      const opts = { ...HTTP, hostPolicy: { allow } };
      const order = allow.join(',');
      assert.equal(validateUrl(`https://example.${suffix}/`, opts).code, 'HOST_NOT_ALLOWED', order);
      assert.equal(isPublicHostname(`example.${suffix}`, opts), false, order);
    }
  }
});

test('invalid numeric-looking hosts stay rejected without swallowing DNS labels', () => {
  for (const host of [
    '999.999.999.999', '1.2.3.4.5', '4294967296', '0x100000000',
    'abc.4294967296', 'beef.123', '1.2.abc.4',
  ]) {
    assert.equal(normalizeHost(host), null, host);
  }
  for (const host of ['db', 'de', 'ca', 'be', 'deadbeef', 'cafe', 'abc123', '123abc', 'x', 'xxxx']) {
    assert.equal(normalizeHost(host), host, host);
  }
});

test('host patterns enforce one root dot after IDNA dot folding', () => {
  for (const pattern of ['api.example.com.', 'api.example.com。', 'api.example.com．', 'api.example.com｡']) {
    const opts = { ...HTTP, hostPolicy: { allow: [pattern] } };
    assert.equal(validateUrl('https://api.example.com/', opts).ok, true, pattern);
    assert.equal(isPublicHostname('api.example.com', opts), true, pattern);
  }

  for (const pattern of [
    'api.example.com..', 'api.example.com。。', 'api.example.com．．', 'api.example.com｡｡',
    'api.example.com.。', 'api.example.com。.', 'api.example.com．。', 'api.example.com｡．',
  ]) {
    const opts = { ...HTTP, hostPolicy: { allow: [pattern] } };
    assert.equal(validateUrl('https://api.example.com/', opts).code, 'HOST_NOT_ALLOWED', pattern);
    assert.equal(isPublicHostname('api.example.com', opts), false, pattern);
  }
});

test('host patterns recheck root dots after IDNA drops ignored characters', () => {
  for (const pattern of [
    'api.example.com.\u00ad.',
    'api.example.com.\u200b.',
    'api.example.com\uff0e\u00ad.',
    'api.example.com.\u00ad\uff0e',
    'api.example.com\uff0e.',
    'api.example.com.\uff0e',
  ]) {
    const opts = { ...HTTP, hostPolicy: { allow: [pattern] } };
    assert.equal(validateUrl('https://api.example.com/', opts).code, 'HOST_NOT_ALLOWED', pattern);
    assert.equal(isPublicHostname('api.example.com', opts), false, pattern);
  }
});

test('isPublicHostname enforces the single root dot limit', () => {
  assert.equal(isPublicHostname('example.com.', HTTP), true);
  assert.equal(isPublicHostname('example.com..', HTTP), false);
  assert.equal(isPublicHostname('example.com...', HTTP), false);
});

test('root trailing dot is not counted in host pattern length', () => {
  const longLabel = 'a'.repeat(63);
  const finalLabel = 'a'.repeat(61);
  const host253 = `${longLabel}.${longLabel}.${longLabel}.${finalLabel}`;
  assert.equal(host253.length, 253);
  for (const pattern of [`${host253}.`, `${host253}。`]) {
    const opts = { ...HTTP, hostPolicy: { allow: [pattern] } };
    assert.equal(validateUrl(`https://${host253}/`, opts).ok, true, pattern.slice(-2));
  }
});

test('overbroad public suffix allowlist entries fail closed in either order', () => {
  for (const allow of [
    ['api.example.com', 'com'],
    ['com', 'api.example.com'],
  ]) {
    const opts = { ...HTTP, hostPolicy: { allow } };
    assert.equal(validateUrl('https://api.example.com/', opts).code, 'HOST_NOT_ALLOWED', allow.join(','));
    assert.equal(isPublicHostname('api.example.com', opts), false, allow.join(','));
  }
});

test('bare single-label allowlist entries stay exact-only without suffix opt-in', () => {
  const exactOnly = { ...HTTP, hostPolicy: { allow: ['intranet'] } };
  assert.equal(validateUrl('https://intranet/', exactOnly).ok, true);
  assert.equal(validateUrl('https://sub.intranet/', exactOnly).code, 'HOST_NOT_ALLOWED');
  assert.equal(isPublicHostname('sub.intranet', exactOnly), false);

  const broad = { ...HTTP, hostPolicy: { allow: ['intranet'], allowPublicSuffix: true } };
  assert.equal(validateUrl('https://sub.intranet/', broad).ok, true);
  assert.equal(isPublicHostname('sub.intranet', broad), true);
});

test('built-in denies outrank single-label opt-ins in both APIs', () => {
  const optionSets = [
    { ...HTTP, allowSingleLabelHostnames: true },
    { ...HTTP, hostPolicy: { allow: ['localhost', 'metadata.google.internal'] } },
    {
      ...HTTP,
      allowSingleLabelHostnames: true,
      hostPolicy: { allow: ['localhost', 'metadata.google.internal'] },
    },
  ];
  for (const opts of optionSets) {
    for (const host of ['localhost', 'metadata.google.internal']) {
      assert.equal(validateUrl(`https://${host}/`, opts).code, 'HOST_DENIED', host);
      assert.equal(isPublicHostname(host, opts), false, host);
    }
  }
});

test('caller denies outrank single-label opt-ins in both APIs', () => {
  const optionSets = [
    { ...HTTP, allowSingleLabelHostnames: true, hostPolicy: { deny: ['intranet'] } },
    { ...HTTP, hostPolicy: { allow: ['intranet'], deny: ['intranet'] } },
  ];
  for (const opts of optionSets) {
    assert.equal(validateUrl('https://intranet/', opts).code, 'HOST_DENIED');
    assert.equal(isPublicHostname('intranet', opts), false);
  }
});


test('caller deny rules canonicalize IPv6 literal spellings', () => {
  const compressed = '2606:4700:4700::1111';
  const expanded = '2606:4700:4700:0:0:0:0:1111';
  const spellings = [
    compressed,
    expanded,
    `[${compressed}]`,
    `[${expanded}]`,
    `${compressed}.`,
    `${expanded}.`,
    `[${compressed}].`,
    expanded.toUpperCase(),
  ];
  for (const pattern of spellings) {
    const opts = { ...HTTP, hostPolicy: { deny: [pattern] } };
    for (const target of [compressed, expanded]) {
      assert.equal(validateUrl(`https://[${target}]/`, opts).code, 'HOST_DENIED', pattern);
      assert.equal(isPublicHostname(target, opts), false, pattern);
    }
  }
});

test('caller deny rules preserve underscore labels accepted by target validators', () => {
  assert.equal(validateUrl('https://foo_bar.example.com/', HTTP).ok, true);
  assert.equal(isPublicHostname('foo_bar.example.com', HTTP), true);

  const opts = { ...HTTP, hostPolicy: { deny: ['foo_bar.example.com'] } };
  assert.equal(validateUrl('https://foo_bar.example.com/', opts).code, 'HOST_DENIED');
  assert.equal(isPublicHostname('foo_bar.example.com', opts), false);
});

test('unusable configured allowlists fail closed', () => {
  const invalidOnly = [
    [null],
    [0],
    [{}],
    [null, undefined],
    [''],
    ['   '],
    ['..'],
    ['api.example.com..'],
  ];
  for (const allow of invalidOnly) {
    const opts = { ...HTTP, hostPolicy: { allow } };
    assert.equal(validateUrl('https://example.com/', opts).code, 'HOST_NOT_ALLOWED');
    assert.equal(isPublicHostname('example.com', opts), false);
    const guard = createGuard(opts);
    assert.equal(guard.validate('https://example.com/').code, 'HOST_NOT_ALLOWED');
    assert.equal(guard.isPublicHostname('example.com'), false);
  }

  const mixed = { ...HTTP, hostPolicy: { allow: [null, 'example.com'] } };
  assert.equal(validateUrl('https://example.com/', mixed).ok, true);
  assert.equal(isPublicHostname('example.com', mixed), true);
  assert.equal(validateUrl('https://evil.com/', mixed).code, 'HOST_NOT_ALLOWED');
});

test('default ports are accepted', () => {
  assert.equal(validateUrl('https://example.com:443/', HTTP).ok, true);
  assert.equal(validateUrl('http://example.com:80/', HTTP).ok, true);
  assert.equal(validateUrl('https://example.com:8443/', HTTP).code, 'PORT_FORBIDDEN');
});

test('port 0 and out-of-range ports are rejected', () => {
  assert.equal(validateUrl('http://example.com:0/', HTTP).code, 'PORT_FORBIDDEN');
  assert.equal(validateUrl('http://example.com:65536/', HTTP).ok, false);
});

test('allowedPorts array', () => {
  const opts = { ...HTTP, allowedPorts: [8443] };
  assert.equal(validateUrl('https://example.com:8443/', opts).ok, true);
  assert.equal(validateUrl('https://example.com/', opts).code, 'PORT_FORBIDDEN');
});

test('allowedPorts any', () => {
  const opts = { ...HTTP, allowedPorts: 'any' };
  assert.equal(validateUrl('https://example.com:8443/', opts).ok, true);
});

test('host allow list', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['example.com'] } };
  assert.equal(validateUrl('https://example.com/', opts).ok, true);
  assert.equal(validateUrl('https://sub.example.com/', opts).ok, true);
  assert.equal(validateUrl('https://evil.com/', opts).code, 'HOST_NOT_ALLOWED');
  assert.equal(validateUrl('https://evil-example.com/', opts).code, 'HOST_NOT_ALLOWED');
});

test('host deny takes precedence over allow', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['example.com'], deny: ['admin.example.com'] } };
  assert.equal(validateUrl('https://admin.example.com/', opts).code, 'HOST_DENIED');
});

test('wildcard host patterns', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['*.example.com'] } };
  assert.equal(validateUrl('https://api.example.com/', opts).ok, true);
  assert.equal(validateUrl('https://example.com/', opts).ok, true);
  assert.equal(validateUrl('https://notexample.com/', opts).code, 'HOST_NOT_ALLOWED');
});

test('public suffix allowlist requires explicit opt-in', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['com'] } };
  assert.equal(validateUrl('https://example.com/', opts).code, 'HOST_NOT_ALLOWED');
  const permissive = { ...HTTP, hostPolicy: { allow: ['com'], allowPublicSuffix: true } };
  assert.equal(validateUrl('https://example.com/', permissive).ok, true);
});

test('isPublicHostname checks hostname policy', () => {
  assert.equal(isPublicHostname('example.com', HTTP), true);
  assert.equal(isPublicHostname('127.0.0.1', HTTP), false);
  assert.equal(isPublicHostname('localhost', HTTP), false);
  assert.equal(isPublicHostname('', HTTP), false);
});

test('custom CIDR allow and deny', () => {
  const deny = { ...HTTP, denyCidrs: ['8.8.8.0/24'] };
  assert.equal(validateUrl('https://8.8.8.8/', deny).code, 'HOST_DENIED');
  const allow = { ...HTTP, allowCidrs: ['1.1.1.0/24'] };
  assert.equal(validateUrl('https://1.1.1.1/', allow).ok, true);
  assert.equal(validateUrl('https://8.8.8.8/', allow).code, 'HOST_NOT_ALLOWED');
});

test('createGuard compiles a reusable policy', () => {
  const guard = createGuard({ ...HTTP, hostPolicy: { allow: ['example.com'] } });
  assert.equal(guard.validate('https://example.com/').ok, true);
  assert.throws(() => guard.assert('https://evil.com/'));
  assert.equal(guard.isPublicHostname('example.com'), true);
  assert.equal(Object.isFrozen(guard.options), true);
});
