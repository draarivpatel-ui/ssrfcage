import { auditIp, auditUrl, normalizeHost } from '../src/index.mjs';

for (const input of ['https://example.com/', 'https://2130706433/', 'https://[::ffff:127.0.0.1]/']) {
  const result = auditUrl(input);
  console.log(input, result.ok ? 'allow' : 'block', result.ok ? result.hostname : result.code);
}
console.log('normalized', normalizeHost('0177.0.0.1'));
console.log('ip audit', auditIp('169.254.169.254'));
