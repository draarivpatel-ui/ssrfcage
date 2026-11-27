// Cross-platform CLI smoke test. Uses spawnSync with shell disabled.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'bin', 'ssrfcage.mjs');

function run(args, expectedStatus) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  });
  assert.equal(result.error, undefined, result.error && result.error.message);
  assert.equal(
    result.status,
    expectedStatus,
    `ssrfcage ${args.join(' ')} exited ${result.status}: ${result.stderr || result.stdout}`,
  );
  assert.equal(result.stderr.includes('/Users/'), false);
  return result.stdout;
}

assert.match(run(['--version'], 0), /^ssrfcage 1\.0\.0\n?$/);
assert.match(run(['audit-url', 'https://example.com/'], 0), /"ok": true/);
assert.match(run(['audit-url', 'https://127.0.0.1/'], 1), /"code": "PRIVATE_IP"/);
assert.match(run(['audit-ip', '169.254.169.254'], 1), /"ok": false/);
assert.match(run(['normalize-host', 'Example.COM.'], 0), /"normalized": "example.com"/);
assert.match(run(['audit-resolved', 'https://example.com/', '93.184.216.34'], 0), /"ok": true/);
assert.match(run(['audit-chain', 'https://example.com/', 'https://example.com/final'], 0), /"ok": true/);
assert.match(run([], 2), /^$/);

console.log('cli smoke tests passed');
