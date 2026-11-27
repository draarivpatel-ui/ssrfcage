import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const declaration = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
if (/(:|=>)\s*any\b|\bas\s+any\b|\bArray<\s*any\s*>|\bany\s*\[\s*\]/u.test(declaration)) {
  console.error('types/index.d.ts must not use an explicit any type');
  process.exit(1);
}
for (const required of ['auditUrl', 'auditIp', 'auditResolvedTarget', 'auditRedirectChain', 'createSafeFetchGuard', 'normalizeHost']) {
  if (!declaration.includes('function ' + required + '(')) {
    console.error('types/index.d.ts does not declare ' + required);
    process.exit(1);
  }
}

const command = process.platform === 'win32' ? 'tsc.cmd' : 'tsc';
const probe = spawnSync(command, ['--version'], { encoding: 'utf8', shell: false });
if (probe.error || probe.status !== 0) {
  console.log('strict type check skipped: tsc is not installed');
  process.exitCode = 0;
} else {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ssrfcage-types-'));
  try {
    fs.copyFileSync(path.join(root, 'types', 'index.d.ts'), path.join(scratch, 'index.d.ts'));
    fs.writeFileSync(path.join(scratch, 'check.ts'), [
      'import ssrfcage, { auditIp, auditRedirectChain, auditResolvedTarget, auditUrl, createSafeFetchGuard, normalizeHost, VERSION } from "./index";',
      'const url = auditUrl("https://example.com/");',
      'const ip = auditIp("127.0.0.1");',
      'const host: string | null = normalizeHost("EXAMPLE.COM.");',
      'const resolved = auditResolvedTarget("https://example.com/", ["93.184.216.34"], { pinnedIp: "93.184.216.34" });',
      'const version: "1.0.0" = VERSION;',
      'const guard = createSafeFetchGuard({ maxRedirects: 2 });',
      'async function run(): Promise<void> {',
      '  const chain = await auditRedirectChain(["https://example.com/"]);',
      '  if (url.ok) await guard("https://example.com/");',
      '  console.log(ip, host, resolved, chain, version, ssrfcage.VERSION);',
      '}',
      'void run();',
    ].join('\n'), 'utf8');
    const result = spawnSync(command, ['--noEmit', '--strict', '--target', 'es2022', '--module', 'nodenext', '--moduleResolution', 'nodenext', 'check.ts'], { cwd: scratch, encoding: 'utf8', shell: false });
    if (result.status !== 0) {
      process.stderr.write(result.stderr + result.stdout);
      process.exitCode = 1;
    } else {
      console.log('strict type check ok');
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}
