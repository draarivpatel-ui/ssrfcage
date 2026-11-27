#!/usr/bin/env node
import {
  VERSION,
  auditIp,
  auditRedirectChain,
  auditResolvedTarget,
  auditUrl,
  normalizeHost,
} from '../src/index.mjs';

function jsonSafe(value) {
  if (value && typeof value === 'object') {
    const copy = { ...value };
    delete copy.url;
    return copy;
  }
  return value;
}

function write(value) {
  process.stdout.write(JSON.stringify(jsonSafe(value), null, 2) + '\n');
}

function usage() {
  process.stderr.write([
    'usage:',
    '  ssrfcage audit-url <url>',
    '  ssrfcage audit-ip <ip>',
    '  ssrfcage normalize-host <host>',
    '  ssrfcage audit-resolved <url> <ip> [ip...]',
    '  ssrfcage audit-chain <url> [url...]',
    '  ssrfcage --version',
  ].join('\n') + '\n');
}

async function main(argv) {
  const [command, ...args] = argv;
  if (command === '--version') {
    process.stdout.write('ssrfcage ' + VERSION + '\n');
    return 0;
  }
  if (command === 'audit-url' && args.length === 1) {
    const result = auditUrl(args[0]);
    write(result);
    return result.ok ? 0 : 1;
  }
  if (command === 'audit-ip' && args.length === 1) {
    const result = auditIp(args[0]);
    write(result);
    return result.ok ? 0 : 1;
  }
  if (command === 'normalize-host' && args.length === 1) {
    const result = normalizeHost(args[0]);
    if (result === null) {
      write({ ok: false, code: 'INVALID_HOST', normalized: null });
      return 1;
    }
    write({ ok: true, normalized: result });
    return 0;
  }
  if (command === 'audit-resolved' && args.length >= 2) {
    const result = auditResolvedTarget(args[0], args.slice(1));
    write(result);
    return result.ok ? 0 : 1;
  }
  if (command === 'audit-chain' && args.length >= 1) {
    const result = await auditRedirectChain(args);
    write(result);
    return result.ok ? 0 : 1;
  }
  usage();
  return 2;
}

main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
}, (error) => {
  process.stderr.write('ssrfcage: error: ' + (error && error.message ? error.message : 'failed') + '\n');
  process.exitCode = 2;
});
