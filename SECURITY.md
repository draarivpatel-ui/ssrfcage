# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Please **Privately report** security issues through the repository's [GitHub Security Advisory form](https://github.com/draarivpatel-ui/ssrfcage/security/advisories/new). Do not open a public issue for an exploitable defect.

Include:

1. The affected version and module format (ESM or CommonJS).
2. A minimal proof of concept URL or payload.
3. The expected versus observed validation result.
4. Any DNS resolver configuration used.

## Response SLA

- Acknowledgement: within 48 hours.
- Initial assessment: within 5 business days.
- Fix or mitigation plan: within 10 business days for confirmed issues.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.

Severity is judged by whether the issue allows a blocked destination to be reached, causes a false negative in redirect chains, or leaks sensitive data through errors.
