# Security

Please do **not** report vulnerabilities as public issues; use
[GitHub Security Advisories](https://github.com/larosen/asn-blocker/security/advisories/new) instead.

## Threat model (short version)

- The UI can modify CrowdSec's blocklists. It belongs behind SSO or the built-in login and should not be exposed directly to the internet.
- In the recommended LAPI mode, the container has no access to the Docker socket. Taking over the app allows changes to
  CrowdSec decisions, but no access to the host.
- External sources (RIPEstat, VPN providers, Spamhaus) are treated as untrusted: only public addresses are
  accepted, errors abort the run before anything is written, and large changes require confirmation.
