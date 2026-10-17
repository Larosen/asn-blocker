# Security

Please do **not** report vulnerabilities as public issues; use
[GitHub Security Advisories](https://github.com/larosen/asn-blocker/security/advisories/new) instead.

## Supported versions

Only the latest release (`:latest` and the newest `x.y` tag) receives security fixes.

## Threat model (short version)

- The UI can modify CrowdSec's blocklists. It belongs behind SSO or the built-in login and should not be exposed
  directly to the internet. All signed-in users have full rights; there are no roles.
- **What a compromised app could do:** it holds CrowdSec *machine* credentials. With those, decisions can be added or
  removed directly at the LAPI – self-protection is enforced by the app, not by CrowdSec, so a firewall bouncer could
  then also lock out SSH. The app also sees the SSH user names and source IPs from the mounted session registry, and can reach
  every service on the Docker networks it is attached to (see README, *Security → Network isolation*). In the recommended LAPI
  mode it has no Docker socket and no access to the host. In legacy Docker socket mode, a compromise means root on the host.
- **Proxy authentication** trusts the username header only from the configured proxy IPs. The proxy must strip that
  header from client requests and set it itself; trust a single proxy address, never a whole shared Docker network.
- **External sources** (RIPEstat, bgp.tools, VPN providers, Spamhaus) are treated as untrusted: downloads are size- and
  time-limited, private/reserved ranges and implausibly large prefixes are never blocked, errors abort the run before
  anything is written, and large changes in range count or blocked address space require confirmation.
- **Secrets** (LAPI password, notification URL, password hash, session hashes) are stored in the SQLite database in
  the data volume with mode 0600. The LAPI password and the notification URL are never sent back to the browser in full.
- **Supply chain:** dependencies are pinned with hashes, GitHub Actions and base images by digest; images are scanned
  with Trivy before `:latest` or a version tag is published.
- **Accepted limits:** every account that logs in over SSH (including restricted accounts such as SFTP or git users)
  counts as an active session and its IP is exempted while the session lasts. The confirmation before blocking your
  own network is a safety net against mistakes, not a security boundary: it is skipped if the network cannot be
  determined. VPN server lists from third parties (Proton VPN, gluetun) can only add exemptions for single public
  addresses in the countries you selected.
