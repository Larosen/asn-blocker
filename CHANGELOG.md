# Changelog

## 0.5.4 (2026-10-17)
- Notifications: optional access token, sent as `Authorization: Bearer` (ntfy, webhook) or `X-Gotify-Key` (Gotify);
  write-only and discarded when the URL points to a different server
- Notifications link to the affected run; priorities and tags by severity; clearer messages
- **Test notification** reports the server's answer (e.g. HTTP 401/403) instead of always "sent"

## 0.5.3 (2026-10-17)
- Active SSH sessions are now also detected via systemd-logind (`/run/systemd/sessions`), for distributions that no
  longer have a utmp file (e.g. Ubuntu 26.04). The compose file mounts it by default; utmp remains supported.
- A utmp mount that Docker created as an empty directory (host without utmp) counts as "not mounted" instead of an error.

## 0.5.2 (2026-10-16)
- README rewritten for new users: requirements, installation, access options, usage, safeguards, operations, troubleshooting
- Maintenance: removing decisions of other tools needs an explicit reason (no pre-filled value) and explains that only `cscli` decisions are affected

## 0.5.1 (2026-10-16) – security hardening
Result of a full security review (auth, injection/SSRF, frontend, container and supply chain).
- **Sign-in:** the login throttle counts attempts before the password check (parallel requests could run ~9× the
  allowed guesses and spike memory above 1 GB); at most 2 concurrent password hashes; IPv6 throttled per /64;
  constant-time username check; setup token stored hashed, single use, not throttled per IP (could lock the admin
  out of setup); `reset-auth` prints a fresh token and needs no restart
- **Proxy mode:** a username header sent twice is rejected; standard headers (User-Agent, Host, …) can no longer be
  chosen as identity header; warnings when trusted proxies cover more than one address or when local login runs
  behind an untrusted proxy
- **Data sources:** private/reserved ranges are never blocked and prefixes shorter than /8 (IPv6 /16) are ignored;
  the sanity check also compares blocked IPv4 address space and caps it at 2^29 addresses, even on the first run;
  downloads are size- and time-limited and only follow same-host https redirects
- **Secrets:** the stored LAPI password is only reused for the same URL and machine ID; LAPI errors no longer echo
  response bodies; notification URLs are masked in the UI and audit log and no longer appear in logs; the database's
  WAL/SHM files are no longer world-readable
- **CrowdSec:** cleaning up old decisions only removes `cscli`/`cscli-import` decisions, never CrowdSec's own
  detections or blocklists
- **Frontend:** import dialog counts only arrays (HTML injection via crafted file); security headers on every response
- **Container:** no user site-packages (no code persistence via the data volume), no setuid binaries, compose with
  hardening and resource limits by default, all dependencies pinned with hashes
- **CI:** `:latest` and version tags are published only after Trivy scanned both architectures; pull requests are
  scanned too and build with a read-only token; checkouts without persisted credentials

## 0.5.0 (2026-10-16)
- OLED black theme (pure black for OLED screens) and an explicit theme switch: Auto / Light / Dark / OLED black, remembered per browser
- Improved mobile layout
- Everything in English: UI, API messages, logs, CLI and docs; the language switch was removed
- Watched-IP status value `frei` renamed to `clear`

## 0.4.0
- **Self-protection** against accidental lockout (including over SSH with firewall bouncers):
  - the host's active SSH sessions are detected automatically (`/var/run/utmp` mounted read-only) and cut out of all blocks
  - protected IPs and ASNs: never blocked, not even via Spamhaus or a confirmed plausibility check; rules for protected ASNs are rejected
  - `docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect` protects the IP and ASN of the current SSH connection
  - hard final check before every write: if a protected IP ends up in a block, the run aborts
- Run log groups Spamhaus ASNs into one line; missing ASN names are filled in during the run

## 0.3.0
- UI in German and English (automatic by browser language, switchable)
- ASN table: multi-select with bulk actions (Block, Captcha, Remove)
- Apply bar shows the expected change before applying (+/− ranges per action)
- VPN countries grouped by continent, "all/none" per continent
- Logging via `logging`, optionally as JSON (`LOG_FORMAT=json`)
- Accessibility: axe-core (WCAG 2.1 AA) clean in light and dark mode; adjusted contrast,
  screen reader labels, `aria-current`, live regions

## 0.2.1
- Tested against CrowdSec 1.8.1 and 1.8.2-rc1; new CI job with a real CrowdSec 1.8.1 LAPI
- Python 3.14 (base image pinned by digest), Trivy 0.73.0
- pip removed from the runtime image (outdated packages in `pip/_vendor` triggered Trivy findings)
- Error handling when the LAPI is unreachable (previously HTTP 500 on "Test connection")
- Dependencies updated (fastapi 0.143, starlette 1.8, Actions)

## 0.2.0
- CrowdSec connection via the Local API (Docker socket no longer required), Docker socket as legacy mode
- Diff sync: new ranges first, obsolete ones afterwards, so no gap in protection; renewal before expiry
- SQLite instead of JSON; runs with change list, audit log
- Initial setup with setup token; sign-in via reverse proxy header (SSO) or built-in login
- CSRF protection, strict CSP and security headers, no public API docs
- Plausibility limit, watched IPs, lockout warning, IP checker, notifications (ntfy/Gotify/webhook)
- Local ASN search (bgp.tools), ASN sizes, type warning for eyeball (end-user) networks
- VPN: added IVPN, PIA, AirVPN; exact IPs by default instead of /24
- Optional Spamhaus ASN-DROP
- New UI without a build step; ASN lists can be pasted
- Image: non-root, read-only capable, healthcheck; CI with tests, Trivy, SBOM and provenance

## 0.1.0
- First prototype
