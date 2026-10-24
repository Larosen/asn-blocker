# Changelog

## 0.7.2 (2026-10-24) – new interface
- **New design system**: calm, near-monochrome surfaces with hairlines instead of shadows; colours in OKLCH derived
  from three inputs (neutral base, one accent, contrast), so Light, Dark and OLED stay consistent; Geist Sans/Mono
  (bundled, no external requests) with mono labels; dimmed sidebar, content first; glass only for the control layer
  (top bar, apply bar, dialogs)
- **Map of the IPv4 address space** on the overview: every /16 network as one cell along a Hilbert curve, blocked
  and captcha networks light up; hover shows the network and its share
- **Command palette** (Ctrl/⌘+K): jump to any view, apply, preview, check an IP, search ASNs, change the theme
- Motion with purpose only (short fades, the map's reveal); `prefers-reduced-motion`, `prefers-reduced-transparency`
  and `prefers-contrast: more` are honoured; WCAG 2.2 AA contrast in all themes (axe: 0 violations)
- **Security:** certifi 2026.10.23 – removes emSign root CAs whose intermediate CA keys were compromised
  (GHSA-6q48-6c7w-9gw2, critical)

## 0.7.1 (2026-10-20)
- **Fix (security):** 0.7.0 replaced a trusted proxy IP by whatever container name that IP had *now*. If the proxy
  had been recreated and another container got its old IP (e.g. Watchtower), that container was trusted by name and
  could send any username. A name is now only learned right after a valid sign-in through that IP, i.e. from the
  proxy itself; a stale IP is never converted. **If you ran 0.7.0, check Settings → Access** and remove any
  container that is not your proxy (`python -m app.cli untrust-proxy <name>`).
- New `untrust-proxy` command

## 0.7.0 (2026-10-20)
- **Trusted proxies by container name**: Settings, setup and the new `trust-proxy` command accept Docker container
  names (e.g. `gerbil`) besides IPs and CIDRs. A recreated proxy with a new IP keeps working.
- **Existing installations**: trusted private proxy IPs are replaced by their container name automatically (via
  Docker's DNS, only if the name resolves back to that IP). Superseded in 0.7.1, see there.
- **No access page** shows the source address of the request, its container name, whether the user header arrived
  and the names (never the values) of all received headers, plus the command to trust the proxy
- `python -m app.cli trust-proxy <name|IP|CIDR>` fixes a changed proxy without redoing the setup
- Upgrade note: if the proxy already got a new IP before updating, run `trust-proxy` once (the page shows the command)

## 0.6.4 (2026-10-19)
- **Check IP recognises VPN exits**: if a blocked address has listed VPN servers in the same /24 (IPv6 /64), the
  dialog says it is probably a VPN exit and links to the provider. VPN exits often use a neighbouring IP of the listed
  server (e.g. NordVPN Turkey), which *exact server IPs* does not cover.
- NordVPN: the hint recommends *whole network* and still offers AS207137 for the remaining exits

## 0.6.3 (2026-10-19)
- IPVanish: if configs.ipvanish.com refuses the download (it blocks some data center networks, e.g. GitHub's
  runners), the gluetun project's IPVanish server data is used instead of failing; `check-sources` shows which list
  was used

## 0.6.2 (2026-10-17)
- **Stopped runs are confirmed in one step**: when the sanity check stops a run, a dialog shows every reason with
  *Apply anyway*, *Review changes* and *Not now*; the banner and the apply bar offer *Apply anyway* too, instead of a
  plain *Apply* that stopped again
- *Apply anyway* applies exactly the reviewed result: if the recomputed ranges differ by more than 5 % and still trip a
  check, the run stops again; only the latest stopped run can be confirmed
- All stop reasons are recorded (previously only the first), e.g. IPv6 newly enabled and range count together

## 0.6.1 (2026-10-17)
- README: screenshots of the overview, ASN search, suggestions, VPN exemptions and a run; safeguards updated
- ASN search placeholder uses a neutral example IP

## 0.6.0 (2026-10-17)
- **ASN search by IP**: enter an IP (e.g. from a CrowdSec alert) to see the network announcing it and block it or put
  it behind a captcha; unrouted addresses are explained with their registered holder. The IP check dialog offers the
  same buttons.
- **Suggestions**: curated starting lists (large cloud platforms, VPS/dedicated hosting, ByteDance crawlers) and
  one-click Spamhaus ASN-DROP, each reviewed in the import preview
- **Own network guard**: rules for the network the browser is connected from need an explicit confirmation
- **14 more VPN providers** (20 in total): Proton VPN, Windscribe, IPVanish, PrivadoVPN, OVPN, PureVPN, ExpressVPN,
  CyberGhost, TorGuard, PrivateVPN, VyprVPN, FastestVPN, VPN Unlimited, VPNSecure
- **Notifications**: own form; *Send test* checks the unsaved values and *Save* is only possible after a successful
  test (enforced by the server); a banner explains why saving was refused
- **Second security review**: login attempts are only counted once a password-hash slot is free and IPv6 is
  throttled per /64 and /48; the notification token is bound to scheme, host and port; notification and LAPI targets
  must not be link-local (cloud metadata); imports are validated completely before anything is written; hard caps of
  150,000 ranges and 2^36 IPv6 /48 networks; runs only change decisions whose alert carries asn-blocker's own source;
  downloads have an enforced deadline; dialogs focus *Cancel* so a stray Enter adds nothing; `:latest` and other tags
  are set only after the image scan passed

## 0.5.5 (2026-10-17)
- The web UI's files are served with `Cache-Control: no-cache`, so browsers revalidate them and show a new version
  right after an update instead of an outdated cached interface

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
