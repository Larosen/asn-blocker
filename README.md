# asn-blocker

Web UI for [CrowdSec](https://crowdsec.net) that **blocks** entire networks (ASNs) or puts them behind a **captcha**,
with exemptions for the server locations of VPN providers. One container, one volume; everything else is set up in the UI.

## What it does

1. You pick ASNs (search by number or name) and set *Block* or *Captcha* per ASN.
2. asn-blocker fetches the currently announced prefixes (RIPEstat), cuts out all exemptions and syncs the result
   with CrowdSec. This runs automatically every 48 h (configurable).
3. Exemptions:
   - **VPN providers** per country: NordVPN, Mullvad, Surfshark, IVPN, Private Internet Access, AirVPN (each from its public server list)
   - **Exempt ASNs**, e.g. `AS207137` (NordVPN exit IPs)
   - **individual IPs/CIDRs**
4. Optional: automatically include the [Spamhaus ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) list.

### Safety net

- **Diff sync instead of delete and re-import:** New ranges are added first, obsolete ones removed afterwards. There is never a gap in protection.
- **Validate first, then write:** If a source returns no valid data, CrowdSec is left unchanged.
- **Plausibility limit:** If the number of ranges changes by more than 30 % (configurable), the run stops and waits for confirmation.
- **Expiry instead of forever:** Blocks last 7 days by default and are renewed before they expire. If asn-blocker goes down, they expire instead of lingering, outdated, for years.
- **Watched IPs:** e.g. your mobile IP. Checked after every run; if one would be affected, you get notified (ntfy, Gotify or webhook).
- **Lockout warning:** If your own IP falls inside a blocked range, the UI shows it with a one-click fix.
- **IP checker:** For any IP: which ASN, which rule and which exemption applies.

### Appearance

The UI is in English. A theme switch offers **Auto** (follows the system), **Light**, **Dark** and **OLED black**
(pure black for OLED screens); the choice is remembered per browser. The layout also works on phones.

## Quick start

```yaml
# docker-compose.yml
services:
  asn-blocker:
    image: ghcr.io/larosen/asn-blocker:latest
    restart: unless-stopped
    volumes:
      - asn-blocker-data:/data
      - /var/run/utmp:/host/utmp:ro   # self-protection for active SSH sessions
    networks: [crowdsec]          # network in which CrowdSec is reachable
    read_only: true
    tmpfs: ["/tmp:size=16m,noexec,nosuid,nodev"]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 256m
    pids_limit: 128
volumes:
  asn-blocker-data:
networks:
  crowdsec: { external: true }
```

```bash
docker compose up -d
docker logs asn-blocker 2>&1 | grep -i "setup token"
```

1. Open the UI (through the reverse proxy, see below), enter the setup token and choose how to sign in.
2. Once, create credentials in the CrowdSec container and enter the printed password in the UI:
   ```bash
   docker exec crowdsec cscli machines add asn-blocker --auto -f -
   ```
3. Select ASNs → **Apply**.

That's it. No Docker socket, no environment variables.

### Behind Pangolin (or another reverse proxy with SSO)

- Do **not** publish the container with `ports:`; attach it to the proxy's Docker network instead (for Pangolin: the Newt or Traefik network).
- In Pangolin, create a resource for `http://asn-blocker:8080` with authentication enabled.
- During initial setup, choose **"Reverse proxy with SSO"**:
  - *Trusted proxy IPs*: the IP of the proxy container (pre-filled). Trust only that single address, not the whole
    Docker network: every host in a trusted range can send any username header. If the proxy container gets a new IP
    after being recreated, run `reset-auth` (see below) or pin its address in your proxy's compose file.
  - *Header with username*: the header the proxy sets after login (default `Remote-User`). Use only a header the
    proxy always removes from client requests and sets itself: `Remote-User` with Pangolin (Badger ≥ 1.2.1 strips
    client-supplied `Remote-*` headers), or the `X-authentik-*` headers listed in `authResponseHeaders` with
    Authentik forwardAuth.
  Setup verifies that the current request meets these conditions, so you cannot accidentally lock yourself out.
- Without an SSO proxy: choose **"Built-in login"** (password, session cookie, login throttling).

The app expects TLS to terminate at the proxy. Identity headers and `X-Forwarded-For` are only accepted from the configured proxy IPs.
The proxy must *set* (overwrite) the username header; a request that carries it twice is rejected. Do not add
unauthenticated bypass rules for this resource in Pangolin.

#### Network isolation

The proxy network of a Pangolin stack also contains Traefik, Pangolin's API, Gerbil, middleware-manager, Authentik
and CrowdSec. The app only needs to reach CrowdSec's LAPI and to be reached by the proxy. For stronger isolation,
create a dedicated network that only the proxy (Gerbil/Traefik) and asn-blocker join, and a second one for CrowdSec:

```bash
docker network create asnb-proxy && docker network connect asnb-proxy gerbil   # the container Traefik runs in
docker network create asnb-lapi  && docker network connect asnb-lapi crowdsec
```

Then use `networks: [asnb-proxy, asnb-lapi]` (both `external: true`) instead of the shared proxy network.
Re-run the `docker network connect` commands if those containers are recreated.

#### Updates

`:latest` and the version tags are only published after the image passed the vulnerability scan. Watchtower
can follow `:latest`; for a pinned deployment use a version tag such as `:0.5` or a digest.

Lost access? Run `docker exec asn-blocker python -m app.cli reset-auth` – it prints a new setup token; open the web UI and set up sign-in again (no restart needed).

### Self-protection: don't lock yourself out

When a firewall bouncer (nftables/iptables) blocks a range, that also hits SSH. asn-blocker therefore protects:

- **Active SSH sessions automatically**, if the host's `/var/run/utmp` is mounted read-only
  (`- /var/run/utmp:/host/utmp:ro`, see `docker-compose.yml`). Their IPs are cut out of all blocks on every run.
- **Protected IPs and ASNs** (Exemptions → Self-protection). Rules for protected ASNs are rejected, including via
  Spamhaus. Their prefixes are never blocked, not even after a confirmed plausibility check. Since home connections usually
  have changing IPs, at least the **ASN of your own connection** should be protected.
- From within the running SSH session, without the UI:
  ```bash
  docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect          # protect IP + ASN of this connection
  docker exec asn-blocker python -m app.cli protect --list                  # overview
  ```
- Before any write, a run additionally checks that no protected IP ends up in a block, and aborts otherwise.

### Captcha

Captcha decisions only take effect with a bouncer that can serve captchas, e.g. the
[Traefik bouncer plugin](https://plugins.traefik.io/plugins/6335346ca4caa9ddeffda116/crowdsec-bouncer-traefik-plugin) with captcha configured.
Firewall bouncers (nftables/iptables) **ignore** captcha decisions.

### Migrating from the bash script `asn-to-range-ban.sh`

1. ASNs → **Paste list** → paste the contents of `ASN_LIST=( … )`. Comments are kept as notes, commented-out lines are skipped.
2. Tick `EXEMPT_COUNTRIES` under *VPN exemptions → NordVPN*, enter `EXEMPT_ASNS` and `MANUAL_EXEMPT` under *Exemptions*, and `TEST_IPS` as *Watched IPs*.
3. Apply. Then remove the old decisions (`Auto-Block via ASN Bulk`) under *Settings → Maintenance* and delete the script's cron job.

## Operation

| | |
|---|---|
| Data | `/data/asn-blocker.db` (SQLite): rules, runs, audit log, caches, CrowdSec credentials |
| Process | one Uvicorn worker, scheduler in the same process |
| User | UID 10001, no setuid binaries in the image; run it with `read_only`, `cap_drop: ALL`, `no-new-privileges` (see compose file) |
| Healthcheck | `GET /healthz` (built into the image) |
| Logs | stdout, readable text; `LOG_FORMAT=json` for JSON (e.g. Loki), `LOG_LEVEL=DEBUG` for more detail |
| Language / theme | English; theme Auto / Light / Dark / OLED black, remembered per browser |
| External sources | stat.ripe.net, bgp.tools (ASN name list, weekly), provider APIs, optionally spamhaus.org |

**Legacy Docker socket mode:** In the settings, `cscli` via `docker exec` can be used instead of the LAPI. This requires
mounting `/var/run/docker.sock` and starting the container with a group that may access it.
Anyone who takes over the UI then has root on the host. Only use this if the LAPI is not reachable.

## Compatibility

Tested against CrowdSec **1.8.1** and **1.8.2-rc1** (as well as 1.6.8); CI checks every push against a real CrowdSec 1.8.1 container.
The image is based on Python 3.14.

## Development

```bash
pip install --require-hashes --no-deps -r requirements.txt && pip install -r requirements-dev.txt
ruff check app tests && pytest -q
DATA_DIR=./data uvicorn app.main:app --reload --port 8080
```

Integration test against a real LAPI: set `CROWDSEC_LAPI_URL`, `CROWDSEC_MACHINE_ID`, `CROWDSEC_PASSWORD`, then run `pytest tests/test_lapi_integration.py`.
The frontend is plain HTML/CSS/JS with no build step (`app/static`).
Dependencies: direct pins live in `requirements.in`; `requirements.txt` is the fully pinned, hash-checked lock
(`uv pip compile requirements.in --universal --python-version 3.14 --generate-hashes -o requirements.txt`).
