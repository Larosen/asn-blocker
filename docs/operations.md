# Operations

## Settings

Under **Settings → Schedule and safety**:

| Setting | Default | |
|---|---|---|
| Update every | 48 h | How often the ranges are refreshed (6 h to 14 days) |
| Decision lifetime | 7 days | At least twice the interval |
| Also block IPv6 prefixes | off | |
| Sanity limit | 30 % | Largest change a run may make without confirmation |
| Spamhaus ASN-DROP | off | Include the list as *Block* or *Captcha* |

Optional environment variables: `LOG_FORMAT=json` for structured logs, `LOG_LEVEL=DEBUG`.

The routing table is kept in `/data/routes.db` (about 75 MB) and refreshed daily. Until it is loaded, or if it
could not be refreshed for three days, asn-blocker asks RIPEstat instead. **Settings → Maintenance** shows its state.

## Data and backup

Everything is in the `/data` volume: one SQLite database with rules, run history, the audit log and the CrowdSec
credentials, plus the routing table. Back up the volume, or export rules and exemptions under
**Settings → Maintenance**. The same page imports an export and offers the active ranges as plain text.

Before a database upgrade, a copy is kept next to it as `asn-blocker.db.schema-v<old version>.bak`.

## Versions

`:latest` is published only after the image passed a vulnerability scan, so updaters like Watchtower can follow it.
Release tags: `:0.7.12` (exact), `:0.7` (patch updates only), and `:sha-<commit>` for every build. To keep Watchtower
away from a pinned container, add the label `com.centurylinklabs.watchtower.enable=false`.

## Command line

```bash
docker exec asn-blocker python -m app.cli reset-auth              # forgot the password: prints a new setup token
docker exec asn-blocker python -m app.cli trust-proxy NAME        # trust a proxy by container name, IP or CIDR
docker exec asn-blocker python -m app.cli protect [IP] [--asn]    # protect an IP, and optionally its ASN
docker exec asn-blocker python -m app.cli check-sources           # test all external data sources
```

## Decisions of other tools

If you blocked networks with your own script through `cscli` before, **Settings → Maintenance** can remove those
decisions by their reason. Only decisions added through `cscli` are affected.
