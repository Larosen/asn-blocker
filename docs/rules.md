# Rules, exemptions and safeguards

## How rules combine

ASN rules, exemptions, VPN exemptions, self-protection and Spamhaus ASN-DROP all work the same way: a set of networks
and an effect. Where they overlap, the stronger effect wins for each address:

**never blocked** (exemptions, VPN servers, self-protection, private ranges, active SSH sessions)
› **at most captcha** (networks protected against bans) › **block** › **captcha**

**Check IP → Why** lists every rule that covers an address and marks the one that decides.

## Lockout protection

A firewall bouncer applies bans to all traffic, SSH included.

- **Active SSH sessions** are never blocked if the host's session registry is mounted read-only:
  `/run/systemd/sessions:/host/sessions:ro` with systemd, or `/var/run/utmp:/host/utmp:ro` without it.
  **Exemptions → Self-protection** shows whether sessions are detected.
- **Protected IPs** are never blocked, not even by Spamhaus or a confirmed run. Home connections change their IP, so
  you can protect the **ASN** of your connection as well:
  - **At most captcha** (default): bans for that network become captchas. Firewall bouncers ignore captchas, so SSH
    stays reachable, while web visitors from that network still get a captcha.
  - **Never blocked**: the whole network is exempt. Only use this for small networks you control.
- From an SSH session, one command protects your connection:

  ```bash
  docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect          # this connection's IP
  docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect --asn    # and its ASN, at most captcha
  docker exec asn-blocker python -m app.cli protect --list
  ```
- The overview warns when the IP you are browsing from is affected, with a button to exempt it.
- Every run checks that no protected IP would be blocked before it writes anything.

CrowdSec itself still bans single attacking IPs from protected networks.

## VPN exemptions

Pick a provider and the countries whose servers should stay reachable. By default exactly the listed server IPs are
exempt. **Whole network** exempts the surrounding `/24` (IPv6 `/64`) instead, which also covers neighbouring exit
addresses but may exempt other servers at the same host.

Some providers send traffic from a different address than the one they list. NordVPN users usually come from a
neighbouring address in the same `/24`, so choose **whole network** for NordVPN; other NordVPN exits are in
`AS207137`, which you can add as an exempt ASN. **Check IP** points out listed VPN servers next to a blocked address.

Server lists come from the providers themselves for NordVPN, Mullvad, Surfshark, IVPN, Private Internet Access,
AirVPN, Windscribe, IPVanish, PrivadoVPN and OVPN; from [ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs) for
Proton VPN; and from the [gluetun](https://github.com/qdm12/gluetun-servers) server data for PureVPN, ExpressVPN,
CyberGhost, TorGuard, PrivateVPN, VyprVPN, FastestVPN, VPN Unlimited and VPNSecure, which publish no list of
their own. Surfshark only publishes hostnames, so the container needs working DNS.

## Attackers and automatic rules

**Attackers** counts only real detections of your own CrowdSec on this server. Community blocklists, manual
decisions and asn-blocker's own decisions are left out. A hosting network with 5 or more attacking IPs is
recommended for *Block*, very large clouds and transit networks for *Captcha*. Consumer networks are never
recommended. CrowdSec keeps alerts for about a week, so asn-blocker reads them every hour and keeps a summary for
180 days.

**Automatic rules** are off by default. When switched on, recommended networks become rules after each collection,
either always as captcha or with the recommended action, for 7, 30 or 90 days. At most 10 are added at a time, each
batch sends a notification, and a rule you remove is not added again during its lifetime.

## Spamhaus ASN-DROP

The [Spamhaus ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) list (networks run entirely by
criminals) can be included as an extra set of rules under **Settings → Schedule and safety**.

## Safeguards

| | |
|---|---|
| Validate before writing | If a data source fails or returns invalid data, the run stops and CrowdSec stays unchanged. |
| Sanity check | If the number of ranges or the blocked IPv4 or IPv6 space changes by more than 30 % (configurable), the run stops and shows why. **Apply anyway** applies exactly the reviewed result. Hard limits apply even to the first run: 150,000 ranges, 2^29 IPv4 addresses, 2^36 IPv6 /48 networks. |
| Implausible data | Private and reserved ranges are never blocked. Prefixes larger than /8 (IPv6 /16) are discarded. |
| No gaps | New ranges are added before old ones are removed. |
| Decisions expire | Every decision has a lifetime and is renewed by each run, so nothing lingers if asn-blocker is gone. |
| Own decisions only | asn-blocker only changes decisions with its own reason (`asn-blocker ban`, `asn-blocker captcha`). |
