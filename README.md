# asn-blocker

Weboberfläche für CrowdSec, mit der man ganze ASNs **blockieren** oder mit einem **Captcha** versehen kann.
Ausnahmen für Server-Regionen von VPN-Anbietern lassen sich per Klick festlegen.
Ist die Weiterentwicklung des Skripts `asn-to-range-ban.sh`.

## Funktionen

- **ASNs**: Suche nach Nummer oder Name (RIPEstat), Aktion pro ASN: `ban` oder `captcha`.
- **Automatisches Update**: Ein Scheduler im Container holt die announced Prefixe alle
  `UPDATE_INTERVAL_HOURS` (Standard 48 h) neu und ersetzt die Decisions. Nach einem Fehler gibt es einen neuen Versuch nach 1 h.
- **VPN-Whitelist**: Länder pro Anbieter auswählen. Deren Server-IPs (optional auf /24 bzw. /64 erweitert)
  werden aus allen Ranges herausgeschnitten. Unterstützt werden Anbieter, die ihre Serverliste öffentlich anbieten:
  | Anbieter | Quelle |
  |---|---|
  | NordVPN | `api.nordvpn.com/v1/servers` |
  | Mullvad | `api.mullvad.net/www/relays/all/` |
  | Surfshark | `api.surfshark.com/v4/server/clusters/generic` + DNS |
- **Weitere Ausnahmen**: Ausnahme-ASNs (z. B. `207137` PacketHub für die NordVPN-Exit-IPs) und einzelne IPs/CIDRs.
- **Sicherheit wie im Original-Skript**: Alte Decisions werden erst gelöscht, wenn *alle* Quellen gültige Daten geliefert haben.
  Danach wird geprüft, ob die Anzahl übereinstimmt. Ein Testlauf ist ohne Änderungen an CrowdSec möglich.

Ban- und Captcha-Decisions bekommen eigene Reasons (`asn-blocker ban` / `asn-blocker captcha`).
Captcha braucht einen Bouncer, der das unterstützt (z. B. das Traefik-Plugin mit Captcha-Konfiguration).
Die nftables/iptables-Firewall-Bouncer behandeln `captcha` **nicht**.

## Start

```bash
docker compose up -d   # danach http://127.0.0.1:8080
```

Der Container führt `cscli` per `docker exec` im CrowdSec-Container aus. Dafür ist `/var/run/docker.sock` gemountet.
Wer Zugriff auf den Socket hat, hat faktisch Root-Rechte auf dem Host. Die Oberfläche deshalb nicht öffentlich erreichbar machen und `ADMIN_PASSWORD` setzen.

| Variable | Standard | |
|---|---|---|
| `CROWDSEC_CONTAINER` | `crowdsec` | Name des CrowdSec-Containers |
| `UPDATE_INTERVAL_HOURS` | `48` | Update-Intervall |
| `DECISION_DURATION` | `1095d` | Dauer der Decisions |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / leer | Basic Auth (leer = aus) |

Die Konfiguration liegt in `/data/config.json` und lässt sich auch von Hand bearbeiten.

## Image

Die GitHub Action `.github/workflows/docker.yml` baut bei Pushes auf `main` und bei Tags `v*` ein Image für amd64 und arm64
und veröffentlicht es als `ghcr.io/larosen/asn-blocker`.
