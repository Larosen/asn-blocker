# asn-blocker

Web-Oberfläche für [CrowdSec](https://crowdsec.net), mit der man ganze Netze (ASNs) **blockiert** oder mit einem **Captcha** versieht –
mit Ausnahmen für die Server-Standorte von VPN-Anbietern. Ein Container, ein Volume, alles Weitere wird in der Oberfläche eingerichtet.

## Was es tut

1. Du wählst ASNs aus (Suche nach Nummer oder Name) und legst pro ASN *Blockieren* oder *Captcha* fest.
2. asn-blocker holt die aktuell announcten Prefixe (RIPEstat), schneidet alle Ausnahmen heraus und gleicht das Ergebnis
   mit CrowdSec ab. Das passiert automatisch alle 48 h (einstellbar).
3. Ausnahmen:
   - **VPN-Anbieter** pro Land: NordVPN, Mullvad, Surfshark, IVPN, Private Internet Access, AirVPN (jeweils deren öffentliche Serverliste)
   - **Ausnahme-ASNs**, z. B. `AS207137` (Exit-IPs von NordVPN)
   - **einzelne IPs/CIDRs**
4. Optional: die [Spamhaus ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)-Liste automatisch übernehmen.

### Sicherheitsnetz

- **Diff-Sync statt Löschen und Neuimport:** Neue Ranges werden zuerst angelegt, entfallene danach gelöscht. Es gibt keine Lücke ohne Schutz.
- **Erst prüfen, dann schreiben:** Liefert eine Quelle keine gültigen Daten, bleibt CrowdSec unverändert.
- **Plausibilitätsgrenze:** Ändert sich die Anzahl der Ranges um mehr als 30 % (einstellbar), hält der Lauf an und wartet auf Bestätigung.
- **Ablauf statt Ewigkeit:** Sperren gelten standardmäßig 7 Tage und werden vor Ablauf erneuert. Fällt asn-blocker aus, laufen sie aus statt jahrelang veraltet zu bleiben.
- **Wächter-IPs:** z. B. deine Mobilfunk-IP. Nach jedem Lauf geprüft; wäre eine betroffen, wirst du benachrichtigt (ntfy, Gotify oder Webhook).
- **Aussperr-Warnung:** Liegt deine eigene IP in einer gesperrten Range, zeigt die Oberfläche das mit einem Ein-Klick-Fix.
- **IP-Prüfer:** Für jede IP: Welcher ASN, welche Regel, welche Ausnahme greift.

## Schnellstart

```yaml
# docker-compose.yml
services:
  asn-blocker:
    image: ghcr.io/larosen/asn-blocker:latest
    restart: unless-stopped
    volumes: [asn-blocker-data:/data]
    networks: [crowdsec]          # Netz, in dem CrowdSec erreichbar ist
volumes:
  asn-blocker-data:
networks:
  crowdsec: { external: true }
```

```bash
docker compose up -d
docker logs asn-blocker            # enthält das Setup-Token
```

1. Oberfläche aufrufen (über den Reverse Proxy, siehe unten), Setup-Token eingeben und die Anmeldung wählen.
2. Einmalig im CrowdSec-Container einen Zugang anlegen und das ausgegebene Passwort in der Oberfläche eintragen:
   ```bash
   docker exec crowdsec cscli machines add asn-blocker --auto -f -
   ```
3. ASNs auswählen → **Anwenden**.

Das war's. Kein Docker-Socket, keine Umgebungsvariablen.

### Hinter Pangolin (oder einem anderen Reverse Proxy mit SSO)

- Den Container **nicht** mit `ports:` veröffentlichen, sondern ins Docker-Netz des Proxys hängen (bei Pangolin: das Netz von Newt bzw. Traefik).
- In Pangolin eine Ressource auf `http://asn-blocker:8080` mit aktivierter Authentifizierung anlegen.
- Bei der Ersteinrichtung **„Reverse Proxy mit SSO“** wählen:
  - *Vertrauenswürdige Proxy-IPs*: die IP/das Netz des Proxy-Containers (wird vorausgefüllt).
  - *Header mit Benutzername*: der Header, den der Proxy nach dem Login setzt (Standard `Remote-User`).
  Die Einrichtung prüft, dass die aktuelle Anfrage diese Bedingungen erfüllt – du kannst dich so nicht versehentlich aussperren.
- Ohne SSO-Proxy: **„Eigener Login“** wählen (Passwort, Session-Cookie, Login-Drosselung).

Die App erwartet, dass TLS am Proxy endet. Identity-Header und `X-Forwarded-For` werden nur von den eingetragenen Proxy-IPs akzeptiert.

Zugang verloren? `docker exec asn-blocker python -m app.cli reset-auth`, Container neu starten, neues Token aus dem Log.

### Captcha

Captcha-Decisions wirken nur mit einem Bouncer, der Captchas ausliefern kann – z. B. dem
[Traefik-Bouncer-Plugin](https://plugins.traefik.io/plugins/6335346ca4caa9ddeffda116/crowdsec-bouncer-traefik-plugin) mit Captcha-Konfiguration.
Firewall-Bouncer (nftables/iptables) **ignorieren** Captcha-Decisions.

### Umstieg vom Bash-Skript `asn-to-range-ban.sh`

1. ASNs → **Liste einfügen** → den Inhalt von `ASN_LIST=( … )` einfügen. Kommentare werden als Notiz übernommen, auskommentierte Zeilen übersprungen.
2. `EXEMPT_COUNTRIES` unter *VPN-Ausnahmen → NordVPN* anhaken, `EXEMPT_ASNS` und `MANUAL_EXEMPT` unter *Ausnahmen* eintragen, `TEST_IPS` als *Wächter-IPs*.
3. Anwenden. Danach unter *Einstellungen → Wartung* die alten Decisions (`Auto-Block via ASN Bulk`) entfernen und den Cronjob des Skripts löschen.

## Betrieb

| | |
|---|---|
| Daten | `/data/asn-blocker.db` (SQLite) – Regeln, Läufe, Protokoll, Caches, CrowdSec-Zugang |
| Prozess | ein Uvicorn-Worker, Scheduler im selben Prozess |
| Benutzer | UID 10001, läuft mit `read_only`, `cap_drop: ALL`, `no-new-privileges` |
| Healthcheck | `GET /healthz` (im Image eingebaut) |
| Logs | stdout, lesbarer Text; `LOG_FORMAT=json` für JSON (z. B. Loki), `LOG_LEVEL=DEBUG` für mehr Details |
| Sprache | Oberfläche Deutsch/Englisch, automatisch nach Browser, umschaltbar unten links |
| Externe Quellen | stat.ripe.net, bgp.tools (ASN-Namensliste, wöchentlich), Anbieter-APIs, optional spamhaus.org |

**Legacy-Modus Docker-Socket:** In den Einstellungen kann statt der LAPI `cscli` per `docker exec` genutzt werden. Dafür muss
`/var/run/docker.sock` eingebunden und der Container mit einer Gruppe gestartet werden, die darauf zugreifen darf.
Wer dann die Oberfläche übernimmt, hat Root auf dem Host – nur verwenden, wenn die LAPI nicht erreichbar ist.

## Kompatibilität

Getestet gegen CrowdSec **1.8.1** und **1.8.2-rc1** (sowie 1.6.8); die CI prüft jeden Push gegen einen echten CrowdSec-1.8.1-Container.
Das Image basiert auf Python 3.14.

## Entwicklung

```bash
pip install -r requirements-dev.txt
ruff check app tests && pytest -q
DATA_DIR=./data uvicorn app.main:app --reload --port 8080
```

Integrationstest gegen eine echte LAPI: `CROWDSEC_LAPI_URL`, `CROWDSEC_MACHINE_ID`, `CROWDSEC_PASSWORD` setzen, dann `pytest tests/test_lapi_integration.py`.
Das Frontend ist reines HTML/CSS/JS ohne Build-Schritt (`app/static`).
