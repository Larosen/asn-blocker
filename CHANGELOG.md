# Changelog

## 0.2.0
- CrowdSec-Anbindung über die Local API (kein Docker-Socket mehr nötig), Docker-Socket als Legacy-Modus
- Diff-Sync: neue Ranges zuerst, entfallene danach – keine Lücke ohne Schutz; Erneuerung vor Ablauf
- SQLite statt JSON; Läufe mit Änderungsliste, Audit-Protokoll
- Ersteinrichtung mit Setup-Token; Anmeldung per Reverse-Proxy-Header (SSO) oder eigenem Login
- CSRF-Schutz, strikte CSP und Security-Header, keine API-Doku öffentlich
- Plausibilitätsgrenze, Wächter-IPs, Aussperr-Warnung, IP-Prüfer, Benachrichtigungen (ntfy/Gotify/Webhook)
- Lokale ASN-Suche (bgp.tools), ASN-Größen, Typ-Warnung bei Endkunden-Netzen
- VPN: zusätzlich IVPN, PIA, AirVPN; exakte IPs als Standard statt /24
- Spamhaus ASN-DROP optional
- Neue Oberfläche ohne Build-Schritt; Import der ASN-Liste aus dem Bash-Skript
- Image: non-root, read-only-fähig, Healthcheck; CI mit Tests, Trivy, SBOM und Provenance

## 0.1.0
- Erster Prototyp
