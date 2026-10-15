# Changelog

## 0.2.1
- Getestet gegen CrowdSec 1.8.1 und 1.8.2-rc1; neuer CI-Job mit echter CrowdSec-1.8.1-LAPI
- Python 3.14 (Basis-Image per Digest gepinnt), Trivy 0.73.0
- pip aus dem Laufzeit-Image entfernt (veraltete Pakete in `pip/_vendor` lösten Trivy-Funde aus)
- Fehlerbehandlung, wenn die LAPI nicht erreichbar ist (vorher HTTP 500 bei „Verbindung testen“)
- Abhängigkeiten aktualisiert (fastapi 0.143, starlette 1.8, Actions)

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
