# Changelog

## 0.4.0
- **Selbstschutz** gegen versehentliches Aussperren (auch per SSH bei Firewall-Bouncern):
  - aktive SSH-Sitzungen des Hosts werden automatisch erkannt (`/var/run/utmp` schreibgeschützt eingebunden) und aus allen Sperren herausgeschnitten
  - geschützte IPs und ASNs: nie gesperrt, auch nicht über Spamhaus oder eine bestätigte Plausibilitätsprüfung; Regeln für geschützte ASNs werden abgelehnt
  - `docker exec -e SSH_CLIENT asn-blocker python -m app.cli protect` schützt IP und ASN der aktuellen SSH-Verbindung
  - harte Endkontrolle vor jedem Schreibzugriff: landet eine geschützte IP in einer Sperre, bricht der Lauf ab
- Lauf-Protokoll fasst Spamhaus-ASNs in einer Zeile zusammen; fehlende ASN-Namen werden beim Lauf ergänzt

## 0.3.0
- Oberfläche auf Deutsch und Englisch (automatisch nach Browsersprache, umschaltbar)
- ASN-Tabelle: Mehrfachauswahl mit Massenaktionen (Blockieren, Captcha, Entfernen)
- Apply-Leiste zeigt vor dem Anwenden die erwartete Änderung (+/− Ranges je Aktion)
- VPN-Länder nach Kontinent gruppiert, „alle/keine“ je Kontinent
- Logging über `logging`, optional als JSON (`LOG_FORMAT=json`)
- Barrierefreiheit: axe-core (WCAG 2.1 AA) ohne Befund in hellem und dunklem Modus; Kontraste angepasst,
  Screenreader-Beschriftungen, `aria-current`, Live-Regionen

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
