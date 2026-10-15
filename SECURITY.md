# Sicherheit

Sicherheitslücken bitte **nicht** als öffentliches Issue melden, sondern über
[GitHub Security Advisories](https://github.com/larosen/asn-blocker/security/advisories/new).

## Bedrohungsmodell (Kurzfassung)

- Die Oberfläche kann die Sperrlisten von CrowdSec verändern. Sie gehört hinter SSO oder den eingebauten Login und sollte nicht direkt im Internet stehen.
- Im empfohlenen LAPI-Modus hat der Container keinen Zugriff auf den Docker-Socket. Eine Übernahme der App erlaubt Änderungen an
  CrowdSec-Decisions, aber keinen Zugriff auf den Host.
- Externe Quellen (RIPEstat, VPN-Anbieter, Spamhaus) werden als nicht vertrauenswürdig behandelt: nur öffentliche Adressen werden
  übernommen, Fehler brechen den Lauf vor dem Schreiben ab, große Änderungen brauchen eine Bestätigung.
