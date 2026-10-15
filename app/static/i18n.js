// Uebersetzungen: Schluessel ist der deutsche Text, {name} sind Platzhalter.
// Unbekannte Schluessel (z. B. dynamische Server-Meldungen) werden unveraendert angezeigt.
const EN = {
  "1 Zugang": "1 Access", "2 CrowdSec": "2 CrowdSec",
  "203.0.113.7 oder 198.51.100.0/24": "203.0.113.7 or 198.51.100.0/24",
  "ASN suchen": "Search ASN", "ASN suchen – Nummer oder Name, z. B. hetzner, AS16509": "Search ASN – number or name, e.g. hetzner, AS16509",
  "ASN-Liste": "ASN list", "ASN-Namensliste": "ASN name list", "ASN-Regel entfernt": "ASN rule removed", "ASN-Regel gespeichert": "ASN rule saved",
  "ASNs": "ASNs", "AS{asn} als Ausnahme gespeichert": "AS{asn} saved as exemption", "AS{asn} als Ausnahme-ASN hinzufügen": "Add AS{asn} as exempt ASN",
  "AS{asn} auswählen": "Select AS{asn}", "AS{asn} entfernen": "Remove AS{asn}", "AS{asn} hinzugefügt": "AS{asn} added",
  "AS{asn} {name} entfernen? Die Ranges werden beim nächsten Anwenden freigegeben.": "Remove AS{asn} {name}? Its ranges are released on the next apply.",
  "AS{asn} {name} ist als Eyeball-Netz (Internetanbieter für Endkunden) eingestuft. Eine Sperre trifft echte Besucher. Trotzdem hinzufügen?":
    "AS{asn} {name} is classified as an eyeball network (consumer ISP). Blocking it hits real visitors. Add anyway?",
  "Abbrechen": "Cancel", "Abmelden": "Sign out", "Afrika": "Africa", "Aktion": "Action", "Aktive Ban-Ranges": "Active ban ranges",
  "Aktive Captcha-Ranges": "Active captcha ranges", "Aktualisierung alle (Stunden)": "Update every (hours)", "Aktuelles Passwort": "Current password",
  "Alle Decisions mit Reason {r} werden aus CrowdSec gelöscht.": "All decisions with reason {r} will be deleted from CrowdSec.",
  "Alle auswählen": "Select all", "Als Ausnahme": "As exemption", "Als Ausnahme hinzufügen": "Add as exemption",
  "Als Wächter-IP überwachen": "Watch this IP", "Alte Decisions entfernen": "Remove old decisions", "Alte Decisions entfernt": "Old decisions removed",
  "Angemeldet": "Signed in", "Anmelden": "Sign in", "Anmeldung": "Authentication", "Ansehen": "View", "Antarktis": "Antarctica",
  "Anwenden": "Apply", "Art": "Type", "Asien": "Asia", "Ausgenommen": "Exempt", "Ausgenommen durch:": "Exempt via:",
  "Auskommentierte Zeilen werden übersprungen.": "Commented-out lines are skipped.", "Ausnahme als": "Exempt as",
  "Ausnahme entfernt": "Exemption removed", "Ausnahme gespeichert": "Exemption saved", "Ausnahme hinzugefügt": "Exemption added",
  "Ausnahme-ASNs": "Exempt ASNs", "Ausnahmen": "Exemptions", "Auswahl aufheben": "Clear selection",
  "Beide Container müssen im selben Docker-Netz sein.": "Both containers must share a Docker network.",
  "Benachrichtigung": "Notifications", "Benutzer": "User", "Benutzer-Header": "User header", "Benutzername": "Username",
  "Bestätigen": "Confirm", "Blockieren": "Block", "Blockiert": "Blocked", "Captcha": "Captcha", "Container-Name": "Container name",
  "CrowdSec ist noch nicht verbunden.": "CrowdSec is not connected yet.", "CrowdSec nicht verbunden": "CrowdSec not connected",
  "CrowdSec-Verbindung": "CrowdSec connection", "CrowdSec-Verbindung geändert": "CrowdSec connection changed",
  "Dafür muss /var/run/docker.sock eingebunden werden. Wer die Oberfläche übernimmt, hat dann Root-Rechte auf dem Host.":
    "This requires mounting /var/run/docker.sock. Whoever takes over the UI then has root on the host.",
  "Decisions des alten Bash-Skripts werden von asn-blocker nicht angefasst. Nach dem ersten erfolgreichen Lauf hier entfernen.":
    "asn-blocker does not touch decisions of the old bash script. Remove them here after the first successful run.",
  "Deine IP {ip} ist aktuell von {action} betroffen. Du riskierst, dich auszusperren.": "Your IP {ip} is currently affected by {action}. You risk locking yourself out.",
  "Deine IP:": "Your IP:", "Den Header muss der Proxy nach erfolgreichem SSO setzen.": "The proxy must set this header after a successful SSO login.",
  "Details": "Details",
  "Die Plausibilitätsprüfung wird übergangen. Die berechneten Ranges werden trotz großer Abweichung übertragen.":
    "The sanity check is skipped. The computed ranges are pushed despite the large deviation.",
  "Diese Instanz erwartet eine Anmeldung über den Reverse Proxy (SSO). Die Anfrage kam nicht über einen vertrauenswürdigen Proxy oder ohne Benutzer-Header.":
    "This instance expects authentication via the reverse proxy (SSO). The request did not come through a trusted proxy or lacked the user header.",
  "Diesen Stand anwenden": "Apply this state", "Docker-Socket (Legacy)": "Docker socket (legacy)",
  "Eigene IP als Ausnahme gespeichert. Jetzt anwenden, damit es wirkt.": "Your IP was saved as an exemption. Apply to make it effective.",
  "Eigener Login mit Passwort": "Built-in login with password",
  "Ein Lauf berechnet die Ranges neu und gleicht sie mit CrowdSec ab. „Vorschau“ ändert nichts.": "A run recomputes the ranges and syncs them with CrowdSec. “Preview” changes nothing.",
  "Eine ASN pro Zeile, optional mit Kommentar:": "One ASN per line, optionally with a comment:",
  "Einmalig im CrowdSec-Container ausführen und das ausgegebene Passwort unten eintragen:": "Run once in the CrowdSec container and enter the printed password below:",
  "Einrichten": "Set up", "Einstellungen": "Settings", "Einstellungen geändert": "Settings changed", "Einstufung laut bgp.tools": "Classification by bgp.tools",
  "Einzelne Adressen oder CIDRs, IPv4 und IPv6.": "Single addresses or CIDRs, IPv4 and IPv6.",
  "Empfohlen: Local API. Kein Docker-Socket nötig.": "Recommended: Local API. No Docker socket needed.", "Endkunden-Netz": "Consumer network",
  "Entfernen": "Remove", "Erfasst durch {action}:": "Covered by {action}:", "Erste 200 von {n} Änderungen.": "First 200 of {n} changes.",
  "Ersteinrichtung": "Initial setup", "Europa": "Europe",
  "Exit-IPs von {name} können von den Einwahl-IPs abweichen und liegen meist in {asn}.": "{name} exit IPs can differ from entry IPs and are usually in {asn}.",
  "Filtern": "Filter", "Format": "Format", "Gespeichert": "Saved", "Gestartet": "Started", "Gotify (Token in der URL)": "Gotify (token in URL)",
  "Gültigkeit einer Sperre (Stunden)": "Decision lifetime (hours)", "Hauptnavigation": "Main navigation", "Header mit Benutzername": "Header with username",
  "Herkunft": "Origin", "Hinweise": "Notices", "Hinzufügen": "Add", "IP oder CIDR": "IP or CIDR",
  "IP oder CIDR des Reverse Proxys, kommagetrennt. Diese Anfrage kam von {ip}.": "IP or CIDR of the reverse proxy, comma separated. This request came from {ip}.",
  "IP prüfen": "Check IP", "IP prüfen …": "Check IP …", "IP-Adresse": "IP address", "IPs und Netze": "IPs and networks", "IPv4-Adressen": "IPv4 addresses",
  "IPv6-Prefixe ebenfalls sperren": "Also block IPv6 prefixes", "Importieren": "Import", "Importiert": "Imported", "Jetzt anwenden": "Apply now",
  "Kein ASN gefunden.": "No ASN found.", "Kein Treffer": "No match", "Kein Zugriff": "No access", "Keine": "None", "Keine ASNs erkannt": "No ASNs recognised",
  "Keine Änderungen an Ranges.": "No range changes.", "Keine öffentliche Adresse.": "Not a public address.",
  "Konfiguration exportieren": "Export configuration", "Konfiguration importieren": "Import configuration", "Konfiguration importiert": "Configuration imported",
  "LAPI-URL": "LAPI URL", "Lade Serverliste …": "Loading server list …", "Lade …": "Loading …", "Lauf": "Run", "Lauf gestartet": "Run started",
  "Lauf wird ausgeführt …": "Run in progress …", "Lege fest, wie die Oberfläche geschützt wird.": "Choose how the interface is protected.",
  "Letzter Lauf": "Last run", "Letzter Lauf fehlgeschlagen ({when}).": "Last run failed ({when}).",
  "Letzter Lauf wurde von der Plausibilitätsprüfung angehalten.": "The last run was stopped by the sanity check.", "Liste einfügen": "Paste list",
  "Local API (empfohlen)": "Local API (recommended)", "Länder filtern": "Filter countries", "Läufe": "Runs", "Machine-ID": "Machine ID",
  "Mindestens 12 Zeichen.": "At least 12 characters.", "Modus": "Mode", "Name": "Name", "Neue Regeln wirken nach „Anwenden“.": "New rules take effect after “Apply”.",
  "Neues Passwort": "New password", "Nicht angemeldet": "Not signed in",
  "Noch keine ASNs. Oben suchen oder eine bestehende Liste einfügen.": "No ASNs yet. Search above or paste an existing list.",
  "Noch keine Einträge.": "No entries yet.", "Noch keine Läufe.": "No runs yet.", "Nordamerika": "North America", "Notiz": "Note",
  "Notiz gespeichert": "Note saved", "Notiz zu AS{asn}": "Note for AS{asn}", "Notiz, z. B. Handy": "Note, e.g. phone",
  "Nur von hier werden X-Forwarded-For und der Benutzer-Header akzeptiert.": "X-Forwarded-For and the user header are only accepted from here.",
  "Nur von hier wird X-Forwarded-For akzeptiert.": "X-Forwarded-For is only accepted from here.", "Nächster Lauf": "Next run", "Ozeanien": "Oceania",
  "Passwort": "Password", "Passwort geändert": "Password changed", "Passwort geändert – bitte neu anmelden": "Password changed – please sign in again",
  "Passwort ändern": "Change password", "Plausibilitätsgrenze (%)": "Sanity limit (%)", "Prefix": "Prefix", "Prefixe": "Prefixes",
  "Prefixe dieser ASNs werden nie gesperrt, z. B. Exit-Netze von VPN-Anbietern.": "Prefixes of these ASNs are never blocked, e.g. VPN providers’ exit networks.",
  "Protokoll": "Log", "Prüfen": "Review", "Ranges aktiv": "ranges active",
  "Ranges werden neu berechnet und mit CrowdSec abgeglichen. Bestehende Sperren bleiben bis zum Abschluss aktiv.": "Ranges are recomputed and synced with CrowdSec. Existing decisions stay active until it finishes.",
  "Regel entfernen": "Remove rule", "Regeln": "Rules", "Regeln anwenden": "Apply rules", "Regeln entfernen": "Remove rules", "Regeln filtern": "Filter rules",
  "Regeln geändert – noch nicht in CrowdSec aktiv.": "Rules changed – not active in CrowdSec yet.",
  "Reverse Proxy mit SSO (Pangolin, Authelia, Authentik …)": "Reverse proxy with SSO (Pangolin, Authelia, Authentik …)", "Schließen": "Close",
  "Server nicht erreichbar.": "Server unreachable.",
  "Server-IPs der gewählten Länder werden aus allen Sperren herausgeschnitten, damit Nutzer dieser VPN-Standorte durchkommen.": "Server IPs of the selected countries are carved out of all blocks so users of these VPN locations get through.",
  "Setup-Token": "Setup token", "Sonstige": "Other", "Spamhaus ASN-DROP": "Spamhaus ASN-DROP", "Speichern": "Save",
  "Sperren werden vor Ablauf erneuert. Fällt asn-blocker aus, laufen sie nach dieser Zeit aus.": "Decisions are renewed before they expire. If asn-blocker stops, they expire after this time.",
  "Sprache wechseln": "Change language", "Stand: zuletzt angewendeter Lauf.": "As of the last applied run.", "Status": "Status",
  "Steht im Container-Log:": "Printed in the container log:", "Südamerika": "South America", "Test gesendet": "Test sent",
  "Test-Benachrichtigung": "Test notification", "Trotzdem anwenden": "Apply anyway", "Typ": "Type", "VPN-Anbieter": "VPN providers",
  "VPN-Ausnahmen": "VPN exemptions", "VPN-Ausnahmen geändert": "VPN exemptions changed", "VPN-Länder ausgenommen": "Exempt VPN countries",
  "VPN-Server stehen meist bei Hostern. Ein ganzes /24 nimmt dort auch fremde Server aus – möglicherweise genau die, die gesperrt werden sollen.":
    "VPN servers usually sit at hosting providers. A whole /24 also exempts other servers there – possibly exactly the ones you want to block.",
  "Verbindung testen und speichern": "Test connection and save", "Vertrauenswürdige Proxy-IPs": "Trusted proxy IPs", "Vertrauenswürdige Proxys": "Trusted proxies",
  "Verwalten": "Manage", "Von": "By", "Vorschau": "Preview", "Vorschau nicht möglich: {e}": "Preview unavailable: {e}",
  "Vorschau wird berechnet …": "Computing preview …", "Wartung": "Maintenance", "Webhook (JSON)": "Webhook (JSON)", "Weiter": "Continue",
  "Weitere Ausnahmen": "Other exemptions",
  "Werden bei jedem Lauf geprüft. Wäre eine davon betroffen, steht es im Lauf-Protokoll und du wirst benachrichtigt. Sie sind keine Ausnahme.":
    "Checked on every run. If one would be affected, it shows in the run log and you get notified. They are not exemptions.",
  "Wächter-IP entfernt": "Watched IP removed", "Wächter-IP hinzugefügt": "Watched IP added", "Wächter-IPs": "Watched IPs",
  "Wächter-IPs betroffen:": "Watched IPs affected:",
  "Wächter-IPs werden nach jedem Lauf geprüft und melden sich, wenn sie gesperrt würden – z. B. die eigene Mobilfunk-IP.": "Watched IPs are checked after every run and alert you if they would be blocked – e.g. your own mobile IP.",
  "Zeit": "Time", "Zeitplan und Sicherheit": "Schedule and safety", "Zugriff": "Access", "Zurücksetzen:": "Reset:",
  "alle": "all", "alle {h} h": "every {h} h", "angehalten": "stopped", "automatisch Captcha": "captcha automatically", "automatisch blockieren": "block automatically",
  "danach Container neu starten.": "then restart the container.", "eigene IP": "own IP", "erfolgreich": "succeeded", "ersetzt": "replaced",
  "exakte Server-IPs": "exact server IPs", "fehlgeschlagen": "failed", "frei": "clear", "ganzes Netz (/24, /64)": "whole network (/24, /64)",
  "gespeichert – leer lassen zum Behalten": "saved – leave empty to keep", "keine": "none", "keine Regel": "no rule", "läuft": "running",
  "nicht betroffen": "not affected", "nicht verbunden": "not connected", "nicht verwenden": "don’t use", "noch nicht geprüft": "not checked yet",
  "noch nie angewendet": "never applied", "startet nach erstem Anwenden": "starts after the first apply", "verbunden ({mode})": "connected ({mode})",
  "wird geladen": "loading",
  "{a} ASN-Regeln, {e} Ausnahmen und {v} VPN-Länder werden ergänzt bzw. überschrieben.": "{a} ASN rules, {e} exemptions and {v} VPN countries will be added or overwritten.",
  "{name} Exit-IPs": "{name} exit IPs", "{name}: {n} Länder gespeichert": "{name}: {n} countries saved",
  "{n} ASN-Regeln entfernen? Die Ranges werden beim nächsten Anwenden freigegeben.": "Remove {n} ASN rules? Their ranges are released on the next apply.",
  "{n} ASNs übernehmen": "Import {n} ASNs", "{n} ASNs übernommen": "{n} ASNs imported", "{n} Decisions entfernt": "{n} decisions removed",
  "{n} Mio.": "{n} M", "{n} Regeln entfernt": "{n} rules removed", "{n} Regeln geändert": "{n} rules changed", "{n} Tsd.": "{n} K",
  "{n} ausgewählt": "{n} selected", "{n} gewählt": "{n} selected", "{n} von {m}": "{n} of {m}", "{v} entfernen": "Remove {v}",
  "Ändern": "Change", "Ändert sich die Anzahl der Ranges stärker, hält ein Lauf an und wartet auf Bestätigung.": "If the number of ranges changes more than this, a run stops and waits for confirmation.",
  "Änderungen": "Changes", "Öffentliche Liste bekannter Abuse-Netze, wird bei jedem Lauf aktualisiert.": "Public list of known abuse networks, refreshed on every run.",
  "Übernehmen": "Import", "Übersicht": "Overview",
  // Meldungen des Servers
  "Verbunden": "Connected", "Nicht angemeldet.": "Not signed in.", "Benutzername oder Passwort falsch": "Wrong username or password",
  "Zu viele Fehlversuche, bitte später erneut versuchen": "Too many failed attempts, please try again later",
  "Setup-Token falsch (steht im Container-Log)": "Wrong setup token (see container log)", "Es läuft bereits ein Lauf": "A run is already in progress",
  "CrowdSec-Verbindung ist noch nicht eingerichtet": "The CrowdSec connection is not set up yet", "Passwort: mindestens 12 Zeichen": "Password: at least 12 characters",
  "Mindestens ein vertrauenswürdiger Proxy (IP/CIDR) nötig": "At least one trusted proxy (IP/CIDR) is required", "Keine gültige IP-Adresse": "Not a valid IP address",
  "Ländercodes müssen zweistellig sein": "Country codes must have two letters", "Mit diesen Proxy-Einstellungen würdest du dich aussperren": "These proxy settings would lock you out",
  "Decision-Dauer muss mindestens das Doppelte des Intervalls sein": "Decision lifetime must be at least twice the interval",
  "Keine Benachrichtigungs-URL gespeichert": "No notification URL saved", "Aktuelles Passwort falsch": "Current password is wrong",
  "Eigene Decisions werden über Läufe verwaltet": "Own decisions are managed by runs", "Lokaler Login ist nicht aktiv": "Built-in login is not active",
  "Ersteinrichtung nicht abgeschlossen": "Initial setup not completed", "Bereits eingerichtet": "Already set up", "Unbekannter Anbieter": "Unknown provider",
  "CSRF-Header fehlt": "CSRF header missing", "Origin passt nicht": "Origin mismatch",
};

let current = null;
export function lang() {
  if (current) return current;
  let saved = null;
  try { saved = localStorage.getItem("asnb-lang"); } catch { /* privater Modus */ }
  current = saved === "de" || saved === "en" ? saved : (navigator.language || "en").toLowerCase().startsWith("de") ? "de" : "en";
  return current;
}
export function setLang(l) {
  current = l;
  try { localStorage.setItem("asnb-lang", l); } catch { /* egal */ }
}
export const locale = () => (lang() === "de" ? "de-DE" : "en-GB");
export function t(key, vars) {
  let s = lang() === "en" ? (EN[key] ?? key) : key;
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  return s;
}
export const _keys = () => Object.keys(EN);
