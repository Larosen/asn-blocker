"""Compute the desired state and reconcile it with CrowdSec (diff sync).

Flow: load all sources -> compute desired ranges -> sanity check ->
create new/refreshed decisions -> only then delete obsolete ones.
So there is never a gap without protection; any error before writing leaves CrowdSec unchanged.
"""
import ipaddress
import json
import logging
import threading
import time
from collections import defaultdict

from . import attackers, crowdsec, db, netset, notify, selfprotect, sources

REASONS = {"ban": "asn-blocker ban", "captcha": "asn-blocker captcha"}
# Never blocked, whatever a source says: private, loopback, link-local, CGNAT, documentation, multicast, reserved
NON_PUBLIC = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
    "::/8", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8")]
# Shorter prefixes are never announced by a single real ASN
MIN_PREFIXLEN = {4: 8, 6: 16}
# Hard caps even on the first run: about 12 % of the IPv4 space, 2^36 IPv6 /48s (as much as a /12, of 2000::/3),
# and a number of ranges far above any realistic configuration (16k for 40 large hosting ASNs)
MAX_V4_ADDRESSES = 2**29
MAX_V6_48S = 2**36
MAX_RANGES = 150000
_lock = threading.Lock()
log_ = logging.getLogger("asn_blocker.engine")


class Busy(RuntimeError):
    pass


class Blocked(RuntimeError):
    """Sanity check tripped - needs confirmation. Carries every reason, not just the first."""

    def __init__(self, reasons):
        self.reasons = [reasons] if isinstance(reasons, str) else list(reasons)
        super().__init__("; ".join(self.reasons))


CONFIRM_TOLERANCE = 5  # % a confirmed run's result may differ from the stopped run the user reviewed


# --- Desired state -------------------------------------------------------------------------

def rules():
    asn_rules = {r["asn"]: r for r in db.q("SELECT * FROM asn_rules")}
    return asn_rules


def build(log, fresh=True):
    ipv6 = db.get("include_ipv6")
    modes = db.get("vpn_modes") or {}

    log("Collecting exemptions")
    exempt = []  # (network, label)
    by_provider = defaultdict(list)
    for r in db.q("SELECT provider, country FROM vpn_rules ORDER BY provider, country"):
        by_provider[r["provider"]].append(r["country"])
    for pid, countries in by_provider.items():
        prov = sources.PROVIDERS.get(pid)
        if not prov:
            raise sources.SourceError(f"Unknown VPN provider {pid}")
        if fresh:
            prov.entries(fresh=True)  # same validation and limits as every other read
        widen = modes.get(pid) == "net"
        for cc in countries:
            ips = prov.ips(cc)
            if not ips:
                raise sources.SourceError(f"{prov.name} {cc}: no server IPs found")
            for ip in ips:
                a = ipaddress.ip_address(ip)
                plen = (24 if a.version == 4 else 64) if widen else a.max_prefixlen
                exempt.append((ipaddress.ip_network(f"{ip}/{plen}", strict=False), f"VPN {prov.name} {cc}"))
            log(f"  {prov.name} {cc}: {len(ips)} server IPs" + (" (as network)" if widen else ""))

    ex_asns = [int(r["value"]) for r in db.q("SELECT value FROM exemptions WHERE kind='asn'")]
    for asn, p in sources.prefixes_many(ex_asns, use_cache=not fresh).items():
        if not p:
            raise sources.SourceError(f"Exempt AS{asn}: no prefixes")
        exempt += [(n, f"Exempt AS{asn}") for n in _plausible(netset.parse(p), f"exempt AS{asn}", log)]
        log(f"  Exempt AS{asn}: {len(p)} prefixes")
    for r in db.q("SELECT value, note FROM exemptions WHERE kind='cidr'"):
        exempt += [(n, "Manual" + (f": {r['note']}" if r["note"] else "")) for n in netset.parse([r["value"]])]

    exempt += [(n, "Non-public range") for n in NON_PUBLIC]
    guard = guard_ips()
    exempt += [(ipaddress.ip_network(ip), label) for ip, label in guard.items()]
    prot_asns = sorted(selfprotect.protected_asns())
    for asn, p in sources.prefixes_many(prot_asns, use_cache=not fresh).items():
        if not p:  # fail closed like exempt ASNs: better no run than a run without the protection
            raise sources.SourceError(f"Self-protection AS{asn}: no prefixes")
        exempt += [(n, f"Self-protection AS{asn}") for n in _plausible(netset.parse(p), f"protected AS{asn}", log)]
    log(f"  Self-protection: {len(guard)} IPs, {len(prot_asns)} ASNs")

    log("Collecting ASN ranges")
    asn_rules = rules()
    if db.get("spamhaus_asndrop"):
        drop = sources.spamhaus_asndrop(use_cache=not fresh)
        added = 0
        for d in drop:
            if d["asn"] not in asn_rules:
                asn_rules[d["asn"]] = {"asn": d["asn"], "name": d["name"], "action": db.get("spamhaus_asndrop"), "spamhaus": True}
                added += 1
        log(f"  Spamhaus ASN-DROP: {len(drop)} ASNs, {added} of them additional")
    for asn in set(asn_rules) & set(prot_asns):
        log(f"  AS{asn} is protected (self-protection) – rule ignored")
        del asn_rules[asn]
    raw = {"ban": [], "captcha": []}
    prefixes = sources.prefixes_many(asn_rules, use_cache=not fresh)
    spamhaus = [0, 0]  # ASNs, prefixes – summarized instead of hundreds of individual lines
    for asn, r in sorted(asn_rules.items()):
        nets = [n for n in netset.parse(prefixes[asn]) if ipv6 or n.version == 4]
        nets = _plausible(nets, f"AS{asn}", log)
        raw[r["action"]] += nets
        if r.get("spamhaus"):
            spamhaus[0] += 1
            spamhaus[1] += len(nets)
        else:
            log(f"  AS{asn} {r.get('name') or sources.asn_name(asn)} -> {r['action']}: {len(nets)} prefixes")
    if spamhaus[0]:
        log(f"  Spamhaus ASN-DROP -> {db.get('spamhaus_asndrop')}: {spamhaus[0]} ASNs, {spamhaus[1]} prefixes")

    log("Carving out exemptions")
    ex_nets = [n for n, _ in exempt]
    ban = netset.subtract(raw["ban"], ex_nets)
    captcha = netset.subtract(raw["captcha"], ex_nets + ban)  # captcha only where not already banned
    log(f"  ban: {len(ban)} ranges, captcha: {len(captcha)} ranges, {len(netset.collapse(ex_nets))} exempt networks")
    # hard final check: no protected IP may end up in a block
    for ip, label in guard.items():
        hit = status_of(str(ipaddress.ip_network(ip).network_address), {"ban": [str(n) for n in ban], "captcha": [str(n) for n in captcha]})
        if hit:
            raise sources.SourceError(f"Self-protection violated: {ip} ({label}) would be hit by {hit} – run aborted")
    return {"ban": [str(n) for n in ban], "captcha": [str(n) for n in captcha]}, \
        [(str(n), label) for n, label in exempt]


def _plausible(nets, what, log):
    """No real ASN announces prefixes shorter than MIN_PREFIXLEN – from a broken or poisoned source they would block
    (or, as exemption, unblock) huge parts of the internet."""
    huge = [n for n in nets if n.prefixlen < MIN_PREFIXLEN[n.version]]
    if huge:
        log(f"  WARNING {what}: ignored implausibly large prefixes {', '.join(map(str, huge[:5]))}")
    return [n for n in nets if n.prefixlen >= MIN_PREFIXLEN[n.version]]


def _canonical(ip):
    """IPv4-mapped IPv6 (::ffff:a.b.c.d) protects the IPv4 address it stands for."""
    a = ipaddress.ip_address(str(ip).split("/")[0])
    return str(ipaddress.ip_network(a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a))


def guard_ips():
    """All IPs that must never be blocked: protected IPs + active SSH sessions. {ip_cidr: label}"""
    out = {}
    for r in db.q("SELECT value, note FROM protected WHERE kind='ip'"):
        out[_canonical(r["value"])] = "Self-protection" + (f": {r['note']}" if r["note"] else "")
    sessions, _ = selfprotect.ssh_sessions()
    for s in sessions:
        out.setdefault(_canonical(s["ip"]), f"SSH session {s['user']}@{s['line']}")
    return out


# --- Reconcile ----------------------------------------------------------------------------------

def diff(desired, current, refresh_before):
    """current: list of {id,value,until}. Returns (add, delete_ids, refresh_count)."""
    by_value = defaultdict(list)
    for d in current:
        by_value[d["value"]].append(d)
    want = set(desired)
    add, delete, refresh = [], [], 0
    for v in desired:
        ds = sorted(by_value.get(v, []), key=lambda d: d["until"], reverse=True)
        if not ds:
            add.append(v)
        elif ds[0]["until"] < refresh_before:
            add.append(v)
            delete += [d["id"] for d in ds]
            refresh += 1
        else:
            delete += [d["id"] for d in ds[1:]]  # duplicates
    for v, ds in by_value.items():
        if v not in want:
            delete += [d["id"] for d in ds]
    return add, delete, refresh


def _counts():
    return {t: db.q1("SELECT count(*) n FROM applied WHERE type=?", (t,))["n"] for t in REASONS}


def _space(cidrs):
    """Blocked address space: IPv4 addresses and IPv6 /48 networks."""
    v4 = v6 = 0
    for n in netset.parse(cidrs):
        if n.version == 4:
            v4 += n.num_addresses
        else:
            v6 += max(1, n.num_addresses >> 80)
    return v4, v6


def _sanity(desired, force=False, confirmed=None):
    """force: skip all checks. confirmed: summary of the stopped run the user reviewed and accepted. A result within
    CONFIRM_TOLERANCE of it is applied; one that changed since the review goes through the normal checks again, so a
    confirmation never waves through data the user has not seen."""
    if force:
        return
    new = sum(len(v) for v in desired.values())
    changed = []
    if confirmed is not None:
        changed = [f"{t} ranges changed from {confirmed.get(t, 0):,} to {len(v):,} since the run you confirmed"
                   for t, v in desired.items()
                   if abs(len(v) - confirmed.get(t, 0)) > max(confirmed.get(t, 0), 1) * CONFIRM_TOLERANCE / 100]
        if not changed:
            return
    prev = sum(_counts().values())
    reasons = []
    if new > MAX_RANGES:
        reasons.append(f"{new:,} ranges would be pushed, more than the limit of {MAX_RANGES:,}")
    v4, v6 = _space([c for v in desired.values() for c in v])
    if v4 > MAX_V4_ADDRESSES:
        reasons.append(f"{v4:,} IPv4 addresses would be blocked ({v4 / 2**32:.1%} of IPv4), "
                       f"more than the limit of {MAX_V4_ADDRESSES:,}")
    if v6 > MAX_V6_48S:
        reasons.append(f"{v6:,} IPv6 /48 networks would be blocked, more than the limit of {MAX_V6_48S:,}")
    if new == 0 and (db.q1("SELECT 1 x FROM asn_rules") or db.get("spamhaus_asndrop")):
        reasons.append("Rules exist, but 0 ranges computed")
    if prev:
        pv4, pv6 = _space([r["value"] for r in db.q("SELECT value FROM applied")])
        limit = db.get("sanity_percent")
        for label, before, after in (("IPv4 address space", pv4, v4), ("IPv6 address space", pv6, v6)):
            if before and abs(after - before) / before * 100 > limit:
                reasons.append(f"Blocked {label} changes by {abs(after - before) / before * 100:.0f} % "
                               f"({before:,} -> {after:,}), limit {limit} %")
            if not before and after > 2**24:  # IPv6 newly enabled: more than a /24 worth of /48s needs confirmation
                reasons.append(f"Blocked {label} grows from 0 to {after:,} /48 networks (IPv6 newly enabled)")
        pct = abs(new - prev) / prev * 100
        if pct > limit:
            reasons.append(f"Range count changes by {pct:.0f} % ({prev:,} -> {new:,}), limit {limit} %")
    if reasons:  # a result that changed since the review only needs a new confirmation if it trips a check itself
        raise Blocked(changed + reasons)


def status_of(ip, ranges):
    """'ban' | 'captcha' | None for an IP against {type: [cidr]}"""
    for t in ("ban", "captcha"):
        if netset.contains(ranges.get(t, []), ip):
            return t
    return None


def run(kind, user, force=False, confirmed=None):
    """kind: 'plan' (compute only) or 'apply'. confirmed: (run id, summary) of the stopped run the user accepted.
    Returns the run ID."""
    if not _lock.acquire(blocking=False):
        raise Busy("A run is already in progress")
    try:
        with db.tx() as c:
            run_id = c.execute("INSERT INTO runs(kind,status,triggered_by,started_at) VALUES(?,?,?,?)",
                               (kind, "running", user, time.time())).lastrowid
        lines = []

        def log(msg):
            msg = sources.clean(msg, 600)  # external text must not forge lines in the run log or stdout
            line = f"{time.strftime('%H:%M:%S')} {msg}"
            log_.info(msg, extra={"run_id": run_id})
            lines.append(line)
            with db.tx() as c:
                c.execute("UPDATE runs SET log=? WHERE id=?", ("\n".join(lines), run_id))

        status, summary = "failed", {}
        rev = db.get("config_rev")
        try:
            desired, exempt = build(log, fresh=(kind == "apply"))
            summary = {t: len(v) for t, v in desired.items()}
            try:
                backend = crowdsec.backend()
            except crowdsec.CrowdSecError:
                if kind == "apply":
                    raise
                backend = None
            refresh_before = time.time() + db.get("interval_hours") * 3600 * 2
            changes, plan = [], {}
            for t, reason in REASONS.items():
                if backend:
                    current = backend.list(reason)
                else:
                    current = [{"id": None, "value": r["value"], "until": float("inf")}
                               for r in db.q("SELECT value FROM applied WHERE type=?", (t,))]
                add, delete, refresh = diff(desired[t], current, refresh_before)
                removed = {d["value"] for d in current} - set(desired[t])
                new = set(add) - {d["value"] for d in current}
                plan[t] = (add, delete)
                summary[f"{t}_added"], summary[f"{t}_removed"], summary[f"{t}_refreshed"] = len(new), len(removed), refresh
                changes += [(run_id, "+", t, v) for v in sorted(new)] + [(run_id, "-", t, v) for v in sorted(removed)]
                log(f"Plan {t}: +{len(new)} new, -{len(removed)} removed, {refresh} refreshed")
            with db.tx() as c:
                c.executemany("INSERT INTO run_changes VALUES(?,?,?,?)", changes)

            watch = {}
            for w in db.q("SELECT ip FROM watch_ips"):
                watch[w["ip"]] = status_of(w["ip"], desired)
                if watch[w["ip"]]:
                    log(f"WARNING watch IP {w['ip']} would be affected: {watch[w['ip']]}")
            summary["watch_hits"] = [ip for ip, s in watch.items() if s]

            if kind == "apply":
                _sanity(desired, force, confirmed[1] if confirmed else None)
                if confirmed:
                    log(f"Confirmed by {user} after review of run #{confirmed[0]}")
                log("Pushing changes to CrowdSec")
                for t, reason in REASONS.items():  # all additions first: no gap when a range moves ban <-> captcha
                    if plan[t][0]:
                        backend.add(plan[t][0], t, reason, db.get("decision_hours") * 3600)
                for t in REASONS:
                    if plan[t][1]:
                        backend.delete_ids(plan[t][1])
                for t, reason in REASONS.items():
                    active = {d["value"] for d in backend.list(reason)}
                    missing = set(desired[t]) - active
                    extra = active - set(desired[t])
                    summary[f"{t}_active"] = len(active)
                    log(f"  {t}: {len(active)} active" + (f", MISSING {len(missing)}" if missing else "")
                        + (f", EXTRA {len(extra)}" if extra else ""))
                    if missing:
                        raise crowdsec.CrowdSecError(f"{len(missing)} {t} ranges missing after import")
                with db.tx() as c:
                    c.execute("DELETE FROM applied")
                    c.executemany("INSERT INTO applied VALUES(?,?)", [(t, v) for t, vs in desired.items() for v in vs])
                    c.execute("DELETE FROM exempt_index")
                    c.executemany("INSERT INTO exempt_index VALUES(?,?)", exempt)
                    for ip, s in watch.items():
                        c.execute("UPDATE watch_ips SET last_status=? WHERE ip=?", (s or "clear", ip))
                    db.put("applied_rev", rev, c)
                if summary["watch_hits"]:
                    notify.send("asn-blocker: watch IP affected",
                                "Affected by the current rules: " + ", ".join(f"{ip} ({watch[ip]})" for ip in summary["watch_hits"]),
                                "warning", run_id)
            status = "ok"
            log("Done")
        except Blocked as e:
            status = "blocked"
            summary["stopped"] = e.reasons
            for r in e.reasons:
                log(f"STOPPED: {r}")
            log("CrowdSec unchanged – confirm in the UI to apply anyway.")
            notify.send("asn-blocker: run stopped", f"{e}. CrowdSec is unchanged – review and confirm the run.",
                        "warning", run_id)
        except (sources.SourceError, crowdsec.CrowdSecError) as e:
            log(f"ERROR: {e}")
            if kind == "apply":
                notify.send("asn-blocker: run failed", f"{e}. The active decisions stay until they expire.",
                            "error", run_id)
        except Exception as e:  # noqa: BLE001
            log(f"ERROR (unexpected): {e!r}")
            log_.exception("Unexpected error in run %s", run_id)
            if kind == "apply":
                notify.send("asn-blocker: run failed", f"Unexpected error: {e!r}", "error", run_id)
        with db.tx() as c:
            c.execute("UPDATE runs SET status=?, finished_at=?, summary=? WHERE id=?",
                      (status, time.time(), json.dumps(summary), run_id))
            # limit history
            c.execute("DELETE FROM run_changes WHERE run_id IN (SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET 100)")
            c.execute("DELETE FROM runs WHERE id IN (SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET 100)")
        return run_id
    finally:
        _lock.release()


_preview = {"rev": None, "result": None}
_preview_lock = threading.Lock()


def preview():
    """Quick preview for the apply bar: desired state (from caches) vs. last applied state."""
    rev = db.get("config_rev")
    if _preview["rev"] == rev:
        return _preview["result"]
    if not _preview_lock.acquire(blocking=False):
        return {"busy": True}
    try:
        try:
            desired, _ = build(lambda _msg: None, fresh=False)
        except sources.SourceError as e:
            return {"error": str(e)}
        result = {"rev": rev}
        for t in REASONS:
            applied = {r["value"] for r in db.q("SELECT value FROM applied WHERE type=?", (t,))}
            want = set(desired[t])
            result[t] = {"total": len(want), "add": len(want - applied), "remove": len(applied - want)}
        _preview.update(rev=rev, result=result)
        return result
    finally:
        _preview_lock.release()


def is_running():
    return _lock.locked()


# --- IP check --------------------------------------------------------------------------------------

def check_ip(ip):
    ip = str(ipaddress.ip_address(ip))
    applied = defaultdict(list)
    for r in db.q("SELECT type, value FROM applied"):
        applied[r["type"]].append(r["value"])
    hits = {t: netset.contains(v, ip) for t, v in applied.items()}
    a = ipaddress.ip_address(ip)
    exempt = sorted({r["label"] for r in db.q("SELECT cidr, label FROM exempt_index")
                     if a in ipaddress.ip_network(r["cidr"])})
    manual = [r["value"] for r in db.q("SELECT value FROM exemptions WHERE kind='cidr'")
              if a in ipaddress.ip_network(r["value"], strict=False)]
    out = {"ip": ip, "status": status_of(ip, applied), "ranges": {t: [str(n) for n in v] for t, v in hits.items() if v},
           "exempt": exempt or (["Manual"] if manual else []), "asns": [], "global": a.is_global}
    if a.is_global:
        try:
            info = sources.ip_info(ip)
            out["prefix"] = info["prefix"]
            for asn in info["asns"]:
                r = db.q1("SELECT action FROM asn_rules WHERE asn=?", (asn,))
                n = db.q1("SELECT class FROM asn_names WHERE asn=?", (asn,))
                out["asns"].append({"asn": asn, "name": sources.asn_name(asn), "rule": r["action"] if r else None,
                                    "class": n["class"] if n else ""})
        except sources.SourceError as e:
            out["lookup_error"] = str(e)
        out["vpn_near"] = _vpn_neighbours(a)
    return out


def _vpn_neighbours(a):
    """VPN servers listed in the same /24 (IPv6 /64) as the address. Exit IPs often differ from the listed server
    IPs but sit next to them – then the address is most likely a VPN exit. Uses cached lists only."""
    net = ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 64}", strict=False)
    selected = {(r["provider"], r["country"]) for r in db.q("SELECT provider, country FROM vpn_rules")}
    modes = db.get("vpn_modes") or {}
    out = []
    for pid, prov in sources.PROVIDERS.items():
        near = set()
        for cc, _, v in db.cache_get(f"vpn:{pid}", float("inf")) or []:
            try:
                if ipaddress.ip_address(v) in net:
                    near.add(cc)
            except ValueError:
                continue  # hostname entries
        out += [{"provider": pid, "name": prov.name, "country": cc, "selected": (pid, cc) in selected,
                 "mode": modes.get(pid, "exact")} for cc in sorted(near)]
    return out[:10]


# --- Scheduler -------------------------------------------------------------------------------------------

def _last_apply():
    return db.q1("SELECT status, started_at FROM runs WHERE kind='apply' AND status!='running' ORDER BY id DESC LIMIT 1")


def next_due():
    """Time of the next automatic run, or None (never applied manually yet)."""
    last = _last_apply()
    if not last or not db.get("crowdsec_mode"):
        return None
    wait = db.get("interval_hours") * 3600 if last["status"] in ("ok", "blocked") else 3600
    return last["started_at"] + wait


def scheduler():
    last_prune = last_attackers = 0.0
    while True:
        try:
            due = next_due()
            if due and due <= time.time() and not is_running():
                run("apply", "scheduler")
            if time.time() - last_prune > 86400:
                db.prune()
                last_prune = time.time()
            if db.get("crowdsec_mode") and time.time() - (db.get("attackers_updated") or 0) > 3600 \
                    and time.time() - last_attackers > 900:
                last_attackers = time.time()
                try:
                    attackers.collect()
                except (crowdsec.CrowdSecError, sources.SourceError) as e:
                    log_.warning("Attackers: %s", e)
            updated = db.get("asn_names_updated") or 0
            if time.time() - updated > 7 * 86400:
                try:
                    n = sources.refresh_asn_names()
                    log_.info("ASN name list updated: %d entries", n)
                except sources.SourceError as e:
                    log_.warning("ASN name list: %s", e)
                    db.put("asn_names_updated", time.time() - 6 * 86400)  # retry in 1 day
        except Busy:
            pass
        except Exception:  # noqa: BLE001
            log_.exception("Scheduler error")
        time.sleep(30)
