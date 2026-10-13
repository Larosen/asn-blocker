"""Persistente Konfiguration (JSON in /data) und Laufzeit-Einstellungen aus ENV."""
import json
import os
import threading
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_FILE = DATA_DIR / "config.json"
STATE_FILE = DATA_DIR / "state.json"

CROWDSEC_CONTAINER = os.environ.get("CROWDSEC_CONTAINER", "crowdsec")
UPDATE_INTERVAL_HOURS = float(os.environ.get("UPDATE_INTERVAL_HOURS", "48"))
DECISION_DURATION = os.environ.get("DECISION_DURATION", "1095d")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
USER_AGENT = os.environ.get("USER_AGENT", "asn-blocker/1.0 (+https://github.com/larosen/asn-blocker)")

# Pro Aktionstyp ein eigener Decision-"Reason", damit alte Eintraege gezielt entfernt werden koennen
REASONS = {"ban": "asn-blocker ban", "captcha": "asn-blocker captcha"}

DEFAULT_CONFIG = {
    # {"asn": 16509, "name": "AMAZON-02", "action": "ban"|"captcha", "note": ""}
    "asns": [],
    # {"provider": "nordvpn", "country": "DE"}
    "vpn_whitelist": [],
    # ASNs, deren Prefixe nie blockiert werden (z.B. 207137 PacketHub / NordVPN-Exit-IPs)
    "exempt_asns": [],
    # einzelne IPs/CIDRs
    "manual_exempt": [],
    # VPN-Server-IPs auf /24 (v4) bzw. /64 (v6) erweitern, Exit-IPs liegen oft im selben Netz
    "widen_vpn_ips": True,
    "include_ipv6": False,
}

_lock = threading.RLock()


def _read(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return json.loads(json.dumps(default))


def _write(path: Path, data) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.replace(path)


def load_config() -> dict:
    with _lock:
        cfg = _read(CONFIG_FILE, DEFAULT_CONFIG)
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        return cfg


def save_config(cfg: dict) -> None:
    with _lock:
        _write(CONFIG_FILE, cfg)


def load_state() -> dict:
    with _lock:
        return _read(STATE_FILE, {"last_run": None, "next_run": None, "running": False, "log": [], "stats": {}})


def save_state(state: dict) -> None:
    with _lock:
        _write(STATE_FILE, state)
