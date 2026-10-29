"""Runs (history, log, changes) and the last applied state (ranges and the origin of every exemption)."""
import json
import time
from collections import defaultdict

from .. import db
from . import watch

KEEP = 100  # runs kept in the history


def _row(r):
    if r and r.get("summary"):
        r["summary"] = json.loads(r["summary"])
    return r


def create(kind, user):
    with db.tx() as c:
        return c.execute("INSERT INTO runs(kind,status,triggered_by,started_at) VALUES(?,?,?,?)",
                         (kind, "running", user, time.time())).lastrowid


def set_log(run_id, text):
    with db.tx() as c:
        c.execute("UPDATE runs SET log=? WHERE id=?", (text, run_id))


def add_changes(rows):
    """rows: [(run_id, '+'|'-', type, value)]"""
    with db.tx() as c:
        c.executemany("INSERT INTO run_changes VALUES(?,?,?,?)", rows)


def finish(run_id, status, summary):
    with db.tx() as c:
        c.execute("UPDATE runs SET status=?, finished_at=?, summary=? WHERE id=?", (status, time.time(), json.dumps(summary), run_id))
        c.execute("DELETE FROM run_changes WHERE run_id IN (SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET ?)", (KEEP,))
        c.execute("DELETE FROM runs WHERE id IN (SELECT id FROM runs ORDER BY id DESC LIMIT -1 OFFSET ?)", (KEEP,))


def mark_interrupted():
    """After a restart: runs that were in progress did not finish."""
    with db.tx() as c:
        c.execute("UPDATE runs SET status='failed', finished_at=? WHERE status='running'", (time.time(),))


def listing(limit=30):
    return [_row(r) for r in db.q("SELECT id,kind,status,triggered_by,started_at,finished_at,summary FROM runs "
                                  "ORDER BY id DESC LIMIT ?", (limit,))]


def get(run_id):
    r = _row(db.q1("SELECT * FROM runs WHERE id=?", (run_id,)))
    if r:
        r["changes"] = db.q("SELECT op,type,value FROM run_changes WHERE run_id=? LIMIT 500", (run_id,))
    return r


def last_apply(finished=False):
    """The latest apply run (summary decoded); finished=True skips one still in progress."""
    return _row(db.q1("SELECT id,status,started_at,finished_at,summary,triggered_by FROM runs WHERE kind='apply' "
                      "AND (? = 0 OR status != 'running') ORDER BY id DESC LIMIT 1", (int(finished),)))


# --- Applied state ---------------------------------------------------------------------------------------

def applied():
    """{type: [cidr]} as last pushed to CrowdSec."""
    out = defaultdict(list)
    for r in db.q("SELECT type, value FROM applied"):
        out[r["type"]].append(r["value"])
    return dict(out)


def applied_values(typ=None):
    if typ:
        return [r["value"] for r in db.q("SELECT value FROM applied WHERE type=? ORDER BY value", (typ,))]
    return [r["value"] for r in db.q("SELECT value FROM applied")]


def applied_counts(types):
    return {t: db.q1("SELECT count(*) n FROM applied WHERE type=?", (t,))["n"] for t in types}


def exempt_index():
    """[(cidr, label)] – what was exempted in the last applied run, and why."""
    return [(r["cidr"], r["label"]) for r in db.q("SELECT cidr, label FROM exempt_index")]


def commit_apply(desired, exempt, watch_status, rev):
    """One transaction after a successful push: applied ranges, exemption index, watched IPs and applied_rev."""
    with db.tx() as c:
        c.execute("DELETE FROM applied")
        c.executemany("INSERT INTO applied VALUES(?,?)", [(t, v) for t, vs in desired.items() for v in vs])
        c.execute("DELETE FROM exempt_index")
        c.executemany("INSERT INTO exempt_index VALUES(?,?)", exempt)
        watch.set_status(watch_status, c)
        db.put("applied_rev", rev, c)
