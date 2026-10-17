import os
import tempfile

import pytest

os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="asnb-test-")


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch, tmp_path):
    from app import auth, db

    auth._failed.clear()
    from app import notify
    notify._tested.clear()

    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "DB_FILE", tmp_path / "t.db")
    db._local.__dict__.clear()
    db.init()
    yield
    db._local.__dict__.clear()


class FakeBackend:
    """Behaves like the LAPI: decisions with ID, expiry time and scenario."""

    def __init__(self):
        self.decisions, self.next_id, self.calls = [], 1, []

    def test(self):
        return "ok"

    def list(self, reason):
        import time

        return [d for d in self.decisions if d["reason"] == reason and d["until"] > time.time()]

    def add(self, values, typ, reason, duration_s):
        import time

        self.calls.append(("add", typ, len(values)))
        for v in values:
            self.decisions.append({"id": self.next_id, "value": v, "type": typ, "reason": reason, "until": time.time() + duration_s})
            self.next_id += 1

    def delete_ids(self, ids):
        self.calls.append(("delete", len(ids)))
        ids = set(ids)
        self.decisions = [d for d in self.decisions if d["id"] not in ids]

    def delete_scenario(self, reason):
        n = len([d for d in self.decisions if d["reason"] == reason])
        self.decisions = [d for d in self.decisions if d["reason"] != reason]
        return n
