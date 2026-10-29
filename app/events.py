"""Change notifications for the live updates in the UI (Server-Sent Events, api/events.py).

Every change that the UI shows bumps a version counter: the configuration (config_rev), runs (start, phase, progress,
log, end) and background loads. The SSE endpoint sends the current state whenever the version moved, so the browser
no longer polls. In-process only – the app runs as a single worker.
"""
import threading

_cond = threading.Condition()
_version = 0
_run = {}


def changed():
    global _version
    with _cond:
        _version += 1
        _cond.notify_all()


def run_state(**state):
    """The run in progress: id, kind, phase, progress (0..1); run_state() clears it."""
    with _cond:
        _run.clear()
        _run.update(state)
    changed()


def snapshot():
    with _cond:
        return _version, dict(_run)
