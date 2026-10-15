"""Wartung: docker exec asn-blocker python -m app.cli reset-auth"""
import sys

from . import db


def main():
    db.init()
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "reset-auth":
        with db.tx() as c:
            db.put("auth_mode", None, c)
            c.execute("DELETE FROM sessions")
        print("Anmeldung zurückgesetzt. Container neu starten – das neue Setup-Token steht dann im Log.")
    else:
        print("Befehle: reset-auth")
        sys.exit(1)


if __name__ == "__main__":
    main()
