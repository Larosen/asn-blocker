# Development

```bash
pip install --require-hashes --no-deps -r requirements.txt && pip install -r requirements-dev.txt
ruff check app tests && pytest -q
DATA_DIR=./data uvicorn app.main:app --reload --port 8080
```

## Layout

- `app/api/`: HTTP routers, one per area
- `app/store/`: data access, one module per area; every table has exactly one owner (`tests/test_architecture.py`)
- `app/engine.py`: computes the desired state and applies it; `app/policy.py`: how rules combine
- `app/sources.py`, `app/routing.py`: external data and the local routing table; `app/crowdsec.py`: LAPI and Docker
- `app/static/`: the web UI, Preact components written with htm as plain ES modules, no build step.
  `js/lib.js` (rendering, API client, shared store), `js/shell.js` (navigation, apply bar), `js/views/` (one module
  per page), `js/icons.js`. Preact and htm are vendored in `app/static/vendor/` (versions and checksums in its README).

Schema changes: append a step to `MIGRATIONS` in `app/db.py`. It runs once per database, in order.

## Tests

- UI tests (Playwright and axe) run against an offline demo server with fixed example data:
  `cd tests/ui && npm ci && npx playwright install chromium && npm test`.
  The demo server is useful on its own: `python tests/ui/server.py /tmp/asnb-demo 8090`, sign in as `admin` /
  `correct-horse-battery`. `npm run screenshots` recreates the images in `docs/screenshots/`.
- `tests/contract.json` records the API routes and the shape of the read endpoints. Record an intended change with
  `UPDATE_CONTRACT=1 pytest tests/test_contract.py`.
- Against a real LAPI: set `CROWDSEC_LAPI_URL`, `CROWDSEC_MACHINE_ID` and `CROWDSEC_PASSWORD`, then run
  `pytest tests/test_lapi_integration.py`. CI does this against CrowdSec on every push.

## Dependencies

Direct pins are in `requirements.in`. `requirements.txt` is the hash-locked set:
`uv pip compile requirements.in --universal --python-version 3.14 --generate-hashes -o requirements.txt`.
