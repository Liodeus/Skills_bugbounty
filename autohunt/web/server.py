#!/usr/bin/env python3
"""autohunt web dashboard — read-only FastAPI server over an autohunt data/ dir.

Serves a single-page dashboard + a read-only JSON API + SSE streams (data-change events and a
live run.log tail). Nothing here writes to the data dir. Binds 127.0.0.1 by default.

Run:
  python autohunt/web/server.py --data-dir data --host 127.0.0.1 --port 8675
  # deps: pip install -r autohunt/web/requirements.txt   (fastapi, uvicorn, markdown)
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent))
from data import DataStore  # noqa: E402

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
REPO = HERE.parents[1]

app = FastAPI(title="autohunt dashboard")
STORE: DataStore = None  # set in main()
READ_ONLY = False        # set in main() via --read-only


def store() -> DataStore:
    return STORE


def _require_write():
    if READ_ONLY:
        return JSONResponse({"error": "read-only mode"}, status_code=403)
    return None


# --------------------------------------------------------------------------- #
# pages / static
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/config")
def api_config():
    return {"read_only": READ_ONLY, "stop": store().stop_state()}


# --------------------------------------------------------------------------- #
# read-only JSON API
# --------------------------------------------------------------------------- #
@app.get("/api/overview")
def api_overview():
    return store().overview()


@app.get("/api/programs")
def api_programs():
    return store().programs()


@app.get("/api/programs/{slug}")
def api_program(slug: str):
    d = store().program(slug)
    if d is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return d


@app.get("/api/findings")
def api_findings():
    return store().findings()


@app.get("/api/leads")
def api_leads():
    return store().leads()


@app.get("/api/runs")
def api_runs():
    return store().runs()


@app.get("/api/severity-matrix")
def api_sevmatrix():
    return store().severity_matrix()


@app.get("/api/cost")
def api_cost():
    return store().cost()


@app.get("/api/changes")
def api_changes():
    return store().changes()


@app.get("/api/report/{slug}/{filename}")
def api_report(slug: str, filename: str):
    html = store().report_html(slug, filename)
    if html is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"slug": slug, "filename": filename, "html": html})


# --------------------------------------------------------------------------- #
# triage actions (write; disabled with --read-only)
# --------------------------------------------------------------------------- #
@app.post("/api/stop")
async def api_stop(request: Request):
    ro = _require_write()
    if ro:
        return ro
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {"stop": store().set_stop(bool(body.get("on", True)))}


@app.post("/api/rehunt/{slug}")
def api_rehunt(slug: str):
    ro = _require_write()
    if ro:
        return ro
    return JSONResponse({"ok": store().mark_rehunt(slug)})


@app.post("/api/leads/{slug}/{lead_id}")
async def api_lead_status(slug: str, lead_id: str, request: Request):
    ro = _require_write()
    if ro:
        return ro
    try:
        body = await request.json()
    except Exception:
        body = {}
    ok = store().set_lead_status(slug, lead_id, body.get("status", "dismissed"))
    return JSONResponse({"ok": ok}, status_code=200 if ok else 400)


# --------------------------------------------------------------------------- #
# SSE streams
# --------------------------------------------------------------------------- #
def _mtime(p: Path):
    try:
        return p.stat().st_mtime
    except OSError:
        return None


@app.get("/api/stream/events")
async def stream_events(request: Request):
    async def gen():
        watch = store().watch_paths()
        last = {k: _mtime(p) for k, p in watch.items()}
        yield "event: ping\ndata: connected\n\n"
        while True:
            if await request.is_disconnected():
                break
            await asyncio.sleep(1.5)
            changed = []
            for k, p in watch.items():
                m = _mtime(p)
                if m != last.get(k):
                    last[k] = m
                    changed.append(k)
            if changed:
                yield f"event: update\ndata: {json.dumps({'changed': changed})}\n\n"
            else:
                yield ": keepalive\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/stream/log")
async def stream_log(request: Request):
    async def gen():
        p = store().hunts / "run.log"
        pos = p.stat().st_size if p.exists() else 0
        yield "event: ping\ndata: log-connected\n\n"
        while True:
            if await request.is_disconnected():
                break
            await asyncio.sleep(1.0)
            if not p.exists():
                continue
            size = p.stat().st_size
            if size < pos:  # rotated/truncated
                pos = 0
            if size > pos:
                with p.open() as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                for line in chunk.splitlines():
                    yield f"data: {json.dumps(line)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


# --------------------------------------------------------------------------- #
def main():
    global STORE, READ_ONLY
    ap = argparse.ArgumentParser(description="autohunt web dashboard.")
    ap.add_argument("--data-dir", default=str(REPO / "data"), help="autohunt data/ dir to plug into.")
    ap.add_argument("--host", default="127.0.0.1", help="bind host (default localhost).")
    ap.add_argument("--port", type=int, default=8675)
    ap.add_argument("--read-only", action="store_true", help="Disable triage write actions (view only).")
    args = ap.parse_args()

    READ_ONLY = args.read_only
    STORE = DataStore(args.data_dir)
    if not STORE.root.exists():
        print(f"WARNING: data dir {STORE.root} does not exist yet — dashboard will be empty.", file=sys.stderr)
    print(f"autohunt dashboard → http://{args.host}:{args.port}  (data: {STORE.root})", file=sys.stderr)

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
