"""ThreatLens dashboard API (FastAPI).

PIN-gated (house convention): APP_PIN + signed session cookie.
Static dashboard pages served from ./static with zero outbound requests.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import date, datetime
from decimal import Decimal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from queries import BUCKET_ORDER, Repo, bucket_of
from shared.schema import apply_schema, conn_from_env
from taxii_discover import discover_taxii

APP_PIN = os.environ.get("APP_PIN", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
COOKIE_NAME = "tl_auth"
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

AUTH_EXEMPT = {"/api/login", "/api/logout", "/api/health"}


def _make_signer():
    import itsdangerous
    return itsdangerous.Signer(SESSION_SECRET)


def _is_authed(request: Request) -> bool:
    if not SESSION_SECRET:
        return False
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return False
    try:
        _make_signer().unsign(token)
        return True
    except Exception:
        return False


class AuthMiddleware:
    """Pure-ASGI auth gate.

    NOT BaseHTTPMiddleware: that class is fragile with WebSocket upgrades
    (it can silently drop the connection after the first frame on newer
    Starlette), so we implement the gate directly on the ASGI scope and
    pass websocket frames through untouched (the WS handler enforces auth
    itself as a second layer).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path.startswith("/static/") or path == "/favicon.ico":
            await self.app(scope, receive, send)
            return
        authed = self._authed(scope)

        if scope["type"] == "websocket":
            if path.startswith("/ws/") and not authed:
                # reject the upgrade with a plain 401 before handshake
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-length", b"0")]})
                await send({"type": "http.response.body", "body": b"",
                            "more_body": False})
                return
            await self.app(scope, receive, send)
            return

        # http scope
        if path.startswith("/api/"):
            if path not in AUTH_EXEMPT and not authed:
                body = b'{"detail": "unauthorized"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
            await self.app(scope, receive, send)
            return
        if path == "/login":
            await self.app(scope, receive, send)
            return
        if not authed:
            await send({"type": "http.response.start", "status": 302,
                        "headers": [(b"location", b"/login"),
                                    (b"content-length", b"0")]})
            await send({"type": "http.response.body", "body": b"",
                        "more_body": False})
            return
        await self.app(scope, receive, send)

    @staticmethod
    def _authed(scope) -> bool:
        if not SESSION_SECRET:
            return False
        cookies = {}
        for key, value in scope.get("headers", []):
            if key == b"cookie":
                for part in value.decode(errors="replace").split(";"):
                    if "=" in part:
                        name, val = part.strip().split("=", 1)
                        cookies[name] = val
        token = cookies.get(COOKIE_NAME)
        if not token:
            return False
        try:
            _make_signer().unsign(token)
            return True
        except Exception:
            return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = conn_from_env()
    apply_schema(conn)
    app.state.repo = Repo(conn)
    app.state.ws_manager = WSManager()
    poller = asyncio.create_task(poll_loop(app))
    yield
    poller.cancel()
    conn.close()


class WSManager:
    """Track connected live-view sockets and broadcast to all of them."""

    def __init__(self):
        self._sockets: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._sockets.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._sockets.discard(ws)

    async def broadcast(self, payload: dict) -> None:
        dead = []
        for ws in list(self._sockets):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


def _with_bucket(ev: dict) -> dict:
    ev["bucket"] = bucket_of(ev)
    return ev


def _json_safe(obj):
    """Make WS payloads JSON-serializable (send_json uses plain json.dumps,
    which cannot encode datetime/date/Decimal like the HTTP encoder does)."""
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    return obj


async def poll_loop(app: FastAPI, interval: float = 1.0) -> None:
    """Poll for new events/detections and stream them to live viewers."""
    repo: Repo = app.state.repo
    manager: WSManager = app.state.ws_manager
    ev_watermark = repo.max_event_id()
    det_watermark = repo.max_detection_id()
    while True:
        await asyncio.sleep(interval)
        try:
            events = [_with_bucket(e) for e in repo.events_since(ev_watermark)]
            detections = repo.detections_since(det_watermark)
            if events:
                ev_watermark = events[-1]["id"]
            if detections:
                det_watermark = detections[-1]["id"]
            payload = _json_safe({
                "type": "update",
                "events": events,
                "detections": detections,
                "buckets": repo.bucket_totals(),
            })
            await manager.broadcast(payload)
        except Exception:
            # transient DB hiccup — keep polling
            await asyncio.sleep(interval)


app = FastAPI(title="ThreatLens", lifespan=lifespan)
app.add_middleware(AuthMiddleware)


def get_repo(request: Request) -> Repo:
    return request.app.state.repo


# ---- auth ----

@app.post("/api/login")
async def login(request: Request):
    body = await request.json()
    pin = str(body.get("pin", ""))
    if not APP_PIN or pin != APP_PIN:
        raise HTTPException(status_code=401, detail="invalid pin")
    token = _make_signer().sign(b"authed").decode()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax",
                    max_age=60 * 60 * 24 * 14)
    return resp


@app.get("/api/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.get("/api/health")
async def health():
    return {"ok": True}


@app.get("/api/stats")
async def api_stats(repo: Repo = Depends(get_repo)):
    return repo.stats()


@app.get("/api/buckets")
async def api_buckets(repo: Repo = Depends(get_repo)):
    """Bucket tallies for the live-ingest view (REST fallback / initial paint)."""
    return {"buckets": repo.bucket_totals(), "order": BUCKET_ORDER}


@app.post("/api/taxii/discover")
async def api_taxii_discover(request: Request):
    """Resolve a TAXII discovery URL into its collections (for the feed form)."""
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(400, f"invalid request body: {exc}")
    url = (body.get("discovery_url") or "").strip()
    if not url:
        raise HTTPException(400, "discovery_url is required")
    auth = None
    if body.get("username"):
        auth = (body["username"], body.get("password") or "")
    try:
        return discover_taxii(url, auth=auth)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        # never let a malformed/weird server response surface as a 500
        raise HTTPException(400, f"discovery failed: {exc}")


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    if not _is_authed(websocket):
        await websocket.close(code=4401)
        return
    manager: WSManager = websocket.app.state.ws_manager
    repo: Repo = websocket.app.state.repo
    await manager.connect(websocket)
    try:
        # initial snapshot: current tallies + the most recent events/detections
        recent_events = [_with_bucket(e)
                         for e in repo.events_since(max(0, repo.max_event_id() - 10))]
        recent_dets = repo.detections_since(max(0, repo.max_detection_id() - 5))
        await websocket.send_json(_json_safe({
            "type": "snapshot",
            "buckets": repo.bucket_totals(),
            "events": recent_events,
            "detections": recent_dets,
        }))
        while True:
            await websocket.receive_text()   # keepalive pings from client
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.get("/api/events")
async def api_events(q: str | None = None, since: str | None = None,
                     limit: int = Query(50, ge=1, le=500),
                     offset: int = Query(0, ge=0),
                     flows_only: bool = False,
                     repo: Repo = Depends(get_repo)):
    return repo.events(q=q, since=since, limit=limit, offset=offset,
                       flows_only=flows_only)


@app.get("/api/events/{event_id}")
async def api_event(event_id: int, repo: Repo = Depends(get_repo)):
    ev = repo.event(event_id)
    if not ev:
        raise HTTPException(404, "event not found")
    return ev


@app.get("/api/detections")
async def api_detections(feed_id: int | None = None, q: str | None = None,
                         since: str | None = None,
                         limit: int = Query(50, ge=1, le=500),
                         offset: int = Query(0, ge=0),
                         repo: Repo = Depends(get_repo)):
    return repo.detections(feed_id=feed_id, q=q, since=since,
                           limit=limit, offset=offset)


@app.get("/api/detections/{det_id}")
async def api_detection(det_id: int, repo: Repo = Depends(get_repo)):
    d = repo.detection(det_id)
    if not d:
        raise HTTPException(404, "detection not found")
    return d


@app.get("/api/feeds")
async def api_feeds(repo: Repo = Depends(get_repo)):
    return repo.feeds()


@app.post("/api/feeds")
async def api_create_feed(request: Request, repo: Repo = Depends(get_repo)):
    data = await request.json()
    try:
        return repo.create_feed(data)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.put("/api/feeds/{feed_id}")
async def api_update_feed(feed_id: int, request: Request,
                          repo: Repo = Depends(get_repo)):
    data = await request.json()
    try:
        feed = repo.update_feed(feed_id, data)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not feed:
        raise HTTPException(404, "feed not found")
    return feed


@app.delete("/api/feeds/{feed_id}")
async def api_delete_feed(feed_id: int, repo: Repo = Depends(get_repo)):
    if not repo.delete_feed(feed_id):
        raise HTTPException(404, "feed not found")
    return {"ok": True, "feed_id": feed_id}


@app.post("/api/feeds/{feed_id}/pull")
async def api_feed_pull(feed_id: int, repo: Repo = Depends(get_repo)):
    if not repo.request_pull(feed_id):
        raise HTTPException(404, "feed not found")
    return {"ok": True, "feed_id": feed_id, "queued": True}


@app.get("/api/feeds/{feed_id}/logs")
async def api_feed_logs(feed_id: int,
                        limit: int = Query(50, ge=1, le=500),
                        repo: Repo = Depends(get_repo)):
    """Per-feed operation log (pull attempts, errors, registrations)."""
    return repo.feed_logs(feed_id, limit)


@app.get("/api/iocs")
async def api_iocs(feed_id: int | None = None, type: str | None = None,
                   q: str | None = None,
                   limit: int = Query(50, ge=1, le=500),
                   offset: int = Query(0, ge=0),
                   repo: Repo = Depends(get_repo)):
    return repo.iocs(feed_id=feed_id, ioc_type=type, q=q,
                     limit=limit, offset=offset)


@app.get("/api/iocs/{ioc_id}")
async def api_ioc(ioc_id: int, repo: Repo = Depends(get_repo)):
    ioc = repo.ioc(ioc_id)
    if not ioc:
        raise HTTPException(404, "ioc not found")
    return ioc


# ---- pages + static ----

def _page(name: str) -> str:
    return open(os.path.join(STATIC_DIR, name)).read()


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/login", response_class=HTMLResponse)
async def page_login():
    return _page("login.html")


@app.get("/", response_class=HTMLResponse)
async def page_index():
    return _page("index.html")


@app.get("/detections", response_class=HTMLResponse)
async def page_detections():
    return _page("detections.html")


@app.get("/events", response_class=HTMLResponse)
async def page_events():
    return _page("events.html")


@app.get("/feeds", response_class=HTMLResponse)
async def page_feeds():
    return _page("feeds.html")


@app.get("/iocs", response_class=HTMLResponse)
async def page_iocs():
    return _page("iocs.html")
