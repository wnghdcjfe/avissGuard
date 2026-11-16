"""FastAPI 서버: REST API + WebSocket 실시간 스트림 + 대시보드 정적 파일."""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .scanner import BleScanner, SimulatedScanner
from .signatures import SignatureDB
from .store import Store
from .tracker import DeviceTracker

log = logging.getLogger("avissguard.server")

STATIC_DIR = Path(str(resources.files("avissguard").joinpath("static")))
TOKEN_HEADER = "X-AvissGuard-Token"
SEND_TIMEOUT = 2.0


class Hub:
    """스캐너 → 트래커 → 웹소켓 클라이언트로 이어지는 런타임 상태."""

    def __init__(self, tracker: DeviceTracker, scanner_kind: str, adapter: str | None = None) -> None:
        self.tracker = tracker
        self.clients: set[WebSocket] = set()
        self.pending_alerts: list[dict] = []
        self.scanner_kind = scanner_kind
        self.loop_error: str | None = None
        if scanner_kind == "simulate":
            self.scanner = SimulatedScanner(self.on_observation)
        elif scanner_kind == "ble":
            self.scanner = BleScanner(self.on_observation, adapter=adapter)
        else:
            self.scanner = None
        self.stop = asyncio.Event()

    def on_observation(self, obs) -> None:  # noqa: ANN001
        try:
            alert = self.tracker.ingest(obs)
        except Exception:  # 패킷 하나 때문에 스캐너 콜백이 죽지 않도록
            log.exception("패킷 처리 실패: %s", getattr(obs, "address", "?"))
            return
        if alert:
            log.warning(alert["message"])
            self.pending_alerts.append(alert)

    def status(self) -> dict:
        return {
            "version": __version__,
            "scanner": self.scanner_kind,
            "running": bool(self.scanner and self.scanner.running),
            "error": (self.scanner.error if self.scanner else None) or self.loop_error,
            "signatures": len(self.tracker.db.rules),
            "ttl": self.tracker.ttl,
            "near_rssi": self.tracker.near_rssi,
        }

    def snapshot(self) -> dict:
        snap = self.tracker.snapshot()
        snap["status"] = self.status()
        return snap

    async def _send(self, ws: WebSocket, data: str) -> None:
        try:
            await asyncio.wait_for(ws.send_text(data), timeout=SEND_TIMEOUT)
        except Exception:
            # 느리거나 끊긴 클라이언트는 떼어내서 다른 대시보드를 막지 않게 한다
            self.clients.discard(ws)
            with contextlib.suppress(Exception):
                await ws.close()

    async def broadcast_once(self, tick: int) -> None:
        snap = self.snapshot()
        snap["new_alerts"], self.pending_alerts = self.pending_alerts, []
        data = json.dumps({"type": "snapshot", **snap}, ensure_ascii=False)
        if self.clients:
            await asyncio.gather(*(self._send(ws, data) for ws in list(self.clients)))
        if tick % 5 == 0:
            self.tracker.flush()
            self.tracker.prune()

    async def broadcast_loop(self) -> None:
        tick = 0
        while not self.stop.is_set():
            tick += 1
            try:
                await self.broadcast_once(tick)
                self.loop_error = None
            except Exception as exc:  # DB 잠김 등: 루프는 계속 돌리고 화면에 오류 표시
                self.loop_error = f"내부 오류: {type(exc).__name__}: {exc}"
                log.exception("브로드캐스트 실패")
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass


def create_app(
    *,
    scanner: str = "simulate",
    db_path: str = "avissguard.db",
    signatures_path: str | None = None,
    ttl: float = 30.0,
    near_rssi: int = -60,
    min_rssi: int = -100,
    adapter: str | None = None,
    token: str | None = None,
) -> FastAPI:
    """token이 None이면 실행할 때마다 임의 토큰을 만든다 (app.state.token)."""
    db = SignatureDB.load(signatures_path)
    store = Store(db_path)
    tracker = DeviceTracker(db, store, ttl=ttl, near_rssi=near_rssi, min_rssi=min_rssi)
    hub = Hub(tracker, scanner, adapter=adapter)
    token = token or secrets.token_urlsafe(16)

    def token_ok(value: str | None) -> bool:
        return bool(value) and secrets.compare_digest(value, token)

    async def require_token(request: Request) -> None:
        # 다른 사이트의 페이지나 같은 네트워크의 다른 사람이 기준선·허용 목록을 조작하지 못하도록
        supplied = request.headers.get(TOKEN_HEADER) or request.query_params.get("token")
        if not token_ok(supplied):
            raise HTTPException(401, "토큰이 필요합니다. 터미널에 표시된 URL로 접속하세요.")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks = [asyncio.create_task(hub.broadcast_loop())]
        if hub.scanner is not None:
            tasks.append(asyncio.create_task(hub.scanner.run(hub.stop)))
        try:
            yield
        finally:
            hub.stop.set()
            for t in tasks:
                try:
                    await asyncio.wait_for(t, timeout=5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                except Exception:
                    log.exception("종료 중 작업 오류")
            with contextlib.suppress(Exception):
                tracker.flush()
            store.close()

    app = FastAPI(title="AvissGuard", version=__version__, lifespan=lifespan)
    app.state.hub = hub
    app.state.token = token

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    api = APIRouter(prefix="/api", dependencies=[Depends(require_token)])

    @api.get("/status")
    async def get_status() -> dict:
        return hub.status()

    @api.get("/snapshot")
    async def get_snapshot() -> dict:
        return hub.snapshot()

    @api.get("/alerts")
    async def get_alerts(limit: int = 100) -> list[dict]:
        return store.recent_alerts(min(max(limit, 1), 1000))

    @api.post("/alerts/ack")
    async def ack_alerts(alert_id: int | None = None) -> dict:
        store.acknowledge(alert_id)
        return {"ok": True}

    @api.get("/history")
    async def get_history(limit: int = 500) -> list[dict]:
        return store.device_history(min(max(limit, 1), 5000))

    @api.post("/baseline")
    async def set_baseline() -> dict:
        n = tracker.set_baseline()
        return {"ok": True, "size": n, "set_at": tracker.baseline_at}

    @api.delete("/baseline")
    async def clear_baseline() -> dict:
        tracker.clear_baseline()
        return {"ok": True}

    @api.get("/whitelist")
    async def get_whitelist() -> list[dict]:
        return store.whitelist_entries()

    @api.post("/whitelist/{device_id:path}")
    async def add_whitelist(device_id: str) -> dict:
        key = tracker.whitelist_device(device_id)
        if key is None:
            raise HTTPException(404, "기기를 찾을 수 없습니다")
        return {"ok": True, "key": key}

    @api.delete("/whitelist/{key:path}")
    async def remove_whitelist(key: str) -> dict:
        tracker.unwhitelist(key)
        return {"ok": True}

    @api.get("/signatures")
    async def get_signatures() -> dict:
        return {
            "version": db.version,
            "rules": [
                {"id": r.id, "category": r.category, "label": r.label, "confidence": r.confidence}
                for r in db.rules
            ],
        }

    @api.get("/export.csv")
    async def export_csv() -> Response:
        tracker.flush()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "time", "device_id", "name", "category", "label", "level/max_score", "rssi", "detail"])
        for a in reversed(store.recent_alerts(1000)):
            w.writerow([_cell(v) for v in (
                "alert", _fmt(a["ts"]), a["device_id"], a["name"], a["category"], a["label"],
                a["level"], a["rssi"], a["message"],
            )])
        for d in store.device_history(5000):
            w.writerow([_cell(v) for v in (
                "device", _fmt(d["last_seen"]), d["device_id"], d["name"], d["category"], d["label"],
                d["max_score"], d["max_rssi"], d["reasons"],
            )])
        filename = time.strftime("avissguard-%Y%m%d-%H%M%S.csv")
        return Response(
            "﻿" + buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    app.include_router(api)

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        origin = ws.headers.get("origin")
        host = ws.headers.get("host", "")
        if origin and urlsplit(origin).netloc != host:
            await ws.close(code=4403)
            return
        if not token_ok(ws.query_params.get("token")):
            await ws.close(code=4401)
            return
        await ws.accept()
        try:
            # hello는 대기 중인 경보 큐를 비우지 않는다 (다른 대시보드도 받아야 하므로)
            hello = {"type": "hello", "alerts": store.recent_alerts(100), "new_alerts": [], **hub.snapshot()}
            await ws.send_text(json.dumps(hello, ensure_ascii=False))
            hub.clients.add(ws)
            while True:
                await ws.receive_text()  # 클라이언트 핑 유지용
        except WebSocketDisconnect:
            pass
        finally:
            hub.clients.discard(ws)

    return app


def _cell(v) -> str:
    """엑셀 수식 인젝션 방지: 기기 이름은 누구나 정할 수 있으므로 수식 시작 문자를 무력화한다."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _fmt(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""
