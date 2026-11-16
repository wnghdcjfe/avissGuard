"""FastAPI 서버: REST API + WebSocket 실시간 스트림 + 대시보드 정적 파일."""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import logging
import time
from contextlib import asynccontextmanager
from importlib import resources
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .scanner import BleScanner, SimulatedScanner
from .signatures import SignatureDB
from .store import Store
from .tracker import DeviceTracker

log = logging.getLogger("avissguard.server")

STATIC_DIR = Path(str(resources.files("avissguard").joinpath("static")))


class Hub:
    """스캐너 → 트래커 → 웹소켓 클라이언트로 이어지는 런타임 상태."""

    def __init__(self, tracker: DeviceTracker, scanner_kind: str, adapter: str | None = None) -> None:
        self.tracker = tracker
        self.clients: set[WebSocket] = set()
        self.pending_alerts: list[dict] = []
        self.scanner_kind = scanner_kind
        if scanner_kind == "simulate":
            self.scanner = SimulatedScanner(self.on_observation)
        elif scanner_kind == "ble":
            self.scanner = BleScanner(self.on_observation, adapter=adapter)
        else:
            self.scanner = None
        self.stop = asyncio.Event()

    def on_observation(self, obs) -> None:  # noqa: ANN001
        alert = self.tracker.ingest(obs)
        if alert:
            log.warning(alert["message"])
            self.pending_alerts.append(alert)

    def status(self) -> dict:
        return {
            "version": __version__,
            "scanner": self.scanner_kind,
            "running": bool(self.scanner and self.scanner.running),
            "error": self.scanner.error if self.scanner else None,
            "signatures": len(self.tracker.db.rules),
            "ttl": self.tracker.ttl,
            "near_rssi": self.tracker.near_rssi,
        }

    def payload(self) -> dict:
        snap = self.tracker.snapshot()
        snap["status"] = self.status()
        snap["new_alerts"], self.pending_alerts = self.pending_alerts, []
        return snap

    async def broadcast_loop(self) -> None:
        tick = 0
        while not self.stop.is_set():
            tick += 1
            data = json.dumps({"type": "snapshot", **self.payload()}, ensure_ascii=False)
            for ws in list(self.clients):
                try:
                    await ws.send_text(data)
                except Exception:
                    self.clients.discard(ws)
            if tick % 5 == 0:
                self.tracker.flush()
                self.tracker.prune()
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
) -> FastAPI:
    db = SignatureDB.load(signatures_path)
    store = Store(db_path)
    tracker = DeviceTracker(db, store, ttl=ttl, near_rssi=near_rssi, min_rssi=min_rssi)
    hub = Hub(tracker, scanner, adapter=adapter)

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
                with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError):
                    await asyncio.wait_for(t, timeout=5)
            tracker.flush()
            store.close()

    app = FastAPI(title="AvissGuard", version=__version__, lifespan=lifespan)
    app.state.hub = hub

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/api/status")
    async def get_status() -> dict:
        return hub.status()

    @app.get("/api/snapshot")
    async def get_snapshot() -> dict:
        snap = tracker.snapshot()
        snap["status"] = hub.status()
        return snap

    @app.get("/api/alerts")
    async def get_alerts(limit: int = 100) -> list[dict]:
        return store.recent_alerts(min(max(limit, 1), 1000))

    @app.post("/api/alerts/ack")
    async def ack_alerts(alert_id: int | None = None) -> dict:
        store.acknowledge(alert_id)
        return {"ok": True}

    @app.get("/api/history")
    async def get_history(limit: int = 500) -> list[dict]:
        return store.device_history(min(max(limit, 1), 5000))

    @app.post("/api/baseline")
    async def set_baseline() -> dict:
        n = tracker.set_baseline()
        return {"ok": True, "size": n, "set_at": tracker.baseline_at}

    @app.delete("/api/baseline")
    async def clear_baseline() -> dict:
        tracker.clear_baseline()
        return {"ok": True}

    @app.get("/api/whitelist")
    async def get_whitelist() -> list[dict]:
        return store.whitelist_entries()

    @app.post("/api/whitelist/{device_id:path}")
    async def add_whitelist(device_id: str) -> dict:
        key = tracker.whitelist_device(device_id)
        if key is None:
            raise HTTPException(404, "기기를 찾을 수 없습니다")
        return {"ok": True, "key": key}

    @app.delete("/api/whitelist/{key:path}")
    async def remove_whitelist(key: str) -> dict:
        tracker.unwhitelist(key)
        return {"ok": True}

    @app.get("/api/signatures")
    async def get_signatures() -> dict:
        return {
            "version": db.version,
            "rules": [
                {"id": r.id, "category": r.category, "label": r.label, "confidence": r.confidence}
                for r in db.rules
            ],
        }

    @app.get("/api/export.csv")
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

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        await ws.accept()
        hub.clients.add(ws)
        try:
            await ws.send_text(json.dumps(
                {"type": "hello", "alerts": store.recent_alerts(100), **hub.payload()}, ensure_ascii=False
            ))
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
