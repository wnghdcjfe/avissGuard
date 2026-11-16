"""BLE 스캐너(bleak)와 하드웨어 없이 쓰는 시뮬레이터."""

from __future__ import annotations

import asyncio
import logging
import math
import random
import time
from dataclasses import dataclass
from typing import Callable

from .models import Observation

log = logging.getLogger("avissguard.scanner")

ObservationHandler = Callable[[Observation], None]


class BleScanner:
    """bleak 기반 상시 BLE 패시브/액티브 스캔."""

    kind = "ble"

    def __init__(self, on_observation: ObservationHandler, adapter: str | None = None) -> None:
        self.on_observation = on_observation
        self.adapter = adapter
        self.error: str | None = None
        self.running = False

    async def run(self, stop: asyncio.Event) -> None:
        try:
            from bleak import BleakScanner
        except ImportError as exc:  # pragma: no cover - 설치 환경 문제
            self.error = f"bleak 미설치: {exc}"
            log.error(self.error)
            return

        def _cb(device, adv) -> None:  # noqa: ANN001 - bleak 타입
            rssi = adv.rssi if adv.rssi is not None else getattr(device, "rssi", -100)
            self.on_observation(
                Observation(
                    address=device.address,
                    rssi=int(rssi),
                    timestamp=time.time(),
                    name=adv.local_name or device.name,
                    tx_power=adv.tx_power,
                    manufacturer_data=dict(adv.manufacturer_data or {}),
                    service_uuids=list(adv.service_uuids or []),
                    service_data=dict(adv.service_data or {}),
                )
            )

        kwargs = {"detection_callback": _cb, "scanning_mode": "active"}
        if self.adapter:
            kwargs["bluez"] = {"adapter": self.adapter}  # type: ignore[assignment]
        while not stop.is_set():
            try:
                scanner = BleakScanner(**kwargs)
                await scanner.start()
                self.running, self.error = True, None
                log.info("BLE 스캔 시작")
                try:
                    await stop.wait()
                finally:
                    await scanner.stop()
                    self.running = False
            except Exception as exc:  # 어댑터 꺼짐·권한 없음 등
                self.running = False
                self.error = f"{type(exc).__name__}: {exc}"
                log.warning("BLE 스캔 오류, 5초 후 재시도: %s", self.error)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass


# ---------------------------------------------------------------------------
# 시뮬레이터


@dataclass
class _SimDevice:
    address: str
    name: str | None
    base_rssi: float
    mfg: dict[int, bytes]
    uuids: list[str]
    appear: float  # 시나리오 시작 후 등장 시각(초)
    leave: float | None = None
    interval: float = 1.0
    drift: float = 0.0  # 초당 RSSI 변화 (다가오면 +)
    hide_name_ratio: float = 0.0
    tx_power: int | None = None


def _mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02X}" for _ in range(6))


def _airpods_payload(model: bytes, rng: random.Random) -> bytes:
    body = b"\x01" + model + bytes(rng.randint(0, 255) for _ in range(22))
    return bytes([0x07, len(body)]) + body


def build_scenario(seed: int = 7) -> list[_SimDevice]:
    rng = random.Random(seed)
    return [
        # 시험 전부터 있는 기기들 (기준선 대상)
        _SimDevice(_mac(rng), "LG gram 17", -78, {}, [], 0, interval=2.0),
        _SimDevice(_mac(rng), None, -84, {0x004C: bytes([0x02, 0x15]) + bytes(21)}, [], 0, interval=1.0),
        _SimDevice(_mac(rng), "Galaxy S24", -72, {0x0075: b"\x42\x04\x01\x80"}, [], 0, interval=1.5),
        _SimDevice(_mac(rng), None, -66, {0x004C: bytes([0x10, 0x05, 0x01, 0x18, 0x44, 0x1A, 0x2B])}, [], 0, interval=1.2),
        _SimDevice(_mac(rng), None, -90, {0x0006: b"\x01\x09\x20\x02"}, [], 0, interval=3.0),
        _SimDevice(_mac(rng), "Eddystone", -92, {}, ["feaa"], 0, interval=2.0),
        # 시험 중 나타나는 의심 기기들
        _SimDevice(_mac(rng), None, -63, {0x004C: _airpods_payload(b"\x14\x20", rng)}, [], 12, interval=0.5),
        _SimDevice(_mac(rng), "Ray-Ban Meta 0A3F", -58, {0x01AB: b"\x01\x02\x03"}, ["fd5f"], 20, interval=0.8,
                   hide_name_ratio=0.5),
        _SimDevice(_mac(rng), "HDWiFiCam-8A21", -70, {0x02E5: b"\x10\x20"}, [], 30, interval=1.0, drift=0.15),
        _SimDevice(_mac(rng), "Galaxy Buds2 Pro", -61, {0x0075: b"\x42\x09\x81"}, ["fe2c"], 38, leave=95, interval=0.7),
        _SimDevice(_mac(rng), "BT-2208", -55, {}, [], 46, interval=1.0),
        _SimDevice(_mac(rng), None, -59, {0x02E5: b"\xaa\xbb"}, [], 52, interval=0.9),
        _SimDevice(_mac(rng), "Even G1_45_L_8C21D9", -64, {}, [], 60, interval=1.0),
        _SimDevice(_mac(rng), "Galaxy Watch6 (A1B2)", -69, {0x0075: b"\x01"}, ["180d"], 70, interval=1.5),
        _SimDevice(_mac(rng), "ESP32-CAM", -62, {0x02E5: b"\x01"}, [], 84, interval=1.0),
    ]


class SimulatedScanner:
    """현실적인 RSSI 흔들림을 가진 가상 기기들을 일정 주기로 재생한다 (120초 반복)."""

    kind = "simulate"

    def __init__(self, on_observation: ObservationHandler, *, cycle: float = 120.0, seed: int = 7) -> None:
        self.on_observation = on_observation
        self.cycle = cycle
        self.devices = build_scenario(seed)
        self.rng = random.Random(seed + 1)
        self.error: str | None = None
        self.running = False

    def step(self, t: float, now: float) -> list[Observation]:
        """시나리오 시각 t(초)에 송출되는 패킷 목록."""
        out = []
        for d in self.devices:
            if t < d.appear or (d.leave is not None and t > d.leave):
                continue
            if self.rng.random() > (0.5 / d.interval):
                continue
            rssi = d.base_rssi + d.drift * (t - d.appear) + self.rng.gauss(0, 3.0) + 2 * math.sin(t / 7)
            rssi = max(-100, min(-35, rssi))
            name = d.name if self.rng.random() >= d.hide_name_ratio else None
            out.append(
                Observation(
                    address=d.address,
                    rssi=int(rssi),
                    timestamp=now,
                    name=name,
                    tx_power=d.tx_power,
                    manufacturer_data=dict(d.mfg),
                    service_uuids=list(d.uuids),
                    source="simulate",
                )
            )
        return out

    async def run(self, stop: asyncio.Event) -> None:
        self.running = True
        start = time.time()
        while not stop.is_set():
            now = time.time()
            t = (now - start) % self.cycle
            for obs in self.step(t, now):
                self.on_observation(obs)
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
        self.running = False
