"""광고 패킷을 기기 단위로 묶고, 위험도·기준선·경보를 관리한다."""

from __future__ import annotations

import hashlib
import statistics
import time
from collections import deque
from dataclasses import dataclass, field

from .models import Observation, short_uuid
from .risk import LEVEL_ORDER, estimate_distance, score_device
from .signatures import CATEGORY_LABELS, TARGET_CATEGORIES, Classification, SignatureDB
from .store import Store


def fingerprint(obs: Observation, cls: Classification) -> str | None:
    """주소가 바뀌어도(MAC 랜덤화) 같은 기기로 볼 수 있는 특징값.

    이름이나 모델처럼 기기를 구분할 정보가 없으면 None (주소로만 식별).
    """
    if not obs.name and not cls.model:
        return None
    raw = "|".join(
        [
            obs.name or "",
            cls.model or "",
            ",".join(str(c) for c in sorted(obs.manufacturer_data)),
            ",".join(sorted(obs.all_service_uuids)),
        ]
    )
    return "fp:" + hashlib.sha1(raw.encode()).hexdigest()[:12]


@dataclass
class TrackedDevice:
    id: str
    first_seen: float
    last_seen: float
    name: str | None = None
    rssi: float = -100.0
    tx_power: int | None = None
    company_ids: list[int] = field(default_factory=list)
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    service_uuids: list[str] = field(default_factory=list)
    classification: Classification = field(default_factory=Classification)
    fingerprint: str | None = None
    sightings: int = 0
    rssi_window: deque = field(default_factory=lambda: deque(maxlen=7))
    rssi_history: deque = field(default_factory=lambda: deque(maxlen=60))
    score: int = 0
    level: str = "low"
    risk_reasons: list[str] = field(default_factory=list)
    in_baseline: bool = False
    whitelisted: bool = False
    alerted_level: str | None = None
    source: str = "ble"

    @property
    def distance(self) -> float:
        return estimate_distance(self.rssi, self.tx_power)

    def to_dict(self, now: float) -> dict:
        c = self.classification
        return {
            "id": self.id,
            "name": self.name,
            "category": c.category,
            "category_label": CATEGORY_LABELS.get(c.category, c.category),
            "label": c.label,
            "confidence": c.confidence,
            "vendor": c.vendor,
            "model": c.model,
            "is_target": c.is_target,
            "rssi": int(round(self.rssi)),
            "tx_power": self.tx_power,
            "distance": self.distance,
            "score": self.score,
            "level": self.level,
            "reasons": c.reasons + self.risk_reasons,
            "matched_rules": c.matched_rules,
            "company_ids": [f"0x{x:04X}" for x in self.company_ids],
            "service_uuids": [short_uuid(u) for u in self.service_uuids],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "age": round(now - self.last_seen, 1),
            "duration": round(self.last_seen - self.first_seen, 1),
            "sightings": self.sightings,
            "fingerprint": self.fingerprint,
            "in_baseline": self.in_baseline,
            "whitelisted": self.whitelisted,
            "history": [int(round(v)) for v in self.rssi_history],
            "source": self.source,
        }


class DeviceTracker:
    def __init__(
        self,
        db: SignatureDB,
        store: Store | None = None,
        *,
        ttl: float = 30.0,
        forget_after: float = 600.0,
        near_rssi: int = -60,
        min_rssi: int = -100,
        clock=time.time,
    ) -> None:
        self.db = db
        self.store = store or Store()
        self.ttl = ttl
        self.forget_after = forget_after
        self.near_rssi = near_rssi
        self.min_rssi = min_rssi
        self.clock = clock
        self.devices: dict[str, TrackedDevice] = {}
        self.baseline_ids: set[str] = set()
        self.baseline_fps: set[str] = set()
        self.baseline_at: float | None = None
        self.whitelist: set[str] = self.store.whitelist_keys()
        self.started_at = clock()
        self.packets = 0
        self._dirty: set[str] = set()

    # ------------------------------------------------------------------
    def ingest(self, obs: Observation) -> dict | None:
        """광고 패킷을 반영하고, 새 경보가 발생하면 경보 dict를 돌려준다."""
        if obs.rssi < self.min_rssi or obs.rssi >= 20:  # 127 등 무효값 제외
            return None
        self.packets += 1
        now = obs.timestamp
        dev = self.devices.get(obs.address)
        reappeared = dev is not None and (now - dev.last_seen) > self.ttl
        if dev is None:
            dev = TrackedDevice(id=obs.address, first_seen=now, last_seen=now, source=obs.source)
            self.devices[obs.address] = dev
        elif reappeared:
            dev.first_seen = now
            dev.alerted_level = None
            dev.rssi_window.clear()

        dev.last_seen = now
        dev.sightings += 1
        if obs.name:
            dev.name = obs.name
        if obs.tx_power is not None:
            dev.tx_power = obs.tx_power
        if obs.manufacturer_data:
            dev.manufacturer_data.update(obs.manufacturer_data)
            dev.company_ids = sorted(dev.manufacturer_data)
        if obs.all_service_uuids:
            dev.service_uuids = sorted(set(dev.service_uuids) | obs.all_service_uuids)

        dev.rssi_window.append(obs.rssi)
        dev.rssi = statistics.median(dev.rssi_window)
        dev.rssi_history.append(dev.rssi)

        # 이름이 이후 패킷(스캔 응답)에서만 오는 경우가 많아서, 누적 정보로 다시 분류한다
        merged = Observation(
            address=obs.address,
            rssi=obs.rssi,
            timestamp=now,
            name=dev.name,
            tx_power=dev.tx_power,
            manufacturer_data=dev.manufacturer_data,
            service_uuids=dev.service_uuids,
        )
        new_cls = self.db.classify(merged)
        # 신뢰도가 낮은 패킷(예: 이름 없는 광고)으로 이미 확인된 분류를 덮어쓰지 않는다
        if not (dev.classification.is_target and not new_cls.is_target and dev.classification.confidence):
            dev.classification = new_cls
        dev.fingerprint = fingerprint(merged, dev.classification) or dev.fingerprint

        self._rescore(dev, now)
        self._dirty.add(dev.id)
        return self._maybe_alert(dev, now)

    def _rescore(self, dev: TrackedDevice, now: float) -> None:
        dev.whitelisted = dev.id in self.whitelist or (dev.fingerprint in self.whitelist if dev.fingerprint else False)
        dev.in_baseline = dev.id in self.baseline_ids or (
            dev.fingerprint is not None and dev.fingerprint in self.baseline_fps
        )
        res = score_device(
            dev.classification,
            dev.rssi,
            baseline_active=self.baseline_at is not None,
            in_baseline=dev.in_baseline,
            whitelisted=dev.whitelisted,
            seen_seconds=now - dev.first_seen,
            near_rssi=self.near_rssi,
        )
        dev.score, dev.level, dev.risk_reasons = res.score, res.level, res.reasons

    def _maybe_alert(self, dev: TrackedDevice, now: float) -> dict | None:
        if dev.level == "low":
            return None
        prev = LEVEL_ORDER.get(dev.alerted_level, -1) if dev.alerted_level else -1
        if LEVEL_ORDER[dev.level] <= prev:
            return None
        dev.alerted_level = dev.level
        c = dev.classification
        who = dev.name or c.model or "이름 없음"
        msg = f"{'경보' if dev.level == 'high' else '주의'}: {c.label} 탐지 — {who}, 약 {dev.distance}m (RSSI {int(dev.rssi)}dBm)"
        alert = {
            "ts": now,
            "device_id": dev.id,
            "name": dev.name,
            "category": c.category,
            "label": c.label,
            "level": dev.level,
            "score": dev.score,
            "rssi": int(dev.rssi),
            "distance": dev.distance,
            "message": msg,
        }
        alert["id"] = self.store.add_alert(alert)
        alert["acknowledged"] = 0
        return alert

    # ------------------------------------------------------------------
    def active(self, now: float | None = None) -> list[TrackedDevice]:
        now = self.clock() if now is None else now
        return [d for d in self.devices.values() if now - d.last_seen <= self.ttl]

    def prune(self, now: float | None = None) -> None:
        now = self.clock() if now is None else now
        for key in [k for k, d in self.devices.items() if now - d.last_seen > self.forget_after]:
            del self.devices[key]

    def flush(self) -> None:
        """변경된 기기 정보를 DB에 기록한다."""
        now = self.clock()
        rows = [self.devices[i].to_dict(now) for i in self._dirty if i in self.devices]
        self._dirty.clear()
        self.store.upsert_devices(rows)

    def set_baseline(self) -> int:
        now = self.clock()
        act = self.active(now)
        self.baseline_ids = {d.id for d in act}
        self.baseline_fps = {d.fingerprint for d in act if d.fingerprint}
        self.baseline_at = now
        for d in self.devices.values():
            self._rescore(d, now)
            if d.level == "low":
                d.alerted_level = None
        return len(self.baseline_ids)

    def clear_baseline(self) -> None:
        self.baseline_ids.clear()
        self.baseline_fps.clear()
        self.baseline_at = None
        now = self.clock()
        for d in self.devices.values():
            self._rescore(d, now)

    def whitelist_device(self, device_id: str) -> str | None:
        dev = self.devices.get(device_id)
        if dev is None:
            return None
        key = dev.fingerprint or dev.id
        label = dev.name or dev.classification.label
        self.store.add_whitelist(key, label, self.clock())
        self.whitelist.add(key)
        self._rescore(dev, self.clock())
        return key

    def unwhitelist(self, key: str) -> None:
        self.store.remove_whitelist(key)
        self.whitelist.discard(key)
        now = self.clock()
        for d in self.devices.values():
            self._rescore(d, now)

    def snapshot(self) -> dict:
        now = self.clock()
        act = sorted(self.active(now), key=lambda d: (-d.score, -d.rssi))
        by_level = {"high": 0, "medium": 0, "low": 0}
        by_category: dict[str, int] = {}
        for d in act:
            by_level[d.level] += 1
            by_category[d.classification.category] = by_category.get(d.classification.category, 0) + 1
        threat = "high" if by_level["high"] else ("medium" if by_level["medium"] else "clear")
        return {
            "ts": now,
            "uptime": round(now - self.started_at, 1),
            "packets": self.packets,
            "threat": threat,
            "counts": {
                "active": len(act),
                "tracked": len(self.devices),
                "by_level": by_level,
                "by_category": by_category,
                "targets": sum(1 for d in act if d.classification.category in TARGET_CATEGORIES),
            },
            "baseline": {
                "active": self.baseline_at is not None,
                "set_at": self.baseline_at,
                "size": len(self.baseline_ids),
            },
            "devices": [d.to_dict(now) for d in act],
        }
