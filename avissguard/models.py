"""스캐너와 분석기 사이에서 주고받는 데이터 구조."""

from __future__ import annotations

from dataclasses import dataclass, field

BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def normalize_uuid(value: str) -> str:
    """16/32비트 축약 UUID를 128비트 소문자 표기로 맞춘다."""
    v = value.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    if len(v) == 4:
        return f"0000{v}{BASE_UUID_SUFFIX}"
    if len(v) == 8:
        return f"{v}{BASE_UUID_SUFFIX}"
    return v


def short_uuid(value: str) -> str:
    """표준 Base UUID 기반이면 4자리 축약형으로, 아니면 그대로 돌려준다."""
    v = normalize_uuid(value)
    if v.endswith(BASE_UUID_SUFFIX) and v.startswith("0000"):
        return v[4:8]
    return v


@dataclass
class Observation:
    """BLE 광고 패킷 한 건."""

    address: str
    rssi: int
    timestamp: float
    name: str | None = None
    tx_power: int | None = None
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    service_uuids: list[str] = field(default_factory=list)
    service_data: dict[str, bytes] = field(default_factory=dict)
    source: str = "ble"

    def __post_init__(self) -> None:
        self.service_uuids = sorted({normalize_uuid(u) for u in self.service_uuids})
        self.service_data = {normalize_uuid(k): v for k, v in self.service_data.items()}
        if self.name is not None:
            # 깨진 유니코드(짝 없는 서로게이트 등)가 JSON/DB 인코딩을 망가뜨리지 않도록 정리
            clean = self.name.encode("utf-8", "replace").decode("utf-8").replace("\x00", "")
            self.name = clean.strip()[:64] or None

    @property
    def all_service_uuids(self) -> set[str]:
        return set(self.service_uuids) | set(self.service_data.keys())
