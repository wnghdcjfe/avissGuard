"""시그니처 DB 로딩과 기기 분류."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from .models import Observation, normalize_uuid

APPLE_COMPANY_ID = 0x004C

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

# 부정행위 관점에서 관심 있는 카테고리 (대시보드에서 강조 표시)
TARGET_CATEGORIES = ("camera", "glasses", "earpiece")

CATEGORY_LABELS = {
    "camera": "카메라",
    "glasses": "스마트안경",
    "earpiece": "이어폰",
    "wearable": "웨어러블",
    "phone": "휴대기기",
    "computer": "PC",
    "tag": "태그",
    "infra": "비콘",
    "unknown": "미확인",
}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    label: str
    confidence: str
    name_regex: re.Pattern[str] | None = None
    company_ids: frozenset[int] = frozenset()
    service_uuids: frozenset[str] = frozenset()
    apple_types: frozenset[int] = frozenset()

    def matches(self, obs: Observation, apple_types: dict[int, bytes]) -> bool:
        if not (self.name_regex or self.company_ids or self.service_uuids or self.apple_types):
            return False
        if self.name_regex is not None:
            if not obs.name or not self.name_regex.search(obs.name):
                return False
        if self.company_ids and not (self.company_ids & obs.manufacturer_data.keys()):
            return False
        if self.service_uuids and not (self.service_uuids & obs.all_service_uuids):
            return False
        if self.apple_types and not (self.apple_types & apple_types.keys()):
            return False
        return True


@dataclass
class Classification:
    category: str = "unknown"
    label: str = "미확인 기기"
    confidence: str | None = None
    vendor: str | None = None
    model: str | None = None
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)

    @property
    def is_target(self) -> bool:
        return self.category in TARGET_CATEGORIES

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "category_label": CATEGORY_LABELS.get(self.category, self.category),
            "label": self.label,
            "confidence": self.confidence,
            "vendor": self.vendor,
            "model": self.model,
            "reasons": list(self.reasons),
            "matched_rules": list(self.matched_rules),
            "is_target": self.is_target,
        }


def _compile_regex(pattern: str) -> re.Pattern[str]:
    flags = 0
    if pattern.startswith("(?i)"):
        pattern = pattern[4:]
        flags |= re.IGNORECASE
    return re.compile(pattern, flags)


def parse_apple_continuity(payload: bytes) -> dict[int, bytes]:
    """Apple 제조사 데이터(TLV)를 {메시지 타입: 페이로드}로 분해한다."""
    out: dict[int, bytes] = {}
    i = 0
    while i + 2 <= len(payload):
        msg_type = payload[i]
        length = payload[i + 1]
        body = payload[i + 2 : i + 2 + length]
        if len(body) < length:
            # 잘린 패킷: 있는 만큼만 기록
            out.setdefault(msg_type, body)
            break
        out.setdefault(msg_type, body)
        i += 2 + length
    return out


class SignatureDB:
    def __init__(self, data: dict) -> None:
        self.version = data.get("version", 1)
        self.vendors: dict[int, str] = {int(k): v for k, v in data.get("vendors", {}).items()}
        self.apple_models: dict[str, str] = {k.lower(): v for k, v in data.get("apple_models", {}).items()}
        self.rules: list[Rule] = []
        for raw in data.get("rules", []):
            self.rules.append(
                Rule(
                    id=raw["id"],
                    category=raw["category"],
                    label=raw["label"],
                    confidence=raw.get("confidence", "medium"),
                    name_regex=_compile_regex(raw["name_regex"]) if raw.get("name_regex") else None,
                    company_ids=frozenset(int(c) for c in raw.get("company_ids", [])),
                    service_uuids=frozenset(normalize_uuid(u) for u in raw.get("service_uuids", [])),
                    apple_types=frozenset(int(t) for t in raw.get("apple_types", [])),
                )
            )

    @classmethod
    def load(cls, path: str | Path | None = None) -> "SignatureDB":
        if path is None:
            text = resources.files("avissguard").joinpath("data/signatures.json").read_text("utf-8")
        else:
            text = Path(path).read_text("utf-8")
        return cls(json.loads(text))

    def classify(self, obs: Observation) -> Classification:
        apple = {}
        if APPLE_COMPANY_ID in obs.manufacturer_data:
            apple = parse_apple_continuity(obs.manufacturer_data[APPLE_COMPANY_ID])

        result = Classification()
        vendors = [self.vendors[c] for c in obs.manufacturer_data if c in self.vendors]
        if vendors:
            result.vendor = vendors[0]
        elif obs.manufacturer_data:
            cid = next(iter(obs.manufacturer_data))
            result.vendor = f"0x{cid:04X}"

        model_code = None
        if 0x07 in apple and len(apple[0x07]) >= 3:
            model_code = apple[0x07][1:3].hex()
            result.model = self.apple_models.get(model_code, f"Apple 오디오 (0x{model_code})")

        matched = [r for r in self.rules if r.matches(obs, apple)]
        result.matched_rules = [r.id for r in matched]
        if matched:
            best_rank = max(CONFIDENCE_RANK.get(r.confidence, 0) for r in matched)
            best = next(r for r in matched if CONFIDENCE_RANK.get(r.confidence, 0) == best_rank)
            result.category = best.category
            result.label = result.model if (result.model and best.id == "apple-proximity-pairing") else best.label
            result.confidence = best.confidence
            for r in matched:
                result.reasons.append(_reason_for(r, obs))
        else:
            if obs.name:
                result.reasons.append(f"알려진 시그니처 없음 (이름: {obs.name})")
            else:
                result.reasons.append("이름을 숨긴 미확인 기기")
        return result


def _reason_for(rule: Rule, obs: Observation) -> str:
    parts = []
    if rule.name_regex is not None and obs.name:
        parts.append(f"이름 '{obs.name}'")
    if rule.company_ids:
        parts.append("제조사 ID " + ", ".join(f"0x{c:04X}" for c in sorted(rule.company_ids)))
    if rule.service_uuids:
        parts.append("서비스 UUID " + ", ".join(sorted(u[4:8] for u in rule.service_uuids)))
    if rule.apple_types:
        parts.append("Apple 메시지 타입 " + ", ".join(f"0x{t:02X}" for t in sorted(rule.apple_types)))
    return f"{rule.label} ← {' / '.join(parts)} [{rule.confidence}]"
