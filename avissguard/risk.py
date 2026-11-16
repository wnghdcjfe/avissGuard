"""위험도 점수 계산과 거리 추정."""

from __future__ import annotations

from dataclasses import dataclass, field

from .signatures import Classification

CATEGORY_WEIGHT = {
    "camera": 80,
    "glasses": 80,
    "earpiece": 75,
    "wearable": 45,
    "phone": 45,
    "tag": 25,
    "computer": 20,
    "unknown": 12,
    "infra": 5,
}
CONFIDENCE_MULT = {"high": 1.0, "medium": 0.8, "low": 0.55, None: 1.0}

LEVEL_HIGH = 70
LEVEL_MEDIUM = 40
LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2}


def level_for(score: int) -> str:
    if score >= LEVEL_HIGH:
        return "high"
    if score >= LEVEL_MEDIUM:
        return "medium"
    return "low"


def estimate_distance(rssi: float, tx_power: int | None = None, path_loss: float = 2.5) -> float:
    """로그 거리 경로손실 모델로 대략적인 거리(m)를 추정한다.

    BLE 광고의 TX Power는 송신 출력(0m 기준)이라 1m 기준값은 약 41dB 낮다.
    값이 없으면 일반적인 1m RSSI(-59dBm)를 쓴다. 실내 반사 때문에 오차가 크므로 참고용이다.
    """
    measured_1m = (tx_power - 41) if tx_power is not None and -30 <= tx_power <= 20 else -59
    d = 10 ** ((measured_1m - rssi) / (10 * path_loss))
    return round(max(0.1, min(d, 50.0)), 1)


@dataclass
class RiskResult:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)


def score_device(
    cls: Classification,
    rssi: float,
    *,
    baseline_active: bool = False,
    in_baseline: bool = False,
    whitelisted: bool = False,
    seen_seconds: float = 0.0,
    near_rssi: int = -60,
) -> RiskResult:
    if whitelisted:
        return RiskResult(0, "low", ["허용 목록에 등록된 기기"])

    reasons: list[str] = []
    base = CATEGORY_WEIGHT.get(cls.category, 12) * CONFIDENCE_MULT.get(cls.confidence, 1.0)
    score = base

    # 근접도: 가까울수록 '응시자 몸에 지닌 기기'일 가능성이 높다
    if rssi >= near_rssi:
        score += 15
        reasons.append(f"매우 가까움 (RSSI {rssi:.0f}dBm)")
    elif rssi >= near_rssi - 12:
        score += 7
        reasons.append(f"가까움 (RSSI {rssi:.0f}dBm)")
    elif rssi < -88:
        score -= 10
        reasons.append(f"멀리 있음 (RSSI {rssi:.0f}dBm)")

    # 기준선: 시험 시작 전부터 있던 기기(강의실 설비 등)는 감점, 이후 새로 나타난 기기는 가점
    if baseline_active:
        if in_baseline:
            score -= 40
            reasons.append("시험 전 기준선에 있던 기기")
        else:
            score += 10
            reasons.append("기준선 이후 새로 나타남")

    if cls.is_target and seen_seconds >= 60:
        score += 5
        reasons.append(f"{int(seen_seconds // 60)}분 이상 지속 탐지")

    final = int(max(0, min(100, round(score))))
    return RiskResult(final, level_for(final), reasons)
