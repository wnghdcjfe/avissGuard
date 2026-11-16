import time

import pytest
from fastapi.testclient import TestClient

from avissguard.models import Observation
from avissguard.risk import estimate_distance, level_for
from avissguard.scanner import SimulatedScanner
from avissguard.server import create_app
from avissguard.signatures import SignatureDB, parse_apple_continuity
from avissguard.store import Store
from avissguard.tracker import DeviceTracker


@pytest.fixture(scope="module")
def db():
    return SignatureDB.load()


def obs(name=None, rssi=-60, mfg=None, uuids=None, addr="AA:BB:CC:DD:EE:01", ts=None):
    return Observation(
        address=addr, rssi=rssi, timestamp=ts if ts is not None else time.time(), name=name,
        manufacturer_data=mfg or {}, service_uuids=uuids or [],
    )


def airpods(model=b"\x14\x20"):
    body = b"\x01" + model + bytes(22)
    return {0x004C: bytes([0x07, len(body)]) + body}


# --- 분류 ------------------------------------------------------------------
@pytest.mark.parametrize(
    "name,category",
    [
        ("Ray-Ban Meta 0A3F", "glasses"),
        ("RB Meta", "glasses"),
        ("Even G1_45_L_8C21D9", "glasses"),
        ("XREAL Air 2", "glasses"),
        ("Bose Frames Tempo", "glasses"),
        ("HDWiFiCam-8A21", "camera"),
        ("ESP32-CAM", "camera"),
        ("GoPro 1234", "camera"),
        ("Galaxy Buds2 Pro", "earpiece"),
        ("AirPods Pro", "earpiece"),
        ("WF-1000XM5", "earpiece"),
        ("i12 TWS", "earpiece"),
        ("Nano Earpiece", "earpiece"),
        ("Galaxy Watch6 (A1B2)", "wearable"),
        ("iPhone", "phone"),
        ("LG gram 17", "computer"),
    ],
)
def test_classify_by_name(db, name, category):
    assert db.classify(obs(name=name)).category == category


def test_apple_proximity_pairing_detects_airpods_model(db):
    c = db.classify(obs(mfg=airpods()))
    assert c.category == "earpiece"
    assert c.confidence == "high"
    assert c.model == "AirPods Pro 2"
    assert c.label == "AirPods Pro 2"


def test_apple_nearby_is_phone_not_earpiece(db):
    c = db.classify(obs(mfg={0x004C: bytes([0x10, 0x05, 0x01, 0x18, 0x44, 0x1A, 0x2B])}))
    assert c.category == "phone"


def test_parse_apple_tlv_multiple_and_truncated():
    msgs = parse_apple_continuity(bytes([0x10, 0x02, 0xAA, 0xBB, 0x0C, 0x05, 0x01]))
    assert msgs[0x10] == b"\xaa\xbb"
    assert msgs[0x0C] == b"\x01"  # 잘린 패킷도 있는 만큼


def test_service_uuid_short_and_long_forms(db):
    assert db.classify(obs(uuids=["fe2c"])).category == "earpiece"
    assert db.classify(obs(uuids=["0000FE2C-0000-1000-8000-00805F9B34FB"])).category == "earpiece"


def test_company_id_fallbacks(db):
    assert db.classify(obs(mfg={0x01AB: b"\x01"})).category == "glasses"
    assert db.classify(obs(mfg={0x02E5: b"\x01"})).category == "camera"


def test_name_rule_beats_vendor_rule(db):
    c = db.classify(obs(name="Galaxy Buds2 Pro", mfg={0x0075: b"\x01"}))
    assert c.category == "earpiece"
    assert "samsung-company" in c.matched_rules


def test_unknown_and_no_false_positive(db):
    assert db.classify(obs()).category == "unknown"
    assert db.classify(obs(name="Volatile sensor")).category == "unknown"
    assert db.classify(obs(name="Kitchen Thermometer")).category == "unknown"


# --- 위험도 ----------------------------------------------------------------
def test_distance_monotonic():
    assert estimate_distance(-50) < estimate_distance(-70) < estimate_distance(-90)
    assert estimate_distance(-59) == pytest.approx(1.0, abs=0.05)


def test_levels():
    assert level_for(80) == "high" and level_for(50) == "medium" and level_for(10) == "low"


# --- 추적기 ----------------------------------------------------------------
def make_tracker(db, now):
    clock = {"t": now}
    tr = DeviceTracker(db, Store(":memory:"), ttl=30, clock=lambda: clock["t"])
    return tr, clock


def test_tracker_alert_once_per_level(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    a1 = tr.ingest(obs(name="Ray-Ban Meta", rssi=-55, ts=t0))
    assert a1 and a1["level"] == "high"
    assert tr.ingest(obs(name="Ray-Ban Meta", rssi=-55, ts=t0 + 1)) is None
    assert len(tr.store.recent_alerts()) == 1


def test_tracker_realert_after_reappear(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    assert tr.ingest(obs(name="ESP32-CAM", ts=t0))
    assert tr.ingest(obs(name="ESP32-CAM", ts=t0 + 100))  # TTL 이후 재등장


def test_baseline_suppresses_existing_devices(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(name="Galaxy Buds2 Pro", rssi=-75, addr="A1", ts=t0))
    tr.set_baseline()
    dev = tr.devices["A1"]
    assert dev.in_baseline and dev.level != "high"
    # 기준선 이후 새로 등장한 같은 종류 기기는 가점
    tr.ingest(obs(name="AirPods Pro", rssi=-75, addr="A2", ts=t0 + 1))
    assert tr.devices["A2"].score > dev.score


def test_baseline_matches_fingerprint_after_address_rotation(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(name="Galaxy Buds2 Pro", addr="OLD", ts=t0))
    tr.set_baseline()
    tr.ingest(obs(name="Galaxy Buds2 Pro", addr="NEW", ts=t0 + 5))
    assert tr.devices["NEW"].in_baseline


def test_whitelist_zeroes_score(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(name="AirPods Pro", addr="A1", ts=t0))
    tr.whitelist_device("A1")
    assert tr.devices["A1"].score == 0
    assert tr.ingest(obs(name="AirPods Pro", addr="A1", ts=t0 + 1)) is None


def test_name_from_scan_response_kept(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(name="HDWiFiCam-1", addr="C1", ts=t0))
    tr.ingest(obs(name=None, addr="C1", ts=t0 + 1))
    assert tr.devices["C1"].classification.category == "camera"


def test_ignores_weak_and_invalid_rssi(db):
    tr, _ = make_tracker(db, 1000.0)
    tr.min_rssi = -90
    assert tr.ingest(obs(name="AirPods Pro", rssi=-95, ts=1000.0)) is None
    assert tr.ingest(obs(name="AirPods Pro", rssi=127, ts=1000.0)) is None
    assert not tr.devices


def test_simulator_scenario_produces_all_target_categories(db):
    tr, clock = make_tracker(db, 0)
    sim = SimulatedScanner(tr.ingest)
    for i in range(240):
        t = i * 0.5
        clock["t"] = t
        for o in sim.step(t, t):
            o.timestamp = t
            tr.ingest(o)
    cats = {d.classification.category for d in tr.devices.values()}
    assert {"camera", "glasses", "earpiece"} <= cats
    assert any(a["level"] == "high" for a in tr.store.recent_alerts())


# --- API -------------------------------------------------------------------
def test_api_endpoints(tmp_path):
    app = create_app(scanner="none", db_path=str(tmp_path / "t.db"))
    hub = app.state.hub
    with TestClient(app) as client:
        hub.on_observation(obs(name="Ray-Ban Meta", addr="X1"))
        assert client.get("/").status_code == 200
        assert client.get("/static/app.js").status_code == 200
        snap = client.get("/api/snapshot").json()
        assert snap["counts"]["active"] == 1 and snap["threat"] == "high"
        assert client.get("/api/alerts").json()[0]["category"] == "glasses"
        assert client.post("/api/baseline").json()["size"] == 1
        assert client.post("/api/whitelist/X1").json()["ok"]
        assert client.post("/api/whitelist/NOPE").status_code == 404
        csv_text = client.get("/api/export.csv").text
        assert "Ray-Ban Meta" in csv_text
        with client.websocket_connect("/ws") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello" and hello["devices"]


def test_csv_export_neutralizes_formulas(tmp_path):
    app = create_app(scanner="none", db_path=str(tmp_path / "c.db"))
    with TestClient(app) as client:
        app.state.hub.on_observation(obs(name="=HYPERLINK(\"x\") earpiece", addr="F1"))
        text = client.get("/api/export.csv").text
        assert "'=HYPERLINK" in text
        assert ",=HYPERLINK" not in text
