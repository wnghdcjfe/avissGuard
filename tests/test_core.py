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


def test_tracker_realert_only_after_cooldown(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    assert tr.ingest(obs(name="ESP32-CAM", ts=t0))
    assert tr.ingest(obs(name="ESP32-CAM", ts=t0 + 100)) is None  # TTL 후 재등장이지만 쿨다운 중
    assert tr.ingest(obs(name="ESP32-CAM", ts=t0 + 500))  # 쿨다운(300초) 이후 재등장


def test_alert_storm_is_collapsed(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    alerts = [tr.ingest(obs(mfg=airpods(), rssi=-50, addr=f"R{i}", ts=t0 + i * 0.01)) for i in range(100)]
    alerts = [a for a in alerts if a]
    assert len(alerts) == tr.storm_limit + 1
    assert alerts[-1]["device_id"] == "*"


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
    tr.ingest(obs(name="Galaxy S24", addr="OLD", ts=t0))
    tr.set_baseline()
    tr.ingest(obs(name="Galaxy S24", addr="NEW", ts=t0 + 5))
    assert tr.devices["NEW"].in_baseline


def test_target_devices_never_match_by_fingerprint(db):
    """감독관 이어폰을 허용/기준선 처리해도 같은 모델의 응시자 이어폰은 숨겨지면 안 된다."""
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(name="Galaxy Buds2 Pro", addr="PROCTOR", ts=t0))
    tr.ingest(obs(mfg=airpods(), addr="PROCTOR2", ts=t0))
    tr.set_baseline()
    tr.whitelist_device("PROCTOR")
    tr.whitelist_device("PROCTOR2")
    tr.ingest(obs(name="Galaxy Buds2 Pro", rssi=-50, addr="STUDENT", ts=t0 + 5))
    tr.ingest(obs(mfg=airpods(), rssi=-50, addr="STUDENT2", ts=t0 + 5))
    for sid in ("STUDENT", "STUDENT2"):
        d = tr.devices[sid]
        assert not d.whitelisted and not d.in_baseline and d.level == "high"


def test_fingerprint_stable_when_more_data_arrives(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(name="Galaxy S24", mfg={0x0075: b"\x01"}, addr="P1", ts=t0))
    tr.whitelist_device("P1")
    tr.ingest(obs(name="Galaxy S24", uuids=["fd5a"], addr="P1", ts=t0 + 1))
    assert tr.devices["P1"].whitelisted


def test_low_confidence_target_upgraded_by_better_name(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(mfg={301: b"\x01"}, addr="S1", ts=t0))
    assert tr.devices["S1"].classification.category == "earpiece"
    tr.ingest(obs(name="Xperia 1 V", addr="S1", ts=t0 + 1))
    assert tr.devices["S1"].classification.category == "phone"


@pytest.mark.parametrize(
    "name",
    ["Smart Wi-Fi Plug", "Arduino Nano", "Nano X 1A2B", "Magnetic Keyboard", "inmotion V12", "Brilliant Bulb",
     "A95 Pro", "X50", "OSMO Mobile 6"],
)
def test_common_devices_not_flagged_as_targets(db, name):
    assert not db.classify(obs(name=name)).is_target


def test_smarttag_is_tag_not_phone(db):
    assert db.classify(obs(name="Galaxy SmartTag2")).category == "tag"


def test_broken_unicode_name_is_sanitized():
    o = obs(name="cam\ud800\x00x")
    o.name.encode("utf-8")  # 예외 없이 인코딩돼야 한다
    assert "\x00" not in o.name


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
TOKEN = {"X-AvissGuard-Token": "secret"}


def test_api_requires_token(tmp_path):
    app = create_app(scanner="none", db_path=str(tmp_path / "a.db"), token="secret")
    with TestClient(app) as client:
        assert client.get("/").status_code == 200  # 페이지 자체는 공개, 데이터는 토큰 필요
        assert client.get("/api/snapshot").status_code == 401
        assert client.post("/api/baseline", headers={"Origin": "http://evil.example"}).status_code == 401
        assert client.post("/api/baseline", headers={"X-AvissGuard-Token": "wrong"}).status_code == 401
        assert client.get("/api/snapshot?token=secret").status_code == 200
        from starlette.websockets import WebSocketDisconnect
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws") as ws:
                ws.receive_json()
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws?token=secret", headers={"Origin": "http://evil.example"}) as ws:
                ws.receive_json()


def test_ws_hello_does_not_steal_pending_alerts(tmp_path):
    app = create_app(scanner="none", db_path=str(tmp_path / "w.db"), token="secret")
    hub = app.state.hub
    with TestClient(app) as client:
        hub.on_observation(obs(name="Ray-Ban Meta", addr="X1"))
        assert hub.pending_alerts
        with client.websocket_connect("/ws?token=secret") as ws:
            assert ws.receive_json()["type"] == "hello"
        assert hub.pending_alerts  # 다른 대시보드에 보낼 경보가 남아 있어야 한다


def test_api_endpoints(tmp_path):
    app = create_app(scanner="none", db_path=str(tmp_path / "t.db"), token="secret")
    hub = app.state.hub
    with TestClient(app, headers=TOKEN) as client:
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
        assert client.get("/api/whitelist").json()
        with client.websocket_connect("/ws?token=secret") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello" and hello["devices"]


def test_csv_export_neutralizes_formulas(tmp_path):
    app = create_app(scanner="none", db_path=str(tmp_path / "c.db"), token="secret")
    with TestClient(app, headers=TOKEN) as client:
        app.state.hub.on_observation(obs(name="=HYPERLINK(\"x\") earpiece", addr="F1"))
        text = client.get("/api/export.csv").text
        assert "'=HYPERLINK" in text
        assert ",=HYPERLINK" not in text


IPHONE = {0x004C: bytes([0x10, 0x05, 0x01, 0x18, 0x44, 0x1A, 0x2B])}


def test_nameless_phone_address_rotation_inherits_baseline(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(mfg=IPHONE, rssi=-65, addr="OLD", ts=t0))
    clock["t"] = t0 + 1
    tr.set_baseline()
    # 기존 주소는 신호를 멈추고, 같은 유형이 새 주소로 나타남
    alerts = [tr.ingest(obs(mfg=IPHONE, rssi=-65, addr="NEW", ts=t0 + 5 + i)) for i in range(20)]
    assert not any(alerts)
    assert tr.devices["NEW"].in_baseline
    # 한 번 더 주소가 바뀌어도 이어 받는다
    assert not tr.ingest(obs(mfg=IPHONE, rssi=-65, addr="NEWER", ts=t0 + 40))
    assert tr.devices["NEWER"].in_baseline


def test_second_phone_still_alerts_after_grace(db):
    """기준선 휴대폰이 아직 보이는 중에 나타난 다른 휴대폰은 이어 받지 않고 경보한다."""
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(mfg=IPHONE, rssi=-65, addr="OLD", ts=t0))
    clock["t"] = t0 + 1
    tr.set_baseline()
    alerts = []
    for i in range(15):
        tr.ingest(obs(mfg=IPHONE, rssi=-65, addr="OLD", ts=t0 + 2 + i))
        alerts.append(tr.ingest(obs(mfg=IPHONE, rssi=-65, addr="OTHER", ts=t0 + 2 + i)))
    assert not tr.devices["OTHER"].in_baseline
    assert any(a and a["device_id"] == "OTHER" for a in alerts)


def test_rotation_inheritance_never_applies_to_targets(db):
    t0 = 1000.0
    tr, clock = make_tracker(db, t0)
    tr.ingest(obs(mfg=airpods(), rssi=-65, addr="OLD", ts=t0))
    clock["t"] = t0 + 1
    tr.set_baseline()
    assert tr.ingest(obs(mfg=airpods(), rssi=-65, addr="NEW", ts=t0 + 5))
    assert not tr.devices["NEW"].in_baseline


def test_new_airpods_models_labelled(db):
    assert db.classify(obs(mfg=airpods(b"\x24\x20"))).model == "AirPods Pro 2 (USB-C)"
