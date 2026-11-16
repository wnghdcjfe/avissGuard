"use strict";

// BLE 기기 이름은 누구나 임의로 정할 수 있으므로, 화면에 넣는 모든 값은 반드시 이스케이프한다.
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const $ = (id) => document.getElementById(id);
const CAT_ICON = { camera: "📷", glasses: "👓", earpiece: "🎧", wearable: "⌚", phone: "📱", computer: "💻", tag: "🏷️", infra: "📡", unknown: "❔" };
const LEVEL_TEXT = { high: "경보", medium: "주의", low: "일반" };

const state = {
  snap: null,
  alerts: [],
  filter: "suspect",
  query: "",
  sound: true,
  selected: null,
  ws: null,
  retry: 0,
};

try {
  state.sound = localStorage.getItem("avg.sound") !== "off";
  state.filter = localStorage.getItem("avg.filter") || "suspect";
} catch (_) {}

// ---------------------------------------------------------------- 연결
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  state.ws = ws;
  ws.onopen = () => { state.retry = 0; $("conn").classList.add("on"); };
  ws.onclose = () => {
    $("conn").classList.remove("on");
    setMode({ scanner: "offline" });
    const delay = Math.min(10000, 1000 * 2 ** state.retry++);
    setTimeout(connect, delay);
  };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "hello") state.alerts = msg.alerts || [];
    if (msg.new_alerts && msg.new_alerts.length) onNewAlerts(msg.new_alerts);
    state.snap = msg;
    render();
  };
}
setInterval(() => { if (state.ws && state.ws.readyState === 1) state.ws.send("ping"); }, 20000);

// ---------------------------------------------------------------- 경보
let audioCtx = null;
function beep(level) {
  if (!state.sound) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const notes = level === "high" ? [880, 660, 880] : [660];
    notes.forEach((f, i) => {
      const o = audioCtx.createOscillator();
      const g = audioCtx.createGain();
      o.type = "square";
      o.frequency.value = f;
      const t = audioCtx.currentTime + i * 0.18;
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.08, t + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.15);
      o.connect(g).connect(audioCtx.destination);
      o.start(t);
      o.stop(t + 0.16);
    });
  } catch (_) {}
}

function onNewAlerts(list) {
  const fresh = new Set();
  for (const a of list) {
    if (state.alerts.some((x) => x.id === a.id)) continue;
    state.alerts.unshift(a);
    fresh.add(a.id);
  }
  state.alerts = state.alerts.slice(0, 200);
  state.freshIds = fresh;
  const worst = list.some((a) => a.level === "high") ? "high" : "medium";
  beep(worst);
  if (worst === "high" && "Notification" in window && Notification.permission === "granted" && document.hidden) {
    const a = list.find((x) => x.level === "high");
    new Notification("AvissGuard 경보", { body: a.message, tag: "avg-" + a.device_id });
  }
}

// ---------------------------------------------------------------- 렌더링
function setMode(status) {
  const el = $("mode");
  el.className = "badge";
  if (status.scanner === "offline") { el.textContent = "서버 연결 끊김"; el.classList.add("err"); return; }
  if (status.error) { el.textContent = "스캐너 오류"; el.title = status.error; el.classList.add("err"); return; }
  if (status.scanner === "simulate") { el.textContent = "시뮬레이션"; el.classList.add("sim"); }
  else if (status.scanner === "ble") { el.textContent = status.running ? "실시간 BLE 스캔" : "스캐너 시작 중"; el.classList.add("live"); }
  else { el.textContent = "스캔 꺼짐"; }
  el.title = `시그니처 ${status.signatures}개 · TTL ${status.ttl}s`;
}

function render() {
  const s = state.snap;
  if (!s) return;
  setMode(s.status || {});
  renderThreat(s);
  renderKpis(s);
  renderAlerts();
  renderTable(s);
  if (state.selected) renderDrawer();
}

function renderThreat(s) {
  const box = $("threat");
  box.className = "threat " + s.threat;
  const top = s.devices.find((d) => d.level === s.threat) || null;
  if (s.threat === "high") {
    $("threat-title").textContent = `경보 — 의심 기기 ${s.counts.by_level.high}대`;
    $("threat-sub").textContent = top ? `${top.label} · ${top.name || top.model || "이름 없음"} · 약 ${top.distance}m` : "";
  } else if (s.threat === "medium") {
    $("threat-title").textContent = `주의 — 확인 필요 기기 ${s.counts.by_level.medium}대`;
    $("threat-sub").textContent = top ? `${top.label} · ${top.name || top.model || "이름 없음"} · 약 ${top.distance}m` : "";
  } else {
    $("threat-title").textContent = "이상 없음";
    $("threat-sub").textContent = s.baseline.active
      ? `기준선 ${s.baseline.size}대 등록됨 (${fmtTime(s.baseline.set_at)}). 새로 나타나는 기기를 감시 중입니다.`
      : "응시자 입실 전에 '기준선 설정'을 눌러 원래 있던 기기를 등록하세요.";
  }
  $("btn-baseline").textContent = s.baseline.active ? "기준선 다시 설정" : "기준선 설정";
  $("btn-clear-baseline").hidden = !s.baseline.active;
}

function renderKpis(s) {
  const c = s.counts;
  $("k-active").textContent = c.active;
  $("k-packets").textContent = `패킷 ${s.packets.toLocaleString()}`;
  $("k-high").textContent = c.by_level.high;
  $("k-medium").textContent = c.by_level.medium;
  $("k-camera").textContent = c.by_category.camera || 0;
  $("k-earpiece").textContent = c.by_category.earpiece || 0;
  $("k-glasses").textContent = c.by_category.glasses || 0;
}

function renderAlerts() {
  const ol = $("alerts");
  $("alert-count").textContent = `${state.alerts.length}건 · 미확인 ${state.alerts.filter((a) => !a.acknowledged).length}`;
  if (!state.alerts.length) { ol.innerHTML = '<li class="empty">아직 경보가 없습니다.</li>'; return; }
  const fresh = state.freshIds || new Set();
  ol.innerHTML = state.alerts.slice(0, 80).map((a) => `
    <li class="${esc(a.level)} ${a.acknowledged ? "acked" : ""} ${fresh.has(a.id) ? "fresh" : ""}" data-id="${esc(a.device_id)}">
      <span class="t">${fmtTime(a.ts)}</span>
      <span class="m">${CAT_ICON[a.category] || ""} ${esc(a.label)}</span>
      <span class="s">${esc(a.name || "이름 없음")} · 위험도 ${esc(a.score)} · 약 ${esc(a.distance)}m · ${esc(a.rssi)}dBm</span>
    </li>`).join("");
  state.freshIds = null;
}

function spark(hist, w = 110, h = 26, cls = "spark") {
  if (!hist || hist.length < 2) return `<svg class="${cls}" viewBox="0 0 ${w} ${h}"></svg>`;
  const lo = -100, hi = -35;
  const pts = hist.map((v, i) => {
    const x = (i / (hist.length - 1)) * (w - 2) + 1;
    const y = h - 2 - ((Math.max(lo, Math.min(hi, v)) - lo) / (hi - lo)) * (h - 4);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return `<svg class="${cls}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polyline points="${pts.join(" ")}" /></svg>`;
}

function visibleDevices(s) {
  const q = state.query.trim().toLowerCase();
  return s.devices.filter((d) => {
    if (state.filter === "suspect" && !(d.level !== "low" || d.is_target)) return false;
    if (!q) return true;
    return [d.name, d.label, d.vendor, d.model, d.id, d.category_label].some((v) => v && String(v).toLowerCase().includes(q));
  });
}

function renderTable(s) {
  document.querySelectorAll(".seg-btn").forEach((b) => b.classList.toggle("active", b.dataset.filter === state.filter));
  const rows = visibleDevices(s);
  const body = $("device-rows");
  if (!rows.length) {
    const msg = s.devices.length ? (state.query ? "검색 결과가 없습니다." : "의심 기기가 없습니다. '전체'에서 모든 기기를 볼 수 있습니다.") : "주변에서 BLE 신호를 기다리는 중…";
    body.innerHTML = `<tr><td colspan="8" class="empty">${msg}</td></tr>`;
    return;
  }
  body.innerHTML = rows.map((d) => {
    const isNew = s.baseline.active && !d.in_baseline;
    return `
    <tr class="${esc(d.level)}" data-id="${esc(d.id)}">
      <td><span class="score"><b>${d.score}</b><span class="bar"><i style="width:${d.score}%"></i></span></span></td>
      <td><span class="chip ${d.is_target ? "target" : ""}">${CAT_ICON[d.category] || ""} ${esc(d.category_label)}</span></td>
      <td>
        <div class="dev-name">${esc(d.name || d.model || "이름 없음")}
          ${d.in_baseline ? '<span class="tag base">기준선</span>' : ""}
          ${isNew ? '<span class="tag new">신규</span>' : ""}
          ${d.whitelisted ? '<span class="tag white">허용</span>' : ""}
        </div>
        <div class="dev-sub">${esc(d.label)}${d.vendor ? " · " + esc(d.vendor) : ""}</div>
      </td>
      <td class="num">${d.rssi}</td>
      <td class="num">${d.distance}m</td>
      <td>${spark(d.history)}</td>
      <td class="muted">${fmtDur(d.duration)}<br><small>${d.age < 3 ? "방금" : Math.round(d.age) + "초 전"}</small></td>
      <td>${d.whitelisted ? "" : `<button class="btn small" data-allow="${esc(d.id)}" title="감독관 기기 등 허용 목록에 추가">허용</button>`}</td>
    </tr>`;
  }).join("");
}

function renderDrawer() {
  const d = state.snap && state.snap.devices.find((x) => x.id === state.selected);
  const body = $("drawer-body");
  if (!d) { body.innerHTML = `<h3>기기 신호 끊김</h3><p class="muted">${esc(state.selected)} 기기가 ${state.snap ? state.snap.status.ttl : 30}초 이상 보이지 않습니다.</p>`; return; }
  body.innerHTML = `
    <div class="chip ${d.is_target ? "target" : ""}">${CAT_ICON[d.category] || ""} ${esc(d.category_label)} · ${LEVEL_TEXT[d.level]} ${d.score}</div>
    <h3>${esc(d.name || d.model || "이름 없음")}</h3>
    <div class="muted">${esc(d.label)}</div>
    <h4>판단 근거</h4>
    <ul class="reasons">${d.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
    <h4>신호 세기 (최근 ${d.history.length}회)</h4>
    ${spark(d.history, 400, 90, "spark big")}
    <dl>
      <dt>RSSI</dt><dd>${d.rssi} dBm${d.tx_power != null ? ` (TX ${d.tx_power})` : ""}</dd>
      <dt>추정 거리</dt><dd>약 ${d.distance} m</dd>
      <dt>주소/ID</dt><dd>${esc(d.id)}</dd>
      <dt>제조사</dt><dd>${esc(d.vendor || "-")} ${esc(d.company_ids.join(", "))}</dd>
      <dt>모델</dt><dd>${esc(d.model || "-")}</dd>
      <dt>서비스 UUID</dt><dd>${esc(d.service_uuids.join(", ") || "-")}</dd>
      <dt>매칭 규칙</dt><dd>${esc(d.matched_rules.join(", ") || "-")}</dd>
      <dt>최초 탐지</dt><dd>${fmtTime(d.first_seen)}</dd>
      <dt>패킷 수</dt><dd>${d.sightings}</dd>
      <dt>지문</dt><dd>${esc(d.fingerprint || "-")}</dd>
    </dl>
    <p class="muted" style="font-size:12px">찾는 요령: 노트북을 들고 이동하며 RSSI가 커지는(−50 이상) 쪽으로 다가가세요. 주소는 일정 시간마다 바뀔 수 있습니다.</p>
    <div class="actions">
      ${d.whitelisted ? "" : `<button class="btn" data-allow="${esc(d.id)}">허용 목록에 추가</button>`}
    </div>`;
}

// ---------------------------------------------------------------- 레이더
const radar = $("radar");
const rctx = radar.getContext("2d");
const MAX_M = 20;
function hashAngle(id) {
  let h = 2166136261;
  for (let i = 0; i < id.length; i++) h = Math.imul(h ^ id.charCodeAt(i), 16777619);
  return ((h >>> 0) % 3600) / 3600 * Math.PI * 2;
}
function radiusFor(m, R) { return R * Math.min(1, Math.log1p(m) / Math.log1p(MAX_M)); }
let radarHits = [];

function drawRadar(ts) {
  const dpr = window.devicePixelRatio || 1;
  const w = radar.clientWidth, h = radar.clientHeight;
  if (radar.width !== w * dpr || radar.height !== h * dpr) { radar.width = w * dpr; radar.height = h * dpr; }
  const ctx = rctx;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 18;
  const css = getComputedStyle(document.documentElement);
  const col = (n) => css.getPropertyValue(n).trim();

  ctx.strokeStyle = col("--line");
  ctx.lineWidth = 1;
  ctx.font = "11px " + col("--mono");
  ctx.fillStyle = col("--muted");
  for (const m of [1, 3, 8, 20]) {
    const r = radiusFor(m, R);
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.stroke();
    ctx.fillText(`${m}m`, cx + 4, cy - r + 12);
  }
  ctx.beginPath(); ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy); ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R); ctx.stroke();

  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduce) {
    const a = (ts / 2500) * Math.PI * 2;
    const grad = ctx.createConicGradient ? ctx.createConicGradient(a - 0.6, cx, cy) : null;
    if (grad) {
      grad.addColorStop(0, "rgba(34,211,238,0)");
      grad.addColorStop(0.095, "rgba(34,211,238,0.18)");
      grad.addColorStop(0.1, "rgba(34,211,238,0)");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();
    }
  }
  ctx.fillStyle = col("--accent");
  ctx.beginPath(); ctx.arc(cx, cy, 4, 0, Math.PI * 2); ctx.fill();

  radarHits = [];
  const placed = [];
  const devs = state.snap ? state.snap.devices : [];
  const pos = new Map();
  for (const d of [...devs].reverse()) {
    const ang = hashAngle(d.id);
    const r = radiusFor(d.distance, R);
    const x = cx + Math.cos(ang) * r, y = cy + Math.sin(ang) * r;
    const c = d.level === "high" ? col("--high") : d.level === "medium" ? col("--medium") : col("--low");
    const size = d.level === "high" ? 7 : d.level === "medium" ? 6 : 4;
    if (d.level === "high" && !reduce) {
      const p = (ts % 1400) / 1400;
      ctx.strokeStyle = c; ctx.globalAlpha = 1 - p; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(x, y, size + p * 16, 0, Math.PI * 2); ctx.stroke();
      ctx.globalAlpha = 1;
    }
    ctx.fillStyle = c;
    ctx.globalAlpha = Math.max(0.35, 1 - d.age / 30);
    ctx.beginPath(); ctx.arc(x, y, size, 0, Math.PI * 2); ctx.fill();
    ctx.globalAlpha = 1;
    if (d.in_baseline) { ctx.strokeStyle = col("--base"); ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, y, size + 3, 0, Math.PI * 2); ctx.stroke(); }
    pos.set(d.id, { x, y, size });
    if (d.id === state.selected) { ctx.strokeStyle = col("--accent"); ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(x, y, size + 6, 0, Math.PI * 2); ctx.stroke(); }
    radarHits.push({ x, y, r: size + 6, id: d.id });
  }
  // 점은 위험도 낮은 것부터 그리고(위에 겹치도록), 라벨은 위험도 높은 기기부터 자리를 잡는다
  const font = "12px " + getComputedStyle(document.body).fontFamily;
  for (const d of devs) {
    if (d.level === "low") continue;
    const p = pos.get(d.id);
    placeLabel(ctx, d, p.x, p.y, p.size, w, h, col("--text"), font, placed);
  }
  requestAnimationFrame(drawRadar);
}

function placeLabel(ctx, d, x, y, size, w, h, color, font, placed) {
  ctx.font = font;
  const text = `${CAT_ICON[d.category] || ""} ${(d.name || d.model || d.label).slice(0, 20)}`;
  const tw = ctx.measureText(text).width, th = 14;
  const candidates = [];
  for (const dy of [0, -15, 15, -30, 30]) {
    candidates.push([x + size + 5, y + dy], [x - size - 5 - tw, y + dy]);
  }
  for (const [lx, ly] of candidates) {
    const box = { l: lx - 2, r: lx + tw + 2, t: ly - th / 2 - 1, b: ly + th / 2 + 1 };
    if (box.l < 0 || box.r > w || box.t < 0 || box.b > h) continue;
    if (placed.some((o) => box.l < o.r && box.r > o.l && box.t < o.b && box.b > o.t)) continue;
    placed.push(box);
    ctx.fillStyle = "rgba(7,11,20,0.7)";
    ctx.fillRect(box.l, box.t, box.r - box.l, box.b - box.t);
    ctx.fillStyle = color;
    ctx.textBaseline = "middle";
    ctx.fillText(text, lx, ly);
    ctx.textBaseline = "alphabetic";
    if (Math.abs(ly - y) > 2) {
      ctx.strokeStyle = "rgba(139,151,173,0.5)"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(lx < x ? box.r : box.l, ly); ctx.stroke();
    }
    return;
  }
}
requestAnimationFrame(drawRadar);

radar.addEventListener("click", (e) => {
  const rect = radar.getBoundingClientRect();
  const x = e.clientX - rect.left, y = e.clientY - rect.top;
  const hit = radarHits.reverse().find((p) => (p.x - x) ** 2 + (p.y - y) ** 2 <= p.r ** 2);
  if (hit) openDrawer(hit.id);
});

// ---------------------------------------------------------------- 상호작용
function openDrawer(id) { state.selected = id; $("drawer").hidden = false; renderDrawer(); }
function closeDrawer() { state.selected = null; $("drawer").hidden = true; }
$("drawer-close").onclick = closeDrawer;
$("drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") closeDrawer(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

async function api(method, path) {
  const r = await fetch(path, { method });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

document.addEventListener("click", async (e) => {
  const allow = e.target.closest("[data-allow]");
  if (allow) { e.stopPropagation(); await api("POST", "/api/whitelist/" + encodeURIComponent(allow.dataset.allow)); return; }
  const row = e.target.closest("tr[data-id], .alerts li[data-id]");
  if (row) openDrawer(row.dataset.id);
});

$("btn-baseline").onclick = async () => {
  const r = await api("POST", "/api/baseline");
  $("threat-sub").textContent = `현재 보이는 기기 ${r.size}대를 기준선으로 등록했습니다.`;
  if ("Notification" in window && Notification.permission === "default") Notification.requestPermission();
};
$("btn-clear-baseline").onclick = () => api("DELETE", "/api/baseline");
$("btn-ack").onclick = async () => {
  await api("POST", "/api/alerts/ack");
  state.alerts.forEach((a) => (a.acknowledged = 1));
  renderAlerts();
};
const soundBtn = $("btn-sound");
const syncSound = () => { soundBtn.setAttribute("aria-pressed", String(state.sound)); soundBtn.textContent = state.sound ? "🔔" : "🔕"; };
soundBtn.onclick = () => {
  state.sound = !state.sound;
  try { localStorage.setItem("avg.sound", state.sound ? "on" : "off"); } catch (_) {}
  syncSound();
  if (state.sound) beep("medium");
};
syncSound();
document.querySelectorAll(".seg-btn").forEach((b) => (b.onclick = () => {
  state.filter = b.dataset.filter;
  try { localStorage.setItem("avg.filter", state.filter); } catch (_) {}
  render();
}));
$("search").addEventListener("input", (e) => { state.query = e.target.value; render(); });

// ---------------------------------------------------------------- 유틸
const pad = (n) => String(n).padStart(2, "0");
function hms(d) { return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
function fmtTime(ts) { return ts ? hms(new Date(ts * 1000)) : "-"; }
function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec}초`;
  if (sec < 3600) return `${Math.floor(sec / 60)}분 ${sec % 60}초`;
  return `${Math.floor(sec / 3600)}시간 ${Math.floor((sec % 3600) / 60)}분`;
}
setInterval(() => { $("clock").textContent = hms(new Date()); }, 1000);

connect();
