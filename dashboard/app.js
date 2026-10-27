/* Rahyaab dashboard logic — plain JS, no libraries, no build step.
   Every number on screen comes from the hub API. Charts draw only
   from /api/pairs/{id}/history; with no history points the chart
   area says so instead of inventing a line. */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
let state = { servers: [], pairs: [], events: [], filter: "all", section: "overview" };

let serverMetrics = {};
let pairMetrics = {};

async function api(method, path, body) {
  const res = await fetch(path, {
    method, credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { const e = new Error(data.error || ("HTTP " + res.status)); e.status = res.status; throw e; }
  return data;
}

function faTime(ts) {
  return new Date(ts * 1000).toLocaleString("fa-IR");
}

function pairState(pair) {
  const s = pair.healer_last_status;
  if (!s || s.reachable === false) return "down";
  if (s.healthy) return "healthy";
  return "stale";
}
function badgeFor(st) {
  return { healthy: ["سالم", "healthy"], stale: ["هشدار / قدیمی", "stale"],
           down: ["قطع / دسترس‌ناپذیر", "down"] }[st];
}

function protoClass(proto) {
  return proto === "GRE" ? "proto-GRE" : proto === "ESP" ? "proto-ESP" : "proto-other";
}
function metricFresh(m) {
  if (!m) return "unknown";
  return (Date.now() / 1000 - m.created_at) < 180 ? "fresh" : "stale";
}
function serverMini(server, roleLabel) {
  if (!server) return "";
  const m = (serverMetrics[server.id] || []).slice(-1)[0];
  const fresh = metricFresh(m);
  const dot = fresh === "fresh" ? "mini-dot" : fresh === "stale" ? "mini-dot stale" : "mini-dot unknown";
  if (!m) return `<div class="server-mini"><div class="server-mini-head"><span class="${dot}"></span><b>${roleLabel} — ${server.name}</b>`
    + `<span class="host ltr">${server.host}</span></div><p class="muted small">هنوز متریکی ثبت نشده است.</p></div>`;
  return `<div class="server-mini"><div class="server-mini-head"><span class="${dot}"></span><b>${roleLabel} — ${server.name}</b>`
    + `<span class="host ltr">${server.host}</span></div>`
    + `<div class="mini-row"><span>بار CPU</span><b class="ltr">${m.load1 ?? "—"}</b></div>`
    + `<div class="mini-row"><span>حافظه</span><b>${m.mem_used_pct ?? "—"}٪</b></div>${bar(m.mem_used_pct, "grad-mem")}`
    + `<div class="mini-row"><span>دیسک</span><b>${m.disk_used_pct ?? "—"}٪</b></div>${bar(m.disk_used_pct, "grad-disk")}`
    + `<div class="mini-row"><span>آپتایم</span><b>${fmtUptime(m.uptime_seconds)}</b></div></div>`;
}
function fmtUptime(sec) {
  if (sec == null) return "—";
  const days = Math.floor(sec / 86400);
  if (days > 0) return days + " روز";
  return Math.floor(sec / 3600) + " ساعت";
}
function bar(pct, cls) {
  const p = Math.max(0, Math.min(100, pct ?? 0));
  return `<div class="bar"><div class="fill ${cls || ""}" style="width:${p}%"></div></div>`;
}


function renderPairs() {
  const rank = { down: 0, stale: 1, healthy: 2 };
  const list = state.pairs.filter(p => state.filter === "all" || pairState(p) === state.filter)
    .sort((a, b) => rank[pairState(a)] - rank[pairState(b)]);
  $("#pair-cards").innerHTML = list.map(p => {
    const st = pairState(p), [label, cls] = badgeFor(st);
    const pm = pairMetrics[p.id] || [];
    const lat = pm.filter(x => x.latency_ms != null).map(x => x.latency_ms);
    const thr = pm.filter(x => x.rx_kbps != null).map(x => x.rx_kbps + x.tx_kbps);
    const lastLat = lat.length ? lat[lat.length - 1].toFixed(1) + " ms" : "—";
    const lastThr = thr.length ? thr[thr.length - 1].toFixed(1) + " kbps" : "—";
    const scores = Object.entries(p.candidate_scores || {}).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const scoreRows = scores.length ? scores.map(([name, score]) =>
      `<div class="score-row"><span class="ltr">${name}</span>${bar(score, "green")}<span class="ltr">${score}</span></div>`).join("")
      : '<p class="muted small">امتیازی ثبت نشده است.</p>';
    const iran = state.servers.find(s => s.id === p.iran_server_id);
    const foreign = state.servers.find(s => s.id === p.foreign_server_id);
    const dotCls = st === "healthy" ? "status-dot pulse" : st === "stale" ? "status-dot stale" : "status-dot down";
    return `<article class="card tunnel-box st-${st}" data-id="${p.id}">
      <div class="tunnel-head">
        <span class="status-ring ${st}"><span class="${dotCls}"></span></span>
        <div class="tunnel-title">
          <h3>${p.name}</h3>
          <div class="tunnel-badges">
            <span class="proto-badge ${protoClass(p.current_protocol)} ltr">${p.current_protocol || "—"}</span>
            <span class="badge ${cls}">${label}</span>
            <span class="muted small">فرانت‌اند: <span class="ltr">${p.frontend_port || "—"}</span></span>
          </div>
        </div>
        <div class="tunnel-kpis">
          <div class="kpi"><span>تأخیر زنده</span><b class="ltr">${lastLat}</b></div>
          <div class="kpi"><span>توان زنده</span><b class="ltr">${lastThr}</b></div>
        </div>
      </div>
      <p class="meta">مسیر داخلی: <span class="ltr">${p.inner_iran || "—"} ⇄ ${p.inner_foreign || "—"}</span></p>
      <div class="servers-mini">${serverMini(iran, "ایران")}${serverMini(foreign, "خارج")}</div>
      <div class="chart-wrap score-wrap"><div class="muted small">امتیاز پروتکل‌ها (بنچمارک)</div>${scoreRows}</div>
      <div class="actions">
        <button class="act-btn green" data-act="refresh">↻ تازه‌سازی وضعیت</button>
        <button class="act-btn blue" data-act="restart">⟳ ری‌استارت نگهبان</button>
      </div>
    </article>`;
  }).join("");
  $("#pairs-empty").hidden = state.pairs.length > 0;
  $$("#pair-cards .tunnel-box").forEach(card => {
    const id = card.dataset.id;
    card.querySelector('[data-act="refresh"]').onclick = async () => {
      await api("POST", "/api/jobs", { type: "healer_status", pair_id: +id });
      showBanner("جاب تازه‌سازی وضعیت ساخته شد؛ چند ثانیه دیگر تازه‌سازی کنید.");
      setTimeout(loadAll, 3000);
    };
    card.querySelector('[data-act="restart"]').onclick = async () => {
      if (!confirm("نگهبان این جفت ری‌استارت شود؟")) return;
      await api("POST", `/api/pairs/${id}/healer/restart`);
      showBanner("دستور ری‌استارت نگهبان فرستاده شد.");
    };
  });
}

function renderServerStrip() {
  $("#server-strip").innerHTML = state.servers.map(s => {
    const m = (serverMetrics[s.id] || []).slice(-1)[0];
    const fresh = metricFresh(m);
    const dot = fresh === "fresh" ? "mini-dot" : fresh === "stale" ? "mini-dot stale" : "mini-dot unknown";
    if (!m) return `<div class="server-strip-item"><span class="${dot}"></span><b>${s.name}</b>`
      + `<span class="host ltr">${s.host}</span><span class="muted">هنوز متریکی ثبت نشده است.</span></div>`;
    return `<div class="server-strip-item"><span class="${dot}"></span><b>${s.name}</b>`
      + `<span class="host ltr">${s.host}</span>`
      + `<span>بار CPU <b class="ltr">${m.load1 ?? "—"}</b></span>`
      + `<span>حافظه <b>${m.mem_used_pct ?? "—"}٪</b></span>`
      + `<span>دیسک <b>${m.disk_used_pct ?? "—"}٪</b></span>`
      + `<span>آپتایم <b>${fmtUptime(m.uptime_seconds)}</b></span></div>`;
  }).join("");
}

function renderTables() {
  const serverName = id => (state.servers.find(s => s.id === id) || {}).name || id;
  $("#server-cards").innerHTML = state.servers.map(s => {
    const m = (serverMetrics[s.id] || []).slice(-1)[0];
    if (!m) return `<article class="card server-card"><h3>${s.name}</h3>
      <p class="meta ltr">${s.host}:${s.port}</p><p class="muted small">هنوز متریکی ثبت نشده است.</p></article>`;
    return `<article class="card server-card"><h3>${s.name}</h3>
      <p class="meta ltr">${s.host}:${s.port}</p>
      <p class="meta">بار CPU: <span class="ltr">${m.load1 ?? "—"}</span> · آپتایم: ${fmtUptime(m.uptime_seconds)}</p>
      <div class="muted small">حافظه ${m.mem_used_pct ?? "—"}٪</div>${bar(m.mem_used_pct, "grad-mem")}
      <div class="muted small">دیسک ${m.disk_used_pct ?? "—"}٪</div>${bar(m.disk_used_pct, "grad-disk")}</article>`;
  }).join("");
  $("#server-table-wrap").innerHTML = state.servers.length ? `<table><tr><th>نام</th><th>هاست</th><th>کاربر</th><th></th></tr>${
    state.servers.map(s => `<tr><td>${s.name}</td><td class="ltr">${s.host}:${s.port}</td><td class="ltr">${s.username}</td>
    <td><button class="btn ghost" data-del="${s.id}">حذف</button></td></tr>`).join("")}</table>`
    : '<p class="muted">هنوز سروری ثبت نشده است.</p>';
  $$("#server-table-wrap [data-del]").forEach(b => b.onclick = async () => {
    try { await api("DELETE", `/api/servers/${b.dataset.del}`); loadAll(); }
    catch (e) { showBanner(e.message, true); }
  });
  $("#pair-table-wrap").innerHTML = state.pairs.length ? `<table><tr><th>نام</th><th>ایران</th><th>خارج</th><th>پروتکل</th><th>وضعیت</th><th></th></tr>${
    state.pairs.map(p => { const [label, cls] = badgeFor(pairState(p));
      return `<tr><td>${p.name}</td><td>${serverName(p.iran_server_id)}</td><td>${serverName(p.foreign_server_id)}</td>
      <td class="ltr">${p.current_protocol || "—"}</td><td><span class="badge ${cls}">${label}</span></td>
      <td><button class="btn ghost" data-del="${p.id}">حذف</button></td></tr>`; }).join("")}</table>`
    : '<p class="muted">هنوز جفتی ساخته نشده است.</p>';
  $$("#pair-table-wrap [data-del]").forEach(b => b.onclick = async () => {
    if (!confirm("این جفت حذف شود؟")) return;
    await api("DELETE", `/api/pairs/${b.dataset.del}`); loadAll();
  });
  $("#event-list").innerHTML = state.events.map(e =>
    `<li><time>${faTime(e.created_at)}</time><div>${e.message}</div></li>`).join("");
}

function renderCounters() {
  const counts = { all: state.pairs.length, healthy: 0, stale: 0, down: 0 };
  state.pairs.forEach(p => counts[pairState(p)]++);
  $("#c-all").textContent = counts.all; $("#c-healthy").textContent = counts.healthy;
  $("#c-stale").textContent = counts.stale; $("#c-down").textContent = counts.down;
  const lats = [], thrs = [];
  state.pairs.forEach(p => {
    const pm = pairMetrics[p.id] || [];
    const lat = [...pm].reverse().find(x => x.latency_ms != null);
    const thr = [...pm].reverse().find(x => x.rx_kbps != null);
    if (lat) lats.push(lat.latency_ms);
    if (thr) thrs.push(thr.rx_kbps + thr.tx_kbps);
  });
  const avgLat = lats.length ? (lats.reduce((a, b) => a + b, 0) / lats.length).toFixed(1) + " ms" : "—";
  const totThr = thrs.length ? thrs.reduce((a, b) => a + b, 0).toFixed(1) + " kbps" : "—";
  const netIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="12" r="2.5"/><path d="M7.5 12h9"/></svg>';
  const srvIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="4.5" rx="1.5"/><rect x="3" y="10" width="18" height="4.5" rx="1.5"/><rect x="3" y="16" width="18" height="4.5" rx="1.5"/></svg>';
  const gaugeIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 14a8 8 0 1 1 16 0"/><path d="M12 14l4-5"/></svg>';
  const boltIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z"/></svg>';
  $("#stat-cards").innerHTML =
    `<div class="card stat-card c-green" data-stat="pairs"><div class="stat-chip chip-green">${netIcon}</div>`
    + `<h3>جفت‌ها</h3><div class="stat-value">${counts.all}</div><div class="stat-sub">${counts.healthy} سالم</div></div>`
    + `<div class="card stat-card c-blue" data-stat="servers"><div class="stat-chip chip-blue">${srvIcon}</div>`
    + `<h3>سرورها</h3><div class="stat-value">${state.servers.length}</div><div class="stat-sub">ثبت‌شده در فلیت</div></div>`
    + `<div class="card stat-card c-purple"><div class="stat-chip chip-purple">${gaugeIcon}</div>`
    + `<h3>تأخیر تانل‌ها</h3><div class="stat-value ltr">${avgLat}</div><div class="stat-sub">میانگین تازه‌ترین نمونه</div></div>`
    + `<div class="card stat-card c-orange"><div class="stat-chip chip-orange">${boltIcon}</div>`
    + `<h3>توان تانل‌ها</h3><div class="stat-value ltr">${totThr}</div><div class="stat-sub">مجموع تازه‌ترین نمونه</div></div>`;
  $$("#stat-cards [data-stat]").forEach(card => card.onclick = () => {
    if (card.dataset.stat === "pairs") { state.filter = "all"; showSection("overview"); renderCounters(); renderPairs(); }
    if (card.dataset.stat === "servers") showSection("servers");
  });
  $$("#counter-strip .counter").forEach(b => b.classList.toggle("active", b.dataset.filter === state.filter));
}

async function loadAll() {
  try {
    const [s, p, ev] = await Promise.all([
      api("GET", "/api/servers"), api("GET", "/api/pairs"), api("GET", "/api/events")]);
    state.servers = s.servers; state.pairs = p.pairs; state.events = ev.events;
    await Promise.all([
      ...state.servers.map(async sv => {
        try { const d = await api("GET", `/api/servers/${sv.id}/metrics`); serverMetrics[sv.id] = d.metrics; }
        catch { serverMetrics[sv.id] = []; }
      }),
      ...state.pairs.map(async pr => {
        try { const d = await api("GET", `/api/pairs/${pr.id}/metrics`); pairMetrics[pr.id] = d.metrics; }
        catch { pairMetrics[pr.id] = []; }
      }),
    ]);
    renderCounters(); renderServerStrip(); renderPairs(); renderTables();
    $("#conn-dot").className = "dot ok"; $("#conn-text").textContent = "متصل به هاب";
  } catch (e) {
    if (e.status === 401) { showAuth(); return; }
    $("#conn-dot").className = "dot bad"; $("#conn-text").textContent = "قطع از هاب";
  }
}

function showBanner(msg, isError = false) {
  const b = $("#banner"); b.textContent = msg; b.hidden = false;
  b.style.borderColor = isError ? "var(--red)" : "var(--amber)";
  setTimeout(() => b.hidden = true, 6000);
}

function showSection(name) {
  state.section = name;
  $$(".section").forEach(s => s.hidden = true);
  $("#section-" + name).hidden = false;
  $$(".nav a").forEach(a => a.classList.toggle("active", a.dataset.section === name));
  $("#page-title").textContent = { overview: "داشبورد", pairs: "جفت‌ها", servers: "سرورها", events: "رویدادها" }[name];
}
$$(".nav a").forEach(a => a.onclick = e => { e.preventDefault(); showSection(a.dataset.section); });

function showAuth() {
  $("#app").hidden = true; $("#auth-view").hidden = false;
  api("GET", "/api/health").then(h => {
    $("#setup-form").hidden = h.users; $("#login-form").hidden = !h.users;
  }).catch(() => { $("#login-form").hidden = false; });
}
function authError(msg) { const el = $("#auth-error"); el.textContent = msg; el.hidden = false; }
$("#setup-form").onsubmit = async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  try { await api("POST", "/api/setup", { username: f.get("username"), password: f.get("password") }); location.reload(); }
  catch (err) { authError(err.message); }
};
$("#login-form").onsubmit = async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  try { await api("POST", "/api/login", { username: f.get("username"), password: f.get("password") }); location.reload(); }
  catch (err) { authError(err.message); }
};
$("#logout-btn").onclick = async () => { await api("POST", "/api/logout").catch(() => {}); location.reload(); };
$("#refresh-btn").onclick = loadAll;
$("#theme-btn").onclick = () => {
  const root = document.documentElement;
  const next = root.dataset.theme === "dark" ? "light" : "dark";
  root.dataset.theme = next; localStorage.setItem("rahyaab-theme", next);
};
document.documentElement.dataset.theme = localStorage.getItem("rahyaab-theme") || "dark";
$("#sidebar-open").onclick = () => $("#sidebar").classList.add("open");
$("#sidebar-close").onclick = () => $("#sidebar").classList.remove("open");
$$("#counter-strip .counter").forEach(b => b.onclick = () => {
  state.filter = b.dataset.filter; showSection("overview"); renderCounters(); renderPairs();
});
$("#add-server-btn").onclick = () => $("#server-dialog").showModal();
$("#server-cancel").onclick = () => $("#server-dialog").close();
$("#server-form").onsubmit = async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("POST", "/api/servers", { name: f.get("name"), host: f.get("host"),
      port: +(f.get("port") || 22), username: f.get("username") || "root",
      key_path: f.get("key_path") || null, notes: f.get("notes") || "" });
    $("#server-dialog").close(); loadAll();
  } catch (err) { showBanner(err.message, true); }
};
function fillPairSelects() {
  const opts = state.servers.map(s => `<option value="${s.id}">${s.name}</option>`).join("");
  $("#pair-iran").innerHTML = opts; $("#pair-foreign").innerHTML = opts; $("#pair-healer").innerHTML = opts;
}
$("#add-pair-btn").onclick = () => { fillPairSelects(); $("#pair-dialog").showModal(); };
$("#pair-cancel").onclick = () => $("#pair-dialog").close();
$("#pair-form").onsubmit = async e => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("POST", "/api/pairs", { name: f.get("name"),
      iran_server_id: +f.get("iran_server_id"), foreign_server_id: +f.get("foreign_server_id"),
      healer_server_id: +f.get("healer_server_id"), frontend_port: +(f.get("frontend_port") || 443) });
    $("#pair-dialog").close(); loadAll();
  } catch (err) { showBanner(err.message, true); }
};

// Command palette (Ctrl-K), modelled on Nexora's: pages + actions.
const paletteItems = [
  { label: "داشبورد", run: () => showSection("overview") },
  { label: "جفت‌ها", run: () => showSection("pairs") },
  { label: "سرورها", run: () => showSection("servers") },
  { label: "رویدادها", run: () => showSection("events") },
  { label: "جفت تازه", run: () => { fillPairSelects(); $("#pair-dialog").showModal(); } },
  { label: "سرور تازه", run: () => $("#server-dialog").showModal() },
  { label: "تازه‌سازی", run: loadAll },
];
function openPalette() {
  $("#palette").hidden = false;
  const input = $("#palette-input"); input.value = ""; renderPalette("");
  input.focus();
  input.oninput = () => renderPalette(input.value);
  input.onkeydown = e => {
    if (e.key === "Escape") closePalette();
    if (e.key === "Enter") { const sel = $("#palette-list li.sel"); if (sel) sel.click(); }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const items = $$("#palette-list li"); if (!items.length) return;
      let i = items.findIndex(li => li.classList.contains("sel"));
      i = e.key === "ArrowDown" ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
      items.forEach((li, j) => li.classList.toggle("sel", j === i));
    }
  };
}
function renderPalette(q) {
  const items = paletteItems.filter(it => it.label.includes(q));
  $("#palette-list").innerHTML = items.map((it, i) =>
    `<li class="${i === 0 ? "sel" : ""}">${it.label}</li>`).join("");
  $$("#palette-list li").forEach((li, i) => li.onclick = () => { closePalette(); items[i].run(); });
}
function closePalette() { $("#palette").hidden = true; }
$("#search-btn").onclick = openPalette;
$("#palette").onclick = e => { if (e.target.id === "palette") closePalette(); };
document.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
  if (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "SELECT") {
    e.preventDefault(); openPalette();
  }
});

async function boot() {
  try {
    await api("GET", "/api/servers");
    $("#auth-view").hidden = true; $("#app").hidden = false;
    await loadAll();
  } catch (e) {
    if (e.status === 401) showAuth();
    else { $("#conn-dot").className = "dot bad"; $("#conn-text").textContent = "قطع از هاب"; }
  }
  setInterval(() => { if (!$("#app").hidden) loadAll(); }, 20000);
}
boot();
