/* Rahyaab dashboard logic — plain JS, no libraries, no build step.
   Every number on screen comes from the hub API. Charts draw only
   from /api/pairs/{id}/history; with no history points the chart
   area says so instead of inventing a line. */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
let state = { servers: [], pairs: [], events: [], filter: "all", section: "overview" };
let histories = {};

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

function stepChart(points, key) {
  if (!points.length) return '<p class="empty">هنوز نقطه‌ای ثبت نشده است — بعد از اولین تازه‌سازی وضعیت، نمودار اینجا کشیده می‌شود.</p>';
  const w = 300, h = 56, pad = 4;
  const vals = points.map(p => (key === "healthy" ? (p.healthy ? 1 : 0) : (p.heartbeat_age_seconds ?? 0)));
  const max = key === "healthy" ? 1 : Math.max(...vals, 1);
  const step = points.length > 1 ? (w - 2 * pad) / (points.length - 1) : 0;
  let d = "";
  vals.forEach((v, i) => {
    const x = pad + i * step, y = h - pad - (v / max) * (h - 2 * pad);
    d += (i === 0 ? "M" : "L") + x.toFixed(1) + " " + y.toFixed(1) + " ";
  });
  const color = key === "healthy" ? "var(--green)" : "var(--accent)";
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><path d="${d}" fill="none" stroke="${color}" stroke-width="2"/></svg>`;
}

async function loadPairHistory(pair) {
  try { const d = await api("GET", `/api/pairs/${pair.id}/history`); histories[pair.id] = d.history; }
  catch { histories[pair.id] = []; }
}

function renderPairs() {
  const list = state.pairs.filter(p => state.filter === "all" || pairState(p) === state.filter);
  $("#pair-cards").innerHTML = list.map(p => {
    const st = pairState(p), [label, cls] = badgeFor(st);
    const hist = histories[p.id] || [];
    return `<article class="card pair-card" data-id="${p.id}">
      <h3>${p.name}</h3>
      <span class="badge ${cls}">${label}</span>
      <p class="meta">پروتکل جاری: <span class="ltr">${p.current_protocol || "—"}</span> ·
        داخلی: <span class="ltr">${p.inner_iran || "—"} / ${p.inner_foreign || "—"}</span></p>
      <div class="chart-wrap"><div class="muted small">سلامت نگهبان در طول زمان</div>${stepChart(hist, "healthy")}</div>
      <div class="chart-wrap"><div class="muted small">سن هارت‌بیت (ثانیه)</div>${stepChart(hist, "age")}</div>
      <div class="actions">
        <button class="btn ghost" data-act="refresh">تازه‌سازی وضعیت</button>
        <button class="btn ghost" data-act="restart">ری‌استارت نگهبان</button>
      </div>
    </article>`;
  }).join("");
  $("#pairs-empty").hidden = state.pairs.length > 0;
  $$("#pair-cards .pair-card").forEach(card => {
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

function renderTables() {
  const serverName = id => (state.servers.find(s => s.id === id) || {}).name || id;
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
  $("#k-servers").textContent = state.servers.length;
  $("#k-pairs").textContent = state.pairs.length;
  $("#k-proto").textContent = state.pairs.length ? (state.pairs[state.pairs.length - 1].current_protocol || "—") : "—";
  $("#k-events").textContent = state.events.length;
  $$("#counter-strip .counter").forEach(b => b.classList.toggle("active", b.dataset.filter === state.filter));
}

async function loadAll() {
  try {
    const [s, p, ev] = await Promise.all([
      api("GET", "/api/servers"), api("GET", "/api/pairs"), api("GET", "/api/events")]);
    state.servers = s.servers; state.pairs = p.pairs; state.events = ev.events;
    await Promise.all(state.pairs.map(loadPairHistory));
    renderCounters(); renderPairs(); renderTables();
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
