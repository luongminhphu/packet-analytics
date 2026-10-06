"use strict";
const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
};

let S = null, selected = null, editing = false, lastSig = "", ifaceSig = "";

// ---------------------------------------------------------------- API / toast
function toast(msg, err = false) {
  const t = el("div", { class: "toast" + (err ? " err" : "") }, msg);
  $("toasts").append(t);
  setTimeout(() => t.remove(), err ? 7000 : 3500);
}
async function api(url, body, method = "POST") {
  const opt = { method, headers: { "X-PA-Request": "1" } };
  if (body !== undefined) { opt.body = JSON.stringify(body); opt.headers["Content-Type"] = "application/json"; }
  const r = await fetch(url, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) { toast(j.error || `Lỗi ${r.status}`, true); throw new Error(j.error || r.status); }
  return j;
}
async function download(url, name) {
  const r = await fetch(url);
  if (!r.ok) { const j = await r.json().catch(() => ({})); return toast(j.error || `Lỗi ${r.status}`, true); }
  const a = el("a", { href: URL.createObjectURL(await r.blob()), download: name });
  document.body.append(a); a.click(); a.remove();
}

// ---------------------------------------------------------------- formatting
const fmtMs = (v) => (v == null ? "-" : v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }));
const fmtDur = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
const label = (k) => S.labels[k] || `First ${k}`;

function heatStyle(v, lo, hi) {
  if (v == null || v <= 0 || hi <= lo) return "";
  const t = Math.min(1, Math.max(0, (Math.log(v) - Math.log(lo)) / (Math.log(hi) - Math.log(lo))));
  return `background:hsla(${Math.round(125 - 95 * t)},60%,50%,.24)`;
}

// ---------------------------------------------------------------- render
function renderHeader() {
  const c = S.capture, j = S.job, pill = $("pill");
  $("chips").replaceChildren(...[`Chế độ: ${S.meta.mode}`, `Mốc: ${S.meta.reference}`, S.meta.tz].map((t) => el("span", { class: "chip" }, t)));
  if (c.running) { pill.className = "pill live"; pill.textContent = `● Đang capture ${c.iface}`; }
  else if (j.running) { pill.className = "pill busy"; pill.textContent = "Đang import…"; }
  else { pill.className = "pill idle"; pill.textContent = "Sẵn sàng"; }
}

function renderSource() {
  const c = S.capture, j = S.job;
  const sig = JSON.stringify([S.interfaces, S.backends]);
  if (sig !== ifaceSig) {
    ifaceSig = sig;
    const cur = $("iface").value, curB = $("backend").value;
    $("iface").replaceChildren(...S.interfaces.map((i) => el("option", { value: i.id }, i.label)));
    $("backend").replaceChildren(el("option", { value: "auto" }, "auto"), ...S.backends.map((b) => el("option", { value: b }, b)));
    if (cur) $("iface").value = cur; if (curB) $("backend").value = curB;
  }
  $("btn-start").disabled = c.running || !S.interfaces.length;
  $("btn-stop").disabled = !c.running;
  [...document.querySelectorAll("#pane-capture select, #pane-capture input")].forEach((x) => (x.disabled = c.running));
  $("cap-info").textContent = c.running
    ? `${c.frames.toLocaleString()} frame · ${fmtDur(c.elapsed_s)} → ${c.file}`
    : c.error ? `Lỗi: ${c.error}` : c.frames ? `Đã dừng — ${c.frames.toLocaleString()} frame lưu ở ${c.file}` : "";
  const pr = $("progress");
  if (j.running) { pr.hidden = false; $("bar").className = "bar ind"; $("ptext").textContent = `Đang đọc ${j.name}: ${j.packets.toLocaleString()} gói`; }
  else if (j.name) {
    pr.hidden = false; $("bar").className = "bar"; $("bar").style.width = j.error ? "0" : "100%";
    $("ptext").textContent = j.error ? `Lỗi: ${j.error}` : `Đã import ${j.name} (${j.packets.toLocaleString()} gói)`;
  }
}

function renderTable() {
  const sig = JSON.stringify([S.columns, S.rows, $("scale").checked, selected]);
  if (editing || sig === lastSig) return;
  lastSig = sig;
  $("empty").hidden = S.rows.length > 0;
  $("table").hidden = S.rows.length === 0;
  const all = S.rows.flatMap((r) => Object.values(r.cells)).filter((v) => v != null && v > 0);
  const lo = Math.min(...all), hi = Math.max(...all), heat = $("scale").checked;
  const head = el("tr", {}, el("th", {}, "Date"),
    S.columns.map((k) => { const [a, ...b] = label(k).split(/ (.+)/); return el("th", {}, a, b.length ? el("br") : null, b[0] || ""); }),
    el("th", {}, "Noted"));
  const rows = S.rows.map((r) => el("tr", { class: "row-d" + (r.date === selected ? " sel" : ""), onclick: () => { selected = r.date; renderTable(); renderRace(); } },
    el("td", {}, r.date),
    S.columns.map((k) => {
      const v = r.cells[k], best = k === r.best;
      return el("td", { class: best ? "best" : v == null ? "na" : "", style: !best && heat ? heatStyle(v, lo, hi) : null }, fmtMs(v));
    }),
    noteCell(r)));
  $("table").replaceChildren(el("thead", {}, head), el("tbody", {}, rows));
}

function noteCell(r) {
  const td = el("td", { class: "note", title: "Bấm để sửa ghi chú" }, r.note);
  td.addEventListener("click", (ev) => {
    ev.stopPropagation(); if (editing) return; editing = true;
    const inp = el("input", { type: "text", value: r.note, maxlength: 200 });
    const done = async (save) => {
      if (!editing) return; editing = false;
      if (save && inp.value !== r.note) { try { await api("/api/note", { date: r.date, note: inp.value }); } catch (e) {} }
      lastSig = ""; poll();
    };
    inp.addEventListener("keydown", (e) => { if (e.key === "Enter") done(true); if (e.key === "Escape") done(false); });
    inp.addEventListener("blur", () => done(true));
    td.replaceChildren(inp); inp.focus();
  });
  return td;
}

function renderRace() {
  const r = S.rows.find((x) => x.date === selected) || S.rows[S.rows.length - 1];
  if (!r) { $("race").replaceChildren(); return; }
  $("race-sub").textContent = `${r.date} — gap so với message tới đầu tiên (ms)${selected ? "" : " · đang hiển thị ngày mới nhất"}`;
  const max = Math.max(...r.race.map((x) => x.gap_ms), 0.001);
  $("race").replaceChildren(...r.race.map((x, i) => el("div", { class: "rrow", title: `${x.flow} · gói #${x.packet_no} · ${x.count} message` },
    el("div", {}, el("strong", {}, `${i + 1}. ${x.key}`)),
    el("div", { class: "bar2" }, el("i", { style: `width:${(x.gap_ms / max) * 100}%` })),
    el("div", { class: "v" }, i === 0 ? "đầu tiên" : `+${fmtMs(x.gap_ms)}`, el("small", {}, x.delay_ms == null ? "" : `delay ${fmtMs(x.delay_ms)}`)))));
}

function renderFeed() {
  const head = el("tr", {}, ["Giờ", "Message", "Delay (ms)", "Flow"].map((h) => el("th", {}, h)));
  const rows = S.events.map((e) => el("tr", {}, el("td", {}, `${e.date.slice(5)} ${e.time}`), el("td", {}, e.key),
    el("td", {}, fmtMs(e.delay_ms)), el("td", { style: "text-align:left;color:var(--muted);font-size:12px" }, e.flow)));
  $("feed").replaceChildren(el("thead", {}, head), el("tbody", {}, rows));
}

function render() { renderHeader(); renderSource(); renderTable(); renderRace(); renderFeed(); }

// ---------------------------------------------------------------- polling
async function poll() {
  if (document.hidden) return;
  try { S = await (await fetch("/api/state")).json(); render(); } catch (e) { $("pill").textContent = "Mất kết nối"; }
}
setInterval(poll, 1000);
document.addEventListener("visibilitychange", poll);

// ---------------------------------------------------------------- actions
function pickTab(name) {
  for (const t of ["import", "capture"]) {
    $("tab-" + t).setAttribute("aria-selected", t === name);
    $("pane-" + t).hidden = t !== name;
  }
}
$("tab-import").onclick = () => pickTab("import");
$("tab-capture").onclick = () => pickTab("capture");

function upload(f) {
  if (!f) return;
  const pr = $("progress"); pr.hidden = false; $("bar").className = "bar";
  const x = new XMLHttpRequest();
  x.open("POST", "/api/import?name=" + encodeURIComponent(f.name));
  x.setRequestHeader("X-PA-Request", "1");
  x.upload.onprogress = (e) => { if (e.lengthComputable) { $("bar").style.width = (100 * e.loaded / e.total) + "%"; $("ptext").textContent = `Tải lên ${f.name}: ${Math.round(100 * e.loaded / e.total)}%`; } };
  x.onload = () => { let j = {}; try { j = JSON.parse(x.responseText); } catch (e) {} if (x.status >= 400 || j.error) toast(j.error || `Lỗi ${x.status}`, true); poll(); };
  x.onerror = () => toast("Tải lên thất bại", true);
  x.send(f);
}
const drop = $("drop");
drop.onclick = () => $("file").click();
drop.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file").click(); } };
$("file").onchange = (e) => { upload(e.target.files[0]); e.target.value = ""; };
["dragenter", "dragover"].forEach((n) => drop.addEventListener(n, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((n) => drop.addEventListener(n, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => upload(e.dataTransfer.files[0]));

$("btn-path").onclick = async () => { const p = $("path").value.trim(); if (p) { await api("/api/import-path", { path: p }); poll(); } };
$("path").onkeydown = (e) => { if (e.key === "Enter") $("btn-path").click(); };
$("btn-start").onclick = async () => { await api("/api/capture/start", { iface: $("iface").value, backend: $("backend").value, bpf: $("bpf").value }); poll(); };
$("btn-stop").onclick = async () => { await api("/api/capture/stop", {}); poll(); };
$("btn-reset").onclick = async () => { if (confirm("Xoá toàn bộ kết quả hiện tại? (file pcap đã lưu không bị xoá)")) { selected = null; lastSig = ""; await api("/api/reset", {}); poll(); } };
$("btn-csv").onclick = () => download("/api/export.csv", "latency_heatmap.csv");
$("btn-xlsx").onclick = () => download("/api/export.xlsx", "latency_heatmap.xlsx");

$("scale").checked = localStorage.getItem("pa.scale") !== "0";
$("scale").onchange = () => { localStorage.setItem("pa.scale", $("scale").checked ? "1" : "0"); if (S) renderTable(); };
poll();
