// Giao diện: theme, thanh đo, tab, biểu đồ SVG thuần (CSP chỉ cho phép script cùng nguồn).
"use strict";
const NS = "http://www.w3.org/2000/svg";

function el(tag, attrs, parent) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (parent) parent.appendChild(e);
  return e;
}
function readJSON(id) {
  const n = document.getElementById(id);
  return n ? JSON.parse(n.textContent) : null;
}
function svg(box, w, h) { return el("svg", { viewBox: `0 0 ${w} ${h}`, role: "img" }, box); }
function niceMax(v) {
  if (v <= 5) return 5;
  const p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
  return (m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
}
function tip(g, text) { const t = el("title", {}, g); t.textContent = text; }

// Cột chồng theo ngày: luật (dưới) + ML (trên), có lưới ngang
function perDay(box, rows) {
  if (!rows || !rows.length) { box.textContent = "No data yet"; return; }
  const W = 640, H = rows.length < 6 ? 140 : 200, L = 34, B = 22, T = 8;
  const top = Math.max(...rows.map(r => (r.rule || 0) + (r.ml || 0)), 1);
  const max = top <= 4 ? 4 : niceMax(top), ticks = 4;
  const bw = (W - L) / rows.length, s = svg(box, W, H);
  for (let k = 0; k <= ticks; k++) {
    const y = T + (H - B - T) * (1 - k / ticks);
    el("line", { x1: L, x2: W, y1: y, y2: y, class: "gridline" }, s);
    const t = el("text", { x: L - 6, y: y + 3, "text-anchor": "end" }, s); t.textContent = Math.round(max * k / ticks);
  }
  rows.forEach((r, i) => {
    const w = Math.min(Math.max(bw * 0.7, 1), 28), x = L + i * bw + (bw - w) / 2;
    const hr = (r.rule || 0) / max * (H - B - T), hm = (r.ml || 0) / max * (H - B - T);
    const g = el("g", {}, s);
    tip(g, `${r.day}: ${r.rule || 0} rule detections, ${r.ml || 0} ML detections`);
    el("rect", { x, y: H - B - hr, width: w, height: hr, rx: 1.5, class: "bar-rule" }, g);
    el("rect", { x, y: H - B - hr - hm, width: w, height: hm, rx: 1.5, class: "bar-ml" }, g);
  });
  const step = Math.ceil(rows.length / 8);
  rows.forEach((r, i) => { if (i % step === 0) {
    const t = el("text", { x: L + i * bw + bw / 2, y: H - 6, "text-anchor": "middle" }, s);
    t.textContent = r.day.slice(5); } });
}

// Hoạt động theo giờ của thực thể
function hourly(box, obj) {
  const items = Object.entries(obj || {}).sort();
  if (!items.length) { box.textContent = "No raw events were kept for this entity"; return; }
  const W = 640, H = 120, B = 18, bw = W / items.length, max = Math.max(...items.map(x => x[1]));
  const s = svg(box, W, H);
  el("line", { x1: 0, x2: W, y1: H - B, y2: H - B, class: "gridline" }, s);
  items.forEach(([k, v], i) => {
    const h = v / max * (H - B - 6), g = el("g", {}, s);
    tip(g, `${k.slice(0, 16).replace("T", " ")} – ${v} events`);
    el("rect", { x: i * bw, y: H - B - h, width: Math.max(bw - 0.6, 0.6), height: h, rx: 1, class: "bar" }, g);
  });
  const a = el("text", { x: 0, y: H - 4 }, s); a.textContent = items[0][0].slice(0, 13).replace("T", " ") + "h";
  const b = el("text", { x: W, y: H - 4, "text-anchor": "end" }, s);
  b.textContent = items[items.length - 1][0].slice(0, 13).replace("T", " ") + "h";
  const c = el("text", { x: W / 2, y: H - 4, "text-anchor": "middle" }, s); c.textContent = "events per hour";
}

document.addEventListener("DOMContentLoaded", () => {
  // theme sáng / tối
  const tg = document.getElementById("theme-toggle");
  if (tg) tg.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("theme", next); } catch (e) { /* không lưu được – chỉ đổi tạm */ }
  });
  // độ dài thanh đo (CSP không cho style inline trong HTML → đặt qua CSSOM)
  document.querySelectorAll("[data-w]").forEach(i => {
    i.style.width = Math.max(0, Math.min(100, +i.dataset.w || 0)) + "%";
  });
  // tab
  document.querySelectorAll("[data-tabs]").forEach(tabs => {
    const name = tabs.dataset.tabs;
    tabs.querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
      tabs.querySelectorAll("button").forEach(x => x.classList.toggle("on", x === b));
      document.querySelectorAll(`[data-pane^="${name}-"]`).forEach(p => {
        p.hidden = p.dataset.pane !== `${name}-${b.dataset.for}`;
      });
    }));
  });
  // biểu đồ
  const dash = readJSON("dash-data");
  document.querySelectorAll("[data-chart]").forEach(box => {
    const kind = box.dataset.chart;
    if (kind === "perday" && dash) perDay(box, (dash.alerts_per_day || {})[box.dataset.ds]);
    if (kind === "perday-entity") perDay(box, readJSON("entity-days"));
    if (kind === "hourly") hourly(box, readJSON("hourly-data"));
  });
  // trang demo: tác vụ chạy nền – hỏi trạng thái mỗi 3 giây, xong thì tải lại trang
  const rpLog = document.getElementById("rp-log");
  if (rpLog && rpLog.dataset.running === "yes") {
    const timer = setInterval(async () => {
      const r = await fetch("/replay/status", { credentials: "same-origin" });
      if (!r.ok) return;
      const st = await r.json();
      rpLog.textContent = st.log.join("\n");
      if (!st.running) { clearInterval(timer); location.reload(); }
    }, 3000);
  }
});
