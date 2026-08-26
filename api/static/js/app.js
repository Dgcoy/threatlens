/* ThreatLens shared frontend helpers (no dependencies, zero outbound) */

async function api(path, opts = {}) {
  const resp = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (resp.status === 401) { location.href = "/login"; throw new Error("unauthorized"); }
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return resp.json();
}

function el(id) { return document.getElementById(id); }

function fmtTs(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return d.toISOString().slice(0, 19).replace("T", " ") + "Z";
}

function fmtAgo(ts) {
  if (!ts) return "—";
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function badgeForMatch(t) {
  const map = { src: ["src", "SRC"], dst: ["dst", "DST"], host: ["host", "HOST"] };
  const [cls, label] = map[t] || ["feed", t];
  return `<span class="badge ${cls}">${label}</span>`;
}

function openModal(html) {
  const bd = document.getElementById("modal");
  if (!bd) return;
  bd.innerHTML = `<div class="modal"><button class="close" onclick="closeModal()">✕</button>${html}</div>`;
  bd.classList.add("open");
}
function closeModal() { document.getElementById("modal")?.classList.remove("open"); }
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

async function logout() { await api("/api/logout"); location.href = "/login"; }

function activeNav() {
  const path = location.pathname;
  document.querySelectorAll("header nav a").forEach(a => {
    a.classList.toggle("active",
      a.getAttribute("href") === path || (a.getAttribute("href") !== "/" && path.startsWith(a.getAttribute("href"))));
  });
}
document.addEventListener("DOMContentLoaded", activeNav);

/* ===== live ingestion arena (Palo-Alto style) ===== */
const BUCKET_META = [
  ["Firewall · DROP",  "#f87171", "blocked"],
  ["Firewall · ACCEPT","#34d399", "allowed"],
  ["Firewall · Rule",  "#38bdf8", "rule hit"],
  ["IPS / DPIA",       "#c084fc", "inspection"],
  ["DNS",              "#22d3ee", "queries"],
  ["DHCP",             "#2dd4bf", "leases"],
  ["WLAN",             "#fbbf24", "assoc"],
  ["WAN",              "#fb923c", "uplink"],
  ["System",           "#94a3b8", "daemons"],
  ["Kernel",           "#64748b", "core"],
  ["Other",            "#475569", "misc"],
];

class LiveIngest {
  constructor(containerId, handlers = {}) {
    this.el = document.getElementById(containerId);
    this.onDetection = handlers.onDetection || (() => {});
    this.counts = {};
    this.rateSamples = [];
    this.activeParticles = 0;
    this.rendered = false;
    this.initArena();
    this.connect();
  }

  initArena() {
    this.el.innerHTML = `
      <div class="arena">
        <div class="arena-head">
          <span class="live-dot"></span>
          <h2>Live ingestion</h2>
          <span class="rate">stream rate <b id="rateVal">0</b> events/min</span>
        </div>
        <div class="stream-source"><span class="s-icon">🛰️</span><span class="s-label">UDM :514</span></div>
        <div class="buckets" id="buckets"></div>
        <div class="arena-flash" id="arenaFlash"></div>
      </div>
      <div class="ticker"><span class="t-label">ingest</span><div class="t-items" id="tickerItems"></div></div>`;
    const buckets = document.getElementById("buckets");
    BUCKET_META.forEach(([name, color, sub]) => {
      const card = document.createElement("div");
      card.className = "bucket";
      card.dataset.bucket = name;
      card.style.setProperty("--bc", color);
      card.innerHTML = `
        <div class="b-top"><span class="b-name" style="color:${color}">${esc(name)}</span></div>
        <div class="b-count">0</div>
        <div class="b-sub">${sub}</div>
        <div class="b-bar"><i style="background:${color}"></i></div>`;
      buckets.appendChild(card);
      this.counts[name] = 0;
    });
    this.rendered = true;
  }

  connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    let ws;
    const open = () => {
      ws = new WebSocket(`${proto}://${location.host}/ws/events`);
      ws.onmessage = e => {
        let m;
        try { m = JSON.parse(e.data); } catch (_) { return; }
        if (m.type === "snapshot") this.apply(m, true);
        else if (m.type === "update") this.apply(m, false);
      };
      ws.onclose = () => { setTimeout(open, 3000); };
      ws.onerror = () => { try { ws.close(); } catch (_) {} };
    };
    open();
    setInterval(() => { if (ws && ws.readyState === 1) ws.send("ping"); }, 20000);
  }

  apply(msg, isSnapshot) {
    if (msg.buckets) this.setCounts(msg.buckets, isSnapshot);
    if (msg.events) {
      for (const ev of msg.events) {
        this.pushEvent(ev, isSnapshot);
        this.rateSamples.push(Date.now());
      }
      this.pruneRate();
      const rateEl = document.getElementById("rateVal");
      if (rateEl) rateEl.textContent = this.eventsPerMin();
    }
    if (msg.detections && msg.detections.length) {
      this.onDetection(msg.detections);
      const flash = document.getElementById("arenaFlash");
      if (flash) { flash.classList.remove("on"); void flash.offsetWidth; flash.classList.add("on"); }
    }
  }

  setCounts(totals, isSnapshot) {
    for (const [name] of BUCKET_META) {
      const card = document.querySelector(`.bucket[data-bucket="${CSS.escape(name)}"]`);
      if (!card) continue;
      const n = totals[name] ?? 0;
      card.querySelector(".b-count").textContent = n.toLocaleString();
      const pct = totals._total ? Math.round((n / totals._total) * 100) : 0;
      card.querySelector(".b-bar i").style.width = pct + "%";
      if (!isSnapshot && n > (this.counts[name] || 0)) {
        card.classList.remove("pop"); void card.offsetWidth; card.classList.add("pop");
      }
      this.counts[name] = n;
    }
  }

  pushEvent(ev, quiet) {
    const bucket = ev.bucket || "Other";
    const meta = BUCKET_META.find(([n]) => n === bucket) || BUCKET_META[BUCKET_META.length - 1];
    const [, color] = meta;
    // ticker chip
    const items = document.getElementById("tickerItems");
    if (items && !quiet) {
      const chip = document.createElement("span");
      chip.className = "t-chip";
      const label = ev.src_ip || ev.hostname
        ? `${esc(ev.src_ip || ev.hostname || "")}${ev.dst_ip ? "→" + esc(ev.dst_ip) : ""}`
        : (ev.msg || "").slice(0, 34);
      chip.innerHTML = `<b style="color:${color}">${esc(bucket)}</b> ${label}`;
      items.prepend(chip);
      while (items.children.length > 7) items.lastChild.remove();
    }
    if (quiet) return;
    // particle flight (throttled)
    if (this.activeParticles < 14) this.flyParticle(bucket, color);
  }

  flyParticle(bucket, color) {
    const source = document.querySelector(".stream-source");
    const target = document.querySelector(`.bucket[data-bucket="${CSS.escape(bucket)}"]`);
    if (!source || !target) return;
    const s = source.getBoundingClientRect();
    const t = target.getBoundingClientRect();
    const dot = document.createElement("div");
    dot.className = "particle tail";
    dot.style.color = color;
    dot.style.left = (s.left + s.width / 2 - 5) + "px";
    dot.style.top = (s.top + s.height / 2 - 5) + "px";
    document.body.appendChild(dot);
    this.activeParticles++;
    const dx = t.left + t.width / 2 - (s.left + s.width / 2);
    const dy = t.top + t.height / 2 - (s.top + s.height / 2);
    requestAnimationFrame(() => requestAnimationFrame(() => {
      dot.style.transform = `translate(${dx}px, ${dy}px) scale(.45)`;
      dot.style.opacity = "0.35";
    }));
    setTimeout(() => { dot.remove(); this.activeParticles = Math.max(0, this.activeParticles - 1); }, 800);
  }

  pruneRate() {
    const cutoff = Date.now() - 60000;
    this.rateSamples = this.rateSamples.filter(t => t > cutoff);
  }
  eventsPerMin() {
    return this.rateSamples.length;
  }
}

function showDetectionToasts(dets) {
  dets.slice(0, 2).forEach(d => {
    const t = document.createElement("div");
    t.className = "toast";
    t.innerHTML = `<h4>⚠ Detection ${esc(d.match_type || "")}</h4>
      <div class="mono">${esc(d.matched_value)}</div>
      <div class="feed"><span class="badge feed">${esc(d.feed_name)}</span></div>`;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 7000);
  });
}
