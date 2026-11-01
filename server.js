const express = require("express");
const net = require("node:net");
const crypto = require("node:crypto");
const fs = require("node:fs");

const app = express();

const PORT = process.env.PORT || 3000;
const USER = process.env.OWNER_USER || "owner";
const PASS = process.env.OWNER_PASS;
const DATA_FILE = process.env.DATA_FILE || "./visits.json"; // ephemeral on Render free tier
const MAX_VISITS = 500;
const DEDUPE_MS = 10 * 60 * 1000;

if (!PASS) throw new Error("Please set OWNER_PASS in Render Environment Variables.");

app.set("trust proxy", 1);
app.disable("x-powered-by");

// ---------- helpers ----------
const sha = v => crypto.createHash("sha256").update(String(v)).digest();
const USER_H = sha(USER), PASS_H = sha(PASS);

const rateBuckets = new Map();
function hit(key, limit, windowMs) {
  const now = Date.now();
  const arr = (rateBuckets.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now);
  rateBuckets.set(key, arr);
  return arr.length > limit;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of rateBuckets) {
    if (!arr.some(t => now - t < 15 * 60 * 1000)) rateBuckets.delete(k);
  }
}, 60_000).unref();

function secure(req, res, next) {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.locals.nonce = nonce;
  res.set({
    "Content-Security-Policy":
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; ` +
      "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
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
  if (hit("fail:" + ip, 10, 15 * 60 * 1000) && rateBuckets.get("fail:" + ip).length > 10) {
    return res.status(429).send("Too many attempts. Try later.");
  }
  const header = req.headers.authorization || "";
  let ok = false;
  if (header.startsWith("Basic ")) {
    const cred = Buffer.from(header.slice(6), "base64").toString();
    const i = cred.indexOf(":");
    if (i !== -1) {
      const u = crypto.timingSafeEqual(sha(cred.slice(0, i)), USER_H);
      const p = crypto.timingSafeEqual(sha(cred.slice(i + 1)), PASS_H);
      ok = u && p;
    }
  }
  if (!ok) {
    res.set("WWW-Authenticate", 'Basic realm="Owner"');
    return res.status(401).send("Login required");
  }
  // successful login: forgive earlier failures
  rateBuckets.delete("fail:" + ip);
  next();
}

// ---------- storage ----------
let visits = [];
try { visits = JSON.parse(fs.readFileSync(DATA_FILE, "utf8")).slice(0, MAX_VISITS); } catch {}
let saveTimer;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(DATA_FILE, JSON.stringify(visits), err => {
      if (err) console.error("Save failed:", err.message);
    });
  }, 500);
}

// ---------- geolocation (cached, two providers) ----------
const geoCache = new Map();
const unknown = { city: "Unknown", country: "Unknown", cc: "" };

function isPrivate(ip) {
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(ip);
}

async function getLocation(ip) {
  if (!ip) return unknown;
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  if (!net.isIP(ip) || isPrivate(ip)) return unknown;

  const cached = geoCache.get(ip);
  if (cached && Date.now() - cached.t < 24 * 3600 * 1000) return cached.v;

  const providers = [
    async () => {
      const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(6000) });
      const d = await r.json();
      if (!d.success) throw new Error("ipwho.is failed");
      return { city: d.city, country: d.country, cc: d.country_code };
    },
    async () => {
      const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, { signal: AbortSignal.timeout(6000) });
      const d = await r.json();
      if (d.error) throw new Error("ipapi failed");
      return { city: d.city, country: d.country_name, cc: d.country_code };
    }
  ];

  for (const p of providers) {
    try {
      const d = await p();
      if (d.city || d.country) {
        const v = {
          city: d.city || "Unknown",
          country: d.country || "Unknown",
          cc: /^[A-Za-z]{2}$/.test(d.cc || "") ? d.cc.toUpperCase() : ""
        };
        geoCache.set(ip, { v, t: Date.now() });
        if (geoCache.size > 2000) geoCache.delete(geoCache.keys().next().value);
        return v;
      }
    } catch (e) {
      console.error("Geo provider error:", e.message);
    }
  }
  return unknown;
}

// ---------- landing page ----------
app.get("/", (req, res) => {
  const n = res.locals.nonce;
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#050505">
<meta name="robots" content="noindex">
<title>oh hi...</title>
<style nonce="${n}">
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:#050505;color:#fff;font-family:ui-monospace,Menlo,Consolas,monospace;display:flex;align-items:center;justify-content:center;overflow:hidden}
canvas{position:fixed;inset:0;width:100%;height:100%;z-index:0}
main{position:relative;z-index:2;width:90%;max-width:540px;text-align:center;animation:appear 1.2s ease}
@keyframes appear{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
.tag{color:#666;font-size:11px;letter-spacing:5px;margin-bottom:28px}
h1{font-size:clamp(52px,13vw,92px);letter-spacing:5px;margin:0;position:relative;text-shadow:0 0 25px #ffffff55}
h1::before,h1::after{content:attr(data-t);position:absolute;inset:0;opacity:.6}
h1::before{color:#0ff;animation:g1 3.5s infinite steps(1);clip-path:inset(0 0 60% 0)}
h1::after{color:#f0f;animation:g2 3.5s infinite steps(1);clip-path:inset(60% 0 0 0)}
@keyframes g1{0%,92%{transform:none}93%{transform:translate(-4px,1px)}96%{transform:translate(3px,-1px)}100%{transform:none}}
@keyframes g2{0%,90%{transform:none}91%{transform:translate(4px,-1px)}95%{transform:translate(-3px,1px)}100%{transform:none}}
.subtitle{color:#888;font-size:13px;line-height:2;margin:24px 0 34px;min-height:56px}
.cursor::after{content:"▌";animation:blink 1s infinite}
@keyframes blink{50%{opacity:0}}
button{background:#fff;color:#000;border:0;padding:17px 40px;font:inherit;font-size:13px;letter-spacing:2px;cursor:pointer;transition:.25s}
button:hover:not(:disabled){background:#ccc;transform:scale(1.05);box-shadow:0 0 30px #ffffff33}
button:disabled{opacity:.5;cursor:wait}
.notice{color:#555;font-size:10.5px;margin-top:26px;line-height:1.8}
#status{color:#aaa;font-size:12px;margin-top:20px;min-height:18px}
.hidden{display:none}
#reveal h2{font-size:clamp(26px,7vw,38px);letter-spacing:3px;margin:0}
.bar{height:2px;background:#222;margin:22px auto 0;width:200px;overflow:hidden}
.bar i{display:block;height:100%;width:0;background:#fff;animation:fill 1.4s ease forwards}
@keyframes fill{to{width:100%}}
@media (prefers-reduced-motion:reduce){*{animation:none!important}}
</style>
</head>
<body>
<canvas id="bg"></canvas>
<main>
  <section id="intro">
    <div class="tag">A LITTLE SOMETHING FOR YOU</div>
    <h1 data-t="oh hi...">oh hi...</h1>
    <p class="subtitle cursor" id="type"></p>
    <button id="go">TELL ME MORE →</button>
    <p class="notice">
      By clicking, you consent to this site recording your IP address,
      approximate city/country and the time of your visit.
      Nothing is recorded if you just close this page.
    </p>
    <p id="status" role="status"></p>
  </section>

  <section id="reveal" class="hidden">
    <div class="tag">YOU MADE IT</div>
    <h2 id="rt">Well, hello there.</h2>
    <p class="subtitle" id="rs">Nothing to see here...<br>Or maybe there is.</p>
    <div class="bar"><i></i></div>
  </section>
</main>

<script nonce="${n}">
// particles
(function(){
  const c=document.getElementById("bg"),x=c.getContext("2d");
  let w,h,p=[];
  function size(){w=c.width=innerWidth;h=c.height=innerHeight;p=Array.from({length:Math.min(70,w/14|0)},()=>({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*.3,vy:(Math.random()-.5)*.3}))}
  addEventListener("resize",size);size();
  (function f(){
    x.clearRect(0,0,w,h);
    for(const a of p){
      a.x+=a.vx;a.y+=a.vy;
      if(a.x<0||a.x>w)a.vx*=-1;if(a.y<0||a.y>h)a.vy*=-1;
      x.fillStyle="rgba(255,255,255,.35)";x.fillRect(a.x,a.y,1.5,1.5);
      for(const b of p){const d=Math.hypot(a.x-b.x,a.y-b.y);if(d<110){x.strokeStyle="rgba(255,255,255,"+(.08*(1-d/110))+")";x.beginPath();x.moveTo(a.x,a.y);x.lineTo(b.x,b.y);x.stroke()}}
    }
    requestAnimationFrame(f);
  })();
})();

// typewriter
(function(){
  const el=document.getElementById("type"),t="You found this place. Now there's only one thing left to do.";
  let i=0;
  (function s(){el.textContent=t.slice(0,++i);if(i<t.length)setTimeout(s,35);else el.classList.remove("cursor")})();
})();

// click -> consented visit
const btn=document.getElementById("go"),st=document.getElementById("status");
btn.addEventListener("click",async()=>{
  btn.disabled=true;st.textContent="One second...";
  try{
    const r=await fetch("/visit",{method:"POST"});
    const d=await r.json();
    if(!r.ok||!d.success)throw new Error();
    document.getElementById("intro").classList.add("hidden");
    document.getElementById("reveal").classList.remove("hidden");
    document.title="hello.";
  }catch{
    st.textContent="Something went wrong. Try again.";
    btn.disabled=false;
  }
});
</script>
</body>
</html>`);
});

// ---------- visit tracking (consented click only) ----------
app.post("/visit", async (req, res) => {
  try {
    const ip = req.ip || "";
    if (hit("visit:" + ip, 6, 60_000)) return res.status(429).json({ success: false });

    const now = Date.now();
    const existing = visits.find(v => v.ip === ip && now - Date.parse(v.time) < DEDUPE_MS);
    if (existing) {
      existing.hits = (existing.hits || 1) + 1;
      existing.time = new Date().toISOString();
    } else {
      const loc = await getLocation(ip);
      visits.unshift({ ip, city: loc.city, country: loc.country, cc: loc.cc, time: new Date().toISOString(), hits: 1 });
      visits.splice(MAX_VISITS);
      console.log("New consented visit:", loc.city, loc.country);
    }
    save();
    res.json({ success: true });
  } catch (e) {
    console.error("Visit error:", e.message);
    res.status(500).json({ success: false });
  }
});

// ---------- owner ----------
app.get("/owner/data.json", auth, (req, res) => res.json(visits));

app.get("/owner/export.csv", auth, (req, res) => {
  const esc = v => {
    let s = String(v ?? "");
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const rows = [["ip", "city", "country", "time", "hits"], ...visits.map(v => [v.ip, v.city, v.country, v.time, v.hits || 1])];
  res.type("text/csv").set("Content-Disposition", 'attachment; filename="visits.csv"')
    .send(rows.map(r => r.map(esc).join(",")).join("\n"));
});

// custom header forces a CORS preflight, so other sites can't trigger this
app.post("/owner/clear", auth, (req, res) => {
  if (req.get("x-owner-action") !== "clear") return res.status(400).json({ success: false });
  visits = [];
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
<title>Owner Dashboard</title>
<style nonce="${n}">
*{box-sizing:border-box}
body{background:#050505;color:#fff;font-family:ui-monospace,Menlo,Consolas,monospace;margin:0;padding:24px}
h1{letter-spacing:3px;margin:0 0 6px}
.sub{color:#666;font-size:12px;margin-bottom:22px}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.card{border:1px solid #222;padding:14px 20px;min-width:130px}
.card b{display:block;font-size:26px;margin-top:4px}
.card span{color:#777;font-size:11px;letter-spacing:2px}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
input,button,a.btn{background:#111;color:#fff;border:1px solid #2a2a2a;padding:10px 14px;font:inherit;font-size:12px;text-decoration:none;cursor:pointer}
input{flex:1;min-width:180px;cursor:text}
button:hover,a.btn:hover{background:#1c1c1c}
.danger{color:#f66}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:620px}
th,td{padding:13px;border-bottom:1px solid #1c1c1c;text-align:left;font-size:13px}
th{color:#888;font-size:11px;letter-spacing:2px}
tr:hover td{background:#0c0c0c}
.dim{color:#666}
</style>
</head>
<body>
<h1>oh hi, owner.</h1>
<div class="sub">auto-refreshes every 15s · <span id="upd">…</span></div>

<div class="stats">
  <div class="card"><span>VISITS</span><b id="s1">0</b></div>
  <div class="card"><span>UNIQUE IPS</span><b id="s2">0</b></div>
  <div class="card"><span>COUNTRIES</span><b id="s3">0</b></div>
  <div class="card"><span>LAST 24H</span><b id="s4">0</b></div>
</div>

<div class="tools">
  <input id="q" placeholder="filter by IP, city, country…">
  <a class="btn" href="/owner/export.csv">EXPORT CSV</a>
  <button id="clr" class="danger">CLEAR ALL</button>
</div>

<div class="wrap">
<table>
<thead><tr><th>IP ADDRESS</th><th>CITY</th><th>COUNTRY</th><th>TIME</th><th>CLICKS</th></tr></thead>
<tbody id="tb"><tr><td colspan="5" class="dim">Loading…</td></tr></tbody>
</table>
</div>

<script nonce="${n}">
let data=[];
const $=id=>document.getElementById(id);
const flag=cc=>cc&&cc.length===2?String.fromCodePoint(...[...cc.toUpperCase()].map(c=>127397+c.charCodeAt(0)))+" ":"";
function ago(t){const s=(Date.now()-Date.parse(t))/1000;
  if(s<60)return"just now";if(s<3600)return(s/60|0)+"m ago";if(s<86400)return(s/3600|0)+"h ago";return(s/86400|0)+"d ago"}

function render(){
  const q=$("q").value.trim().toLowerCase();
  const rows=data.filter(v=>!q||[v.ip,v.city,v.country].join(" ").toLowerCase().includes(q));
  $("s1").textContent=data.length;
  $("s2").textContent=new Set(data.map(v=>v.ip)).size;
  $("s3").textContent=new Set(data.map(v=>v.country).filter(c=>c!=="Unknown")).size;
  $("s4").textContent=data.filter(v=>Date.now()-Date.parse(v.time)<864e5).length;
  const tb=$("tb");tb.textContent="";
  if(!rows.length){const tr=tb.insertRow(),td=tr.insertCell();td.colSpan=5;td.className="dim";td.textContent="No visits yet.";return}
  for(const v of rows){
    const tr=tb.insertRow();
    tr.insertCell().textContent=v.ip;
    tr.insertCell().textContent=v.city;
    tr.insertCell().textContent=flag(v.cc)+v.country;
    const t=tr.insertCell();t.textContent=new Date(v.time).toLocaleString()+" ";
    const s=document.createElement("span");s.className="dim";s.textContent="("+ago(v.time)+")";t.append(s);
    tr.insertCell().textContent=v.hits||1;
  }
}
async function load(){
  try{
    const r=await fetch("/owner/data.json");
    if(!r.ok)throw 0;
    data=await r.json();render();
    $("upd").textContent="updated "+new Date().toLocaleTimeString();
  }catch{$("upd").textContent="refresh failed"}
}
$("q").addEventListener("input",render);
$("clr").addEventListener("click",async()=>{
  if(!confirm("Delete all recorded visits?"))return;
  await fetch("/owner/clear",{method:"POST",headers:{"X-Owner-Action":"clear"}});
  load();
});
load();setInterval(load,15000);
</script>
</body>
</html>`);
});

app.get("/healthz", (req, res) => res.type("text").send("ok"));

app.use((req, res) => res.status(404).send("Not found"));
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).send("Internal server error");
});

app.listen(PORT, "0.0.0.0", () => console.log("oh hi server running on port " + PORT));
