
const express = require("express");
const app = express();

const visits = [];

const USER = process.env.OWNER_USER || "owner";
const PASS = process.env.OWNER_PASS;

if (!PASS) throw new Error("Set OWNER_PASS");

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const encoded = header.startsWith("Basic ")
    ? header.slice(6) : "";

  let credentials = "";
  try {
    credentials = Buffer.from(encoded, "base64").toString();
  } catch {}

  const i = credentials.indexOf(":");

  if (i < 0 || credentials.slice(0, i) !== USER ||
      credentials.slice(i + 1) !== PASS) {
    res.set("WWW-Authenticate", 'Basic realm="Owner"');
    return res.status(401).send("Login required");
  }
  next();
}

function safe(s) {
  return String(s || "").replace(/[&<>"']/g, c =>
    ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]
  );
}

app.get("/", (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html>
  <head>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>oh hi...</title>
    <style>
      body {
        margin:0;background:#000;color:white;height:100vh;
        display:flex;align-items:center;justify-content:center;
        font-family:monospace;text-align:center;
      }
      h1 {font-size:65px;letter-spacing:5px;text-shadow:0 0 20px white}
      p {color:#555}
      button {background:#111;color:white;border:1px solid #444;padding:12px}
    </style>
  </head>
  <body>
    <main>
      <h1>oh hi...</h1>
      <p>Visitor analytics are collected only with your consent.</p>
      <button id="go">Continue</button>
      <p id="status"></p>
    </main>
    <script>
      document.getElementById("go").onclick = async () => {
        const r = await fetch("/visit", {method:"POST"});
        document.getElementById("status").textContent =
          r.ok ? "Welcome." : "Something went wrong.";
        if (r.ok) document.getElementById("go").remove();
      };
    </script>
  </body>
  </html>`);
});

app.post("/visit", async (req, res) => {
  const ip = req.socket.remoteAddress || "unknown";
  try {
    const r = await fetch("https://ipapi.co/" +
      encodeURIComponent(ip) + "/json/");
    const geo = await r.json();

    visits.unshift({
      ip,
      city: geo.city || "Unknown",
      country: geo.country_name || "Unknown",
      time: new Date().toISOString()
    });

    visits.splice(100);
    res.json({success:true});
  } catch {
    res.status(503).json({success:false});
  }
});

app.get("/owner", auth, (req, res) => {
  const rows = visits.map(v => `
    <tr>
      <td>${safe(v.ip)}</td>
      <td>${safe(v.city)}</td>
      <td>${safe(v.country)}</td>
      <td>${safe(new Date(v.time).toLocaleString())}</td>
    </tr>
  `).join("");

  res.send(`
    <html><head><meta name="viewport" content="width=device-width">
    <title>Owner</title>
    <style>
      body{background:#050505;color:white;font-family:monospace;padding:25px}
      table{width:100%;border-collapse:collapse}
      td,th{padding:12px;border-bottom:1px solid #333;text-align:left}
    </style></head>
    <body>
      <h1>oh hi, owner.</h1>
      <p>Visits: ${visits.length}</p>
      <table>
        <tr><th>IP</th><th>City</th><th>Country</th><th>Time</th></tr>
        ${rows}
      </table>
    </body></html>
  `);
});

app.listen(process.env.PORT || 3000, () =>
  console.log("Website started")
);
