
const express = require("express");
const net = require("node:net");

const app = express();

const PORT = process.env.PORT || 3000;
const USER = process.env.OWNER_USER || "owner";
const PASS = process.env.OWNER_PASS;

if (!PASS) {
  throw new Error("Please set OWNER_PASS in Render Environment Variables.");
}

// Render reverse proxy configuration
app.set("trust proxy", 1);

const visits = [];
const MAX_VISITS = 100;

function safe(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Basic ")) {
    res.set("WWW-Authenticate", 'Basic realm="Owner"');
    return res.status(401).send("Login required");
  }

  let credentials;

  try {
    credentials = Buffer.from(header.slice(6), "base64").toString();
  } catch {
    return res.status(401).send("Invalid login");
  }

  const i = credentials.indexOf(":");

  if (
    i === -1 ||
    credentials.slice(0, i) !== USER ||
    credentials.slice(i + 1) !== PASS
  ) {
    res.set("WWW-Authenticate", 'Basic realm="Owner"');
    return res.status(401).send("Wrong username or password");
  }

  next();
}

// Get visitor location using two providers
async function getLocation(ip) {
  const unknown = {
    city: "Unknown",
    country: "Unknown"
  };

  if (!ip) return unknown;

  // Normalize IPv4-mapped IPv6
  if (ip.startsWith("::ffff:")) {
    ip = ip.substring(7);
  }

  if (!net.isIP(ip)) {
    console.error("Invalid visitor IP");
    return unknown;
  }

  // First provider
  try {
    const response = await fetch(
      `https://ipwho.is/${encodeURIComponent(ip)}`,
      { signal: AbortSignal.timeout(7000) }
    );

    if (response.ok) {
      const data = await response.json();

      if (data.success && (data.city || data.country)) {
        return {
          city: data.city || "Unknown",
          country: data.country || "Unknown"
        };
      }
    }
  } catch (err) {
    console.error("Primary location provider failed:", err.message);
  }

  // Backup provider
  try {
    const response = await fetch(
      `https://ipapi.co/${encodeURIComponent(ip)}/json/`,
      { signal: AbortSignal.timeout(7000) }
    );

    if (response.ok) {
      const data = await response.json();

      if (!data.error) {
        return {
          city: data.city || "Unknown",
          country: data.country_name || "Unknown"
        };
      }
    }
  } catch (err) {
    console.error("Backup location provider failed:", err.message);
  }

  console.error("Both location providers failed.");
  return unknown;
}

// LANDING PAGE
app.get("/", (req, res) => {
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#050505">

<title>oh hi...</title>

<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  background: #050505;
  color: white;
  font-family: monospace;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
}

body::before {
  content: "";
  position: fixed;
  width: 350px;
  height: 350px;
  background: #ffffff;
  opacity: .045;
  filter: blur(120px);
  border-radius: 50%;
  animation: glow 5s infinite alternate;
}

@keyframes glow {
  from { transform: scale(.7); }
  to { transform: scale(1.5); }
}

main {
  position: relative;
  z-index: 2;
  width: 90%;
  max-width: 520px;
  text-align: center;
  animation: appear 1.2s ease;
}

@keyframes appear {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.tag {
  color: #666;
  font-size: 11px;
  letter-spacing: 5px;
  margin-bottom: 30px;
}

h1 {
  font-size: clamp(55px, 12vw, 85px);
  letter-spacing: 5px;
  margin: 0;
  text-shadow: 0 0 25px #ffffff55;
}

.subtitle {
  color: #777;
  font-size: 13px;
  line-height: 2;
  margin: 25px 0 35px;
}

button {
  background: white;
  color: black;
  border: none;
  padding: 17px 40px;
  font-family: monospace;
  font-size: 13px;
  letter-spacing: 2px;
  cursor: pointer;
  transition: .3s;
}

button:hover {
  background: #ccc;
  transform: scale(1.05);
  box-shadow: 0 0 30px #ffffff33;
}

button:disabled {
  opacity: .5;
  cursor: wait;
}

.notice {
  color: #444;
  font-size: 10px;
  margin-top: 28px;
  line-height: 1.8;
}

#status {
  color: #aaa;
  font-size: 12px;
  margin-top: 25px;
}

.hidden {
  display: none;
}

#reveal {
  animation: appear 1s ease;
}

#reveal h2 {
  font-size: 32px;
  letter-spacing: 3px;
}

</style>
</head>

<body>

<main>

  <section id="intro">
    <div class="tag">A LITTLE SOMETHING FOR YOU</div>

    <h1>oh hi...</h1>

    <p class="subtitle">
      You found this place.<br>
      Now there's only one thing left to do.
    </p>

    <button id="go">TELL ME MORE →</button>

    <p class="notice">
      By continuing, you agree to optional visitor analytics.
      Your IP address and approximate city/country are recorded
      only after you consent.
    </p>

    <p id="status"></p>
  </section>

  <section id="reveal" class="hidden">
    <div class="tag">YOU MADE IT</div>

    <h2>Well, hello there.</h2>

    <p class="subtitle">
      Nothing to see here...<br>
      Or maybe there is.
    </p>
  </section>

</main>

<script>
const button = document.getElementById("go");
const status = document.getElementById("status");

button.addEventListener("click", async () => {
  button.disabled = true;
  status.textContent = "One second...";

  try {
    const response = await fetch("/visit", {
      method: "POST"
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error("Could not record visit");
    }

    document.getElementById("intro").classList.add("hidden");
    document.getElementById("reveal").classList.remove("hidden");

  } catch (error) {
    status.textContent = "Something went wrong. Try again.";
    button.disabled = false;
  }
});
</script>

</body>
</html>`);
});

// VISIT TRACKING
app.post("/visit", async (req, res) => {
  try {
    const ip = req.ip || "";

    const location = await getLocation(ip);

    visits.unshift({
      ip,
      city: location.city,
      country: location.country,
      time: new Date().toISOString()
    });

    visits.splice(MAX_VISITS);

    console.log("New consented visit recorded:", {
      city: location.city,
      country: location.country
    });

    res.json({ success: true });

  } catch (error) {
    console.error("Visit error:", error.message);
    res.status(500).json({ success: false });
  }
});

// OWNER DASHBOARD
app.get("/owner", auth, (req, res) => {
  const rows = visits.map(v => `
    <tr>
      <td>${safe(v.ip)}</td>
      <td>${safe(v.city)}</td>
      <td>${safe(v.country)}</td>
      <td>${safe(new Date(v.time).toLocaleString())}</td>
    </tr>
  `).join("");

  res.type("html").send(`
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Owner Dashboard</title>

<style>
body {
  background: #050505;
  color: white;
  font-family: monospace;
  padding: 25px;
}

h1 {
  letter-spacing: 3px;
}

.stat {
  color: #aaa;
  margin: 25px 0;
}

table {
  width: 100%;
  border-collapse: collapse;
  min-width: 550px;
}

th, td {
  padding: 14px;
  border-bottom: 1px solid #222;
  text-align: left;
}

th {
  color: #888;
}

.wrapper {
  overflow-x: auto;
}
</style>
</head>

<body>

<h1>oh hi, owner.</h1>

<div class="stat">
  Total recorded visits: ${visits.length}
</div>

<div class="wrapper">
<table>
<thead>
<tr>
  <th>IP ADDRESS</th>
  <th>CITY</th>
  <th>COUNTRY</th>
  <th>TIME</th>
</tr>
</thead>

<tbody>
${rows || '<tr><td colspan="4">No visits yet.</td></tr>'}
</tbody>
</table>
</div>

</body>
</html>
`);
});

// 404
app.use((req, res) => {
  res.status(404).send("Not found");
});

// ERROR HANDLER
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).send("Internal server error");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("oh hi server running on port " + PORT);
});
