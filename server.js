
const express = require("express");
const net = require("node:net");

const app = express();

const PORT = process.env.PORT || 3000;
const USER = process.env.OWNER_USER || "owner";
const PASS = process.env.OWNER_PASS;

if (!PASS) {
  throw new Error("Missing OWNER_PASS environment variable in Render.");
}

// Render runs behind a reverse proxy.
app.set("trust proxy", 1);

const visits = [];
const MAX_VISITS = 100;

function safe(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
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
    credentials = Buffer.from(header.slice(6), "base64").toString("utf8");
  } catch {
    return res.status(401).send("Invalid login");
  }

  const separator = credentials.indexOf(":");

  if (
    separator === -1 ||
    credentials.slice(0, separator) !== USER ||
    credentials.slice(separator + 1) !== PASS
  ) {
    res.set("WWW-Authenticate", 'Basic realm="Owner"');
    return res.status(401).send("Invalid login");
  }

  next();
}

async function getLocation(ip) {
  const unknown = {
    city: "Unknown",
    country: "Unknown"
  };

  if (!ip || !net.isIP(ip)) {
    return unknown;
  }

  try {
    const response = await fetch(
      `https://ipapi.co/${encodeURIComponent(ip)}/json/`,
      {
        signal: AbortSignal.timeout(5000),
        headers: {
          "User-Agent": "oh-hi-analytics/1.0"
        }
      }
    );

    if (!response.ok) return unknown;

    const geo = await response.json();

    if (geo.error) return unknown;

    return {
      city: geo.city || "Unknown",
      country: geo.country_name || "Unknown"
    };
  } catch (error) {
    console.error("Location lookup failed:", error.message);
    return unknown;
  }
}

// Homepage
app.get("/", (req, res) => {
  res.type("html").send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>oh hi...</title>

  <style>
    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: #000;
      color: white;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: monospace;
      text-align: center;
    }

    h1 {
      font-size: clamp(42px, 10vw, 65px);
      letter-spacing: 5px;
      text-shadow: 0 0 20px white;
    }

    p { color: #555; }

    button {
      background: #111;
      color: white;
      border: 1px solid #444;
      padding: 12px 25px;
      cursor: pointer;
      font-family: monospace;
    }

    button:hover { background: #222; }

    button:disabled {
      opacity: .5;
      cursor: wait;
    }
  </style>
</head>

<body>
  <main>
    <h1>oh hi...</h1>

    <p>
      Visitor analytics are collected only with your consent.
    </p>

    <button id="go">Continue</button>
    <p id="status" role="status"></p>
  </main>

  <script>
    const button = document.getElementById("go");
    const status = document.getElementById("status");

    button.addEventListener("click", async () => {
      button.disabled = true;
      status.textContent = "Loading...";

      try {
        const response = await fetch("/visit", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          }
        });

        if (!response.ok) {
          throw new Error("Request failed");
        }

        const data = await response.json();

        if (!data.success) {
          throw new Error("Visit could not be recorded");
        }

        status.textContent = "Welcome.";
        button.remove();

      } catch (error) {
        status.textContent = "Something went wrong. Try again.";
        button.disabled = false;
      }
    });
  </script>
</body>
</html>
  `);
});

// Record visit after consent
app.post("/visit", async (req, res) => {
  try {
    const ip = req.ip || "unknown";
    const location = await getLocation(ip);

    visits.unshift({
      ip,
      city: location.city,
      country: location.country,
      time: new Date().toISOString()
    });

    visits.splice(MAX_VISITS);

    return res.json({ success: true });

  } catch (error) {
    console.error("Visit recording error:", error);

    return res.status(500).json({
      success: false
    });
  }
});

// Owner dashboard
app.get("/owner", auth, (req, res) => {
  const rows = visits.map((visit) => `
    <tr>
      <td>${safe(visit.ip)}</td>
      <td>${safe(visit.city)}</td>
      <td>${safe(visit.country)}</td>
      <td>${safe(new Date(visit.time).toLocaleString())}</td>
    </tr>
  `).join("");

  res.type("html").send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Owner</title>

  <style>
    body {
      background: #050505;
      color: white;
      font-family: monospace;
      padding: 25px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
    }

    td, th {
      padding: 12px;
      border-bottom: 1px solid #333;
      text-align: left;
    }

    .table-container {
      overflow-x: auto;
    }
  </style>
</head>

<body>
  <h1>oh hi, owner.</h1>

  <p>Visits: ${visits.length}</p>

  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>IP</th>
          <th>City</th>
          <th>Country</th>
          <th>Time</th>
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

// Handle unknown routes
app.use((req, res) => {
  res.status(404).send("Not found");
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).send("Internal server error");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Website started on port ${PORT}`);
});
