import express from "express";
import crypto from "crypto";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();

/* ================= CORS ================= */

app.use(cors({ origin: true }));
app.use(express.json());

/* ================= SUPABASE ================= */

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const LICENSE_SECRET = process.env.LICENSE_SECRET || "change_me";

/* ================= SERVER MEMORY ================= */

// 🔥 ALLT sparas per license
const servers = {}; 
// structure:
// {
//   license_key: {
//      online: true,
//      players: [],
//      version: "3.0.0",
//      started_at: timestamp,
//      last_seen: timestamp
//   }
// }

const serverLogs = {}; // per license

/* ================= ROOT ================= */

app.get("/", (req, res) => {
  res.send("GhostGuard Backend OK");
});

/* ================= LICENSE VERIFY ================= */

app.post("/api/license/verify", async (req, res) => {
  try {
    const { license_key, hwid } = req.body || {};
    if (!license_key)
      return res.status(400).json({ valid: false });

    const { data: lic } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", license_key)
      .single();

    if (!lic) return res.json({ valid: false });

    if (lic.status !== "ACTIVE")
      return res.json({ valid: false });

    if (lic.expires_at && new Date(lic.expires_at) < new Date())
      return res.json({ valid: false });

    const payload = JSON.stringify({
      license_key,
      status: lic.status,
      expires_at: lic.expires_at,
      issued_at: Date.now()
    });

    const signature = crypto
      .createHmac("sha256", LICENSE_SECRET)
      .update(payload)
      .digest("hex");

    return res.json({ valid: true, payload, signature });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ valid: false });
  }
});

/* ================= HEARTBEAT ================= */

app.post("/api/server/heartbeat", (req, res) => {
  const { license_key, players, version } = req.body;

  if (!license_key)
    return res.status(400).json({ success: false });

  if (!servers[license_key]) {
    servers[license_key] = {
      online: true,
      players: [],
      version: version || "3.0.0",
      started_at: Date.now(),
      last_seen: Date.now()
    };
  }

  const server = servers[license_key];

  server.online = true;
  server.players = players || [];
  server.version = version || server.version;
  server.last_seen = Date.now();

  return res.json({ success: true });
});

/* ================= SERVER STATUS ================= */

app.get("/api/server/status/:license", (req, res) => {
  const key = req.params.license;
  const server = servers[key];

  if (!server) {
    return res.json({ online: false });
  }

  const online = (Date.now() - server.last_seen) < 30000;

  const uptime = Math.floor(
    (Date.now() - server.started_at) / 1000
  );

  return res.json({
    online,
    players: server.players.length,
    version: server.version,
    uptime
  });
});

/* ================= SERVER PLAYERS ================= */

app.get("/api/server/players/:license", (req, res) => {
  const key = req.params.license;
  const server = servers[key];

  if (!server) {
    return res.json({ success: true, players: [] });
  }

  return res.json({
    success: true,
    players: server.players
  });
});

/* ================= SERVER LOGS ================= */

function pushLog(license_key, item) {
  serverLogs[license_key] = serverLogs[license_key] || [];
  serverLogs[license_key].unshift(item);
  if (serverLogs[license_key].length > 300)
    serverLogs[license_key].length = 300;
}

app.post("/api/server/log", (req, res) => {
  const { license_key, type, message } = req.body || {};
  if (!license_key || !message)
    return res.status(400).json({ success: false });

  pushLog(license_key, {
    time: new Date().toISOString(),
    type: type || "log",
    message
  });

  return res.json({ success: true });
});

app.get("/api/server/logs/:license", (req, res) => {
  const key = req.params.license;
  return res.json({
    success: true,
    data: serverLogs[key] || []
  });
});

/* ================= START ================= */

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log("GhostGuard backend running on", port);
});
