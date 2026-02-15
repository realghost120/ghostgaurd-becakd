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
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

/* ================= MEMORY STORAGE ================= */

// Allt sparas per license
const servers = {}; // { license_key: { players, version, started_at, last_seen } }
const serverLogs = {}; // { license_key: [logs] }

/* ================= HELPERS ================= */

function requireAdmin(req, res) {
  const bearer = req.headers.authorization || "";
  const token = bearer.startsWith("Bearer ") ? bearer.slice(7) : null;

  if (!ADMIN_SECRET || token !== ADMIN_SECRET) {
    res.status(401).json({ success: false });
    return false;
  }
  return true;
}

function generateLicenseKey() {
  const part = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `GG-${part()}-${part()}`;
}

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

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
    if (lic.status !== "ACTIVE") return res.json({ valid: false });

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

/* ================= SERVER HEARTBEAT ================= */

app.post("/api/server/heartbeat", (req, res) => {
  const { license_key, players, version } = req.body;

  if (!license_key)
    return res.status(400).json({ success: false });

  if (!servers[license_key]) {
    servers[license_key] = {
      players: [],
      version: version || "3.0.0",
      started_at: Date.now(),
      last_seen: Date.now()
    };
  }

  const server = servers[license_key];

  server.players = players || [];
  server.version = version || server.version;
  server.last_seen = Date.now();

  return res.json({ success: true });
});

/* ================= SERVER STATUS ================= */

app.get("/api/server/status/:license", (req, res) => {
  const key = req.params.license;
  const server = servers[key];

  if (!server) return res.json({ online: false });

  const online = (Date.now() - server.last_seen) < 30000;
  const uptime = Math.floor((Date.now() - server.started_at) / 1000);

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

  return res.json({
    success: true,
    players: server ? server.players : []
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
  return res.json({
    success: true,
    data: serverLogs[req.params.license] || []
  });
});

/* ================= LOGIN ================= */

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password)
      return res.json({ success: false });

    const hash = sha256(password);

    const { data: user } = await supabase
      .from("customers")
      .select("*")
      .eq("username", username)
      .eq("password", hash)
      .single();

    if (!user) return res.json({ success: false });

    return res.json({
      success: true,
      license_key: user.license_key,
      token: user.id
    });

  } catch {
    return res.status(500).json({ success: false });
  }
});

/* ================= CUSTOMER ================= */

app.post("/customer/dashboard", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token)
      return res.status(401).json({ success: false });

    const { data: user } = await supabase
      .from("customers")
      .select("*")
      .eq("id", token)
      .single();

    if (!user)
      return res.status(401).json({ success: false });

    const { data: lic } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", user.license_key)
      .single();

    if (!lic)
      return res.status(404).json({ success: false });

    return res.json({
      success: true,
      data: {
        license_key: lic.license_key,
        status: lic.status,
        expires_at: lic.expires_at
      }
    });

  } catch {
    return res.status(500).json({ success: false });
  }
});

/* ================= ADMIN ================= */

app.get("/admin/licenses", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { data } = await supabase
    .from("licenses")
    .select("*")
    .order("created_at", { ascending: false });

  return res.json({ success: true, data });
});

/* ================= START ================= */

const port = process.env.PORT || 3000;

app.listen(port, () =>
  console.log("GhostGuard backend running on", port)
);
