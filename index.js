import express from "express";
import crypto from "crypto";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();

/* ================= CORS + JSON ================= */

const corsOptions = {
  origin: true,
  credentials: false,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json());

/* ================= SUPABASE ================= */

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const LICENSE_SECRET = process.env.LICENSE_SECRET || "change_me";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

/* ================= MEMORY STORAGE ================= */

const serverState = {};     // status per license
const serverLogs = {};      // logs per license
const livePlayers = {};     // players per license
const banList = {};         // bans per license

/* ================= HELPERS ================= */

function requireAdmin(req, res) {
  const bearer = req.headers.authorization || "";
  const token = bearer.startsWith("Bearer ") ? bearer.slice(7) : null;

  if (!ADMIN_SECRET || token !== ADMIN_SECRET) {
    res.status(401).json({ success: false, error: "UNAUTHORIZED" });
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

function pushServerLog(license_key, item) {
  serverLogs[license_key] = serverLogs[license_key] || [];
  serverLogs[license_key].unshift(item);
  if (serverLogs[license_key].length > 300)
    serverLogs[license_key].length = 300;
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

    if (lic.status !== "ACTIVE")
      return res.json({ valid: false });

    if (lic.expires_at && new Date(lic.expires_at) < new Date())
      return res.json({ valid: false });

    await supabase
      .from("licenses")
      .update({ last_seen: new Date().toISOString() })
      .eq("id", lic.id);

    return res.json({ valid: true });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ valid: false });
  }
});

/* ================= SERVER HEARTBEAT ================= */

app.post("/api/server/heartbeat", async (req, res) => {
  try {
    const { license_key, players, version, uptime } = req.body;

    if (!license_key)
      return res.status(400).json({ success: false });

    livePlayers[license_key] = players || [];

    serverState[license_key] = {
      players: (players || []).length,
      version: version || "unknown",
      uptime: uptime || 0,
      last_seen: Date.now(),
    };

    return res.json({ success: true });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});

/* ================= SERVER STATUS ================= */

app.get("/api/server/status/:license", (req, res) => {
  const license = req.params.license;
  const data = serverState[license];

  if (!data) return res.json({ online: false });

  const online = (Date.now() - data.last_seen) < 30000;

  return res.json({
    online,
    players: data.players,
    uptime: data.uptime,
    version: data.version,
  });
});

/* ================= PLAYERS ================= */

app.get("/api/server/players/:license", (req, res) => {
  const license = req.params.license;
  return res.json({
    success: true,
    players: livePlayers[license] || []
  });
});

/* ================= BANS ================= */

app.get("/api/server/bans/:license", (req, res) => {
  const license = req.params.license;
  return res.json({
    success: true,
    bans: banList[license] || []
  });
});

app.post("/api/server/ban", (req, res) => {
  const { license_key, player } = req.body;
  if (!license_key || !player)
    return res.status(400).json({ success:false });

  banList[license_key] = banList[license_key] || [];
  banList[license_key].push({
    player,
    time: new Date().toISOString()
  });

  return res.json({ success:true });
});

/* ================= SERVER LOGS ================= */

app.post("/api/server/log", (req, res) => {
  const { license_key, message } = req.body;
  if (!license_key || !message)
    return res.status(400).json({ success:false });

  pushServerLog(license_key, {
    time: new Date().toISOString(),
    message
  });

  return res.json({ success:true });
});

app.get("/api/server/logs/:license", (req, res) => {
  const license = req.params.license;
  return res.json({
    success: true,
    data: serverLogs[license] || []
  });
});

/* ================= ADMIN (UNTOUCHED) ================= */

app.post("/admin/create-license", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const days = Number(req.body?.days_valid || 0);
  let expires_at = null;

  if (days > 0) {
    const d = new Date();
    d.setDate(d.getDate() + days);
    expires_at = d.toISOString();
  }

  const license_key = generateLicenseKey();

  await supabase.from("licenses").insert([
    { license_key, status: "ACTIVE", expires_at, hwid: null },
  ]);

  return res.json({ success: true, license_key });
});

app.get("/admin/licenses", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { data } = await supabase
    .from("licenses")
    .select("*")
    .order("created_at", { ascending: false });

  return res.json({ success: true, data: data || [] });
});

app.post("/admin/toggle-license", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { license_key, status } = req.body;
  await supabase
    .from("licenses")
    .update({ status })
    .eq("license_key", license_key);

  return res.json({ success: true });
});

/* ================= START ================= */

const port = process.env.PORT || 3000;
app.listen(port, () =>
  console.log("GhostGuard backend running on", port)
);
