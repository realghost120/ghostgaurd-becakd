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

/* ================= ROOT ================= */
app.get("/", (req, res) => res.send("GhostGuard Backend OK"));
app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

/* ================= LICENSE VERIFY ================= */
app.post("/api/license/verify", async (req, res) => {
  try {
    const { license_key, hwid } = req.body || {};
    if (!license_key)
      return res.status(400).json({ valid: false, reason: "MISSING_KEY" });

    const { data: lic, error } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", license_key)
      .single();

    if (error || !lic) return res.json({ valid: false, reason: "NOT_FOUND" });
    if (lic.status !== "ACTIVE") return res.json({ valid: false, reason: lic.status });
    if (lic.expires_at && new Date(lic.expires_at) < new Date())
      return res.json({ valid: false, reason: "EXPIRED" });

    if (lic.hwid) {
      if (hwid && lic.hwid !== hwid)
        return res.json({ valid: false, reason: "HWID_MISMATCH" });
    } else if (hwid) {
      await supabase.from("licenses").update({ hwid }).eq("id", lic.id);
    }

    await supabase
      .from("licenses")
      .update({ last_seen: new Date().toISOString() })
      .eq("id", lic.id);

    const payload = JSON.stringify({
      license_key,
      status: lic.status,
      expires_at: lic.expires_at,
      issued_at: Date.now(),
    });

    const signature = crypto
      .createHmac("sha256", LICENSE_SECRET)
      .update(payload)
      .digest("hex");

    return res.json({ valid: true, payload, signature });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ valid: false, reason: "SERVER_ERROR" });
  }
});




// ===============================
// ACTION QUEUE (Dashboard -> FiveM)
// ===============================
const actionQueue = {}; // { [license_key]: [ {id, type, payload, created_at} ] }

function pushAction(license_key, action) {
  actionQueue[license_key] = actionQueue[license_key] || [];
  actionQueue[license_key].push(action);
  // limit
  if (actionQueue[license_key].length > 200) actionQueue[license_key].splice(0, 50);
}

// Dashboard: skapa action (auth via customer token)
app.post("/api/dashboard/action", async (req, res) => {
  try {
    const { token, type, payload } = req.body || {};
    if (!token || !type) return res.status(400).json({ success: false });

    // token -> customer -> license_key
    const { data: user, error: uErr } = await supabase
      .from("customers")
      .select("*")
      .eq("id", token)
      .single();

    if (uErr || !user) return res.status(401).json({ success: false, error: "UNAUTHORIZED" });

    const license_key = user.license_key;
    const id = "ACT-" + Date.now() + "-" + Math.floor(Math.random() * 9999);

    pushAction(license_key, {
      id,
      type,                // "kick" | "ban" | "dm" | "freeze"
      payload: payload || {},
      created_at: new Date().toISOString(),
    });

    return res.json({ success: true, id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success: false });
  }
});

// FiveM: hämta actions (server poll)
app.get("/api/server/actions/:license", (req, res) => {
  const license_key = req.params.license;
  const list = actionQueue[license_key] || [];
  // töm queue när server hämtar
  actionQueue[license_key] = [];
  return res.json({ success: true, actions: list });
});


/* ================= LIVE MEMORY (status + players) ================= */
const serverState = {}; // { [license_key]: { last_seen, players, uptime, version } }
const livePlayersByLicense = {}; // { [license_key]: [{id,name,ping,identifiers?}] }

/* ===== HEARTBEAT ENDPOINT =====
   Din FiveM resource ska posta hit:
   { license_key, players:[{id,name,ping}], uptime, version }
*/
app.post("/api/server/heartbeat", async (req, res) => {
  try {
    const { license_key, players, version, uptime } = req.body || {};
    if (!license_key) return res.status(400).json({ success: false });

    livePlayersByLicense[license_key] = Array.isArray(players) ? players : [];

    serverState[license_key] = {
      last_seen: Date.now(),
      players: livePlayersByLicense[license_key].length,
      uptime: Number(uptime || 0),
      version: version || null,
    };

    // (valfritt) spara i Supabase om du vill
    await supabase.from("server_status").upsert({
      license_key,
      online: true,
      players: livePlayersByLicense[license_key].length,
      version: version || null,
      uptime: Number(uptime || 0),
      last_seen: new Date().toISOString(),
    });

    return res.json({ success: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success: false });
  }
});

app.get("/api/server/players/:license", (req, res) => {
  const license = req.params.license;
  return res.json({ success: true, players: livePlayersByLicense[license] || [] });
});

app.get("/api/server/status/:license", (req, res) => {
  const license = req.params.license;
  const data = serverState[license];

  if (!data) return res.json({ online: false, players: 0, uptime: 0, version: null });

  const online = Date.now() - data.last_seen < 30000;

  return res.json({
    online,
    players: data.players || 0,
    uptime: data.uptime || 0,
    version: data.version || null,
    last_seen: data.last_seen,
  });
});

/* ================= LOG STORAGE IN MEMORY (per license) ================= */
const serverLogs = {}; // { [license_key]: [{time,type,title,message,meta}] }

function pushServerLog(license_key, item) {
  serverLogs[license_key] = serverLogs[license_key] || [];
  serverLogs[license_key].unshift(item);
  if (serverLogs[license_key].length > 300) serverLogs[license_key].length = 300;
}

app.post("/api/server/log", (req, res) => {
  try {
    const { license_key, type, title, message, meta } = req.body || {};
    if (!license_key || !message) return res.status(400).json({ success: false });

    pushServerLog(license_key, {
      time: new Date().toISOString(),
      type: type || "log",
      title: title || "Server",
      message,
      meta: meta || "",
    });

    return res.json({ success: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success: false });
  }
});

app.get("/api/server/logs/:license", (req, res) => {
  const license = req.params.license;
  return res.json({ success: true, data: serverLogs[license] || [] });
});

/* ================= LOGIN ================= */
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.json({ success: false });

    const hash = sha256(password);

    const { data: user, error } = await supabase
      .from("customers")
      .select("*")
      .eq("username", username)
      .eq("password", hash)
      .single();

    if (error || !user) return res.json({ success: false });

    return res.json({
      success: true,
      license_key: user.license_key,
      token: user.id,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});

/* ================= CUSTOMER ================= */
app.post("/customer/dashboard", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(401).json({ success: false });

    const { data: user } = await supabase
      .from("customers")
      .select("*")
      .eq("id", token)
      .single();

    if (!user) return res.status(401).json({ success: false });

    const { data: lic } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", user.license_key)
      .single();

    if (!lic) return res.status(404).json({ success: false });

    return res.json({
      success: true,
      data: {
        license_key: lic.license_key,
        status: lic.status,
        expires_at: lic.expires_at,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});

app.post("/customer/toggle", async (req, res) => {
  try {
    const { token, status } = req.body || {};
    if (!token || !status) return res.status(400).json({ success: false });

    const { data: user } = await supabase
      .from("customers")
      .select("*")
      .eq("id", token)
      .single();

    if (!user) return res.status(401).json({ success: false });

    await supabase.from("licenses").update({ status }).eq("license_key", user.license_key);
    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});

/* ================= ADMIN ================= */
app.post("/admin/create-license", async (req, res) => {
  try {
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
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});

app.get("/admin/licenses", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { data } = await supabase
      .from("licenses")
      .select("*")
      .order("created_at", { ascending: false });

    return res.json({ success: true, data: data || [] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});

app.post("/admin/toggle-license", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { license_key, status } = req.body || {};
    if (!license_key || !status) return res.status(400).json({ success: false });

    await supabase.from("licenses").update({ status }).eq("license_key", license_key);
    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});

/* ================= START ================= */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("GhostGuard backend running on", port));
