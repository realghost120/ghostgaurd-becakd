import express from "express";
import crypto from "crypto";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();

/* ============================= */
/* ========= CORS + JSON ======= */
/* ============================= */
/**
 * Tillåt ALLA origins (enklast när Netlify/Render bråkar).
 * Viktigt: preflight måste använda samma cors-options.
 */
const corsOptions = {
  origin: true,
  credentials: false,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // preflight
app.use(express.json());

/* ============================= */
/* ========= SUPABASE ========== */
/* ============================= */

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const LICENSE_SECRET = process.env.LICENSE_SECRET || "change_me";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

/* ============================= */
/* ========= HELPERS =========== */
/* ============================= */

function requireAdmin(req, res) {
  const bearer = req.headers.authorization || "";
  const token = bearer.startsWith("Bearer ") ? bearer.slice(7) : null;

  if (!ADMIN_SECRET || token !== ADMIN_SECRET) {
    res.status(401).json({ success: false, error: "UNAUTHORIZED" });
    return false;
  }
  return true;
}

// GG-XXXX-XXXX (snyggt)
function generateLicenseKey() {
  const part = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `GG-${part()}-${part()}`;
}

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

/* ============================= */
/* ========= ROOT ============== */
/* ============================= */

app.get("/", (req, res) => res.send("GhostGuard Backend OK"));

/* ============================= */
/* ========= PUBLIC API ======== */
/* ============================= */

app.post("/api/license/verify", async (req, res) => {
  try {
    const { license_key, hwid } = req.body || {};
    if (!license_key) {
      return res.status(400).json({ valid: false, reason: "MISSING_KEY" });
    }

    const { data: lic, error } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", license_key)
      .single();

    if (error || !lic) return res.json({ valid: false, reason: "NOT_FOUND" });
    if (lic.status !== "ACTIVE") return res.json({ valid: false, reason: lic.status });

    if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
      return res.json({ valid: false, reason: "EXPIRED" });
    }

    // HWID bind
    if (lic.hwid) {
      if (hwid && lic.hwid !== hwid) return res.json({ valid: false, reason: "HWID_MISMATCH" });
    } else if (hwid) {
      await supabase.from("licenses").update({ hwid }).eq("id", lic.id);
    }

    // last_seen
    await supabase
      .from("licenses")
      .update({ last_seen: new Date().toISOString() })
      .eq("id", lic.id);

    const payloadObj = {
      license_key,
      status: lic.status,
      expires_at: lic.expires_at,
      issued_at: Date.now(),
    };
    const payload = JSON.stringify(payloadObj);

    const signature = crypto
      .createHmac("sha256", LICENSE_SECRET)
      .update(payload)
      .digest("hex");

    return res.json({ valid: true, payload, signature });
  } catch {
    return res.status(500).json({ valid: false, reason: "SERVER_ERROR" });
  }
});

/* ============================= */
/* ========= LOGIN ============= */
/* ============================= */
/**
 * Frontend ska posta hit: /api/login
 * Returnerar token = user.id (som dashboard använder).
 */
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
      token: user.id, // viktigt för /customer/dashboard osv
    });
  } catch {
    return res.status(500).json({ success: false });
  }
});

/* ============================= */
/* ===== CUSTOMER DASHBOARD ==== */
/* ============================= */

app.post("/customer/dashboard", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(401).json({ success: false });

    const { data: user, error: userErr } = await supabase
      .from("customers")
      .select("*")
      .eq("id", token)
      .single();

    if (userErr || !user) return res.status(401).json({ success: false });

    const { data: lic, error: licErr } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", user.license_key)
      .single();

    if (licErr || !lic) return res.status(404).json({ success: false });

    return res.json({
      success: true,
      data: {
        license_key: lic.license_key,
        status: lic.status,
        expires_at: lic.expires_at,
      },
    });
  } catch {
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

    const { error } = await supabase
      .from("licenses")
      .update({ status })
      .eq("license_key", user.license_key);

    if (error) return res.status(500).json({ success: false });

    return res.json({ success: true });
  } catch {
    return res.status(500).json({ success: false });
  }
});

// (mock) live players
app.post("/customer/live-players", async (_req, res) => {
  return res.json({ success: true, players: [] });
});

/* ============================= */
/* ========= ADMIN API ========= */
/* ============================= */

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

    const { error } = await supabase.from("licenses").insert([
      { license_key, status: "ACTIVE", expires_at, hwid: null },
    ]);

    if (error) return res.status(500).json({ success: false, error: error.message });

    return res.json({ success: true, license_key });
  } catch {
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

app.get("/admin/licenses", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { data, error } = await supabase
      .from("licenses")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ success: false, error: error.message });

    return res.json({ success: true, data: data || [] });
  } catch {
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

app.post("/admin/toggle-license", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { license_key, status } = req.body || {};
    if (!license_key || !status) {
      return res.status(400).json({ success: false, error: "MISSING_FIELDS" });
    }

    const { error } = await supabase
      .from("licenses")
      .update({ status })
      .eq("license_key", license_key);

    if (error) return res.status(500).json({ success: false, error: error.message });

    return res.json({ success: true });
  } catch {
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

app.post("/admin/create-customer", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { username, password, license_key } = req.body || {};
    if (!username || !password || !license_key) {
      return res.status(400).json({ success: false, error: "Missing fields" });
    }

    const hash = sha256(password);

    const { error } = await supabase
      .from("customers")
      .insert([{
        username,
        password: hash,          // används för login
        password_plain: password, // 🔥 TEST MODE
        license_key
      }]);

    if (error) {
      return res.status(500).json({
        success: false,
        error: error.message,
      });
    }

    return res.json({ success: true });
  } catch {
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});


/* ============================= */

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("GhostGuard backend running on", port));
