import express from "express";
import crypto from "crypto";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();

/* ============================= */
/* ========= CORS ============== */
/* ============================= */

const ALLOWED_ORIGINS = new Set([
  "https://ghostguardd.netlify.app",
  "http://localhost:3000",
  "http://localhost:5173",
]);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.has(origin)) return cb(null, true);
      return cb(new Error("CORS_BLOCKED: " + origin), false);
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.options("*", cors());
app.use(express.json());

/* ============================= */
/* ========= SUPABASE ========== */
/* ============================= */

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const ADMIN_SECRET = process.env.ADMIN_SECRET;

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

function generateLicenseKey() {
  const part = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `GG-${part()}-${part()}`;
}

/* ============================= */
/* ========= ROOT ============== */
/* ============================= */

app.get("/", (req, res) => res.send("GhostGuard Backend OK"));

/* ============================= */
/* ========= LOGIN ============= */
/* ============================= */

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.json({ success: false });
    }

    const hash = crypto.createHash("sha256").update(password).digest("hex");

    const { data: user, error } = await supabase
      .from("customers")
      .select("*")
      .eq("username", username)
      .eq("password", hash)
      .single();

    if (error || !user) {
      return res.json({ success: false });
    }

    return res.json({
      success: true,
      license_key: user.license_key,
      token: user.id   // 🔥 FIX
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
        expires_at: lic.expires_at
      }
    });

  } catch {
    return res.status(500).json({ success: false });
  }
});

/* ============================= */
/* ========= TOGGLE ============ */
/* ============================= */

app.post("/customer/toggle", async (req, res) => {
  try {
    const { token, status } = req.body || {};
    if (!token || !status) {
      return res.status(400).json({ success: false });
    }

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

/* ============================= */
/* ========= LIVE PLAYERS ====== */
/* ============================= */

app.post("/customer/live-players", async (req, res) => {
  return res.json({
    success: true,
    players: []
  });
});

/* ============================= */
/* ========= ADMIN ============= */
/* ============================= */

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

  const { error } = await supabase.from("licenses").insert([
    { license_key, status: "ACTIVE", expires_at }
  ]);

  if (error) {
    return res.status(500).json({ success: false, error: error.message });
  }

  return res.json({ success: true, license_key });
});

app.post("/admin/create-customer", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { username, password, license_key } = req.body || {};
  if (!username || !password || !license_key) {
    return res.status(400).json({ success: false });
  }

  const hash = crypto.createHash("sha256").update(password).digest("hex");

  const { error } = await supabase
    .from("customers")
    .insert([{ username, password: hash, license_key }]);

  if (error) {
    return res.status(500).json({ success: false, error: error.message });
  }

  return res.json({ success: true });
});

/* ============================= */

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("GhostGuard backend running on", port));
