import express from "express";
import crypto from "crypto";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();

/* ============================= */
/* ======= MIDDLEWARE ========== */
/* ============================= */

// JSON body
app.use(express.json());

// CORS (viktigt för Netlify -> Render)
const ALLOWED_ORIGINS = [
  "https://ghostguardd.netlify.app", // din netlify sida
  "http://localhost:3000",
  "http://localhost:5173",
];

app.use(
  cors({
    origin: (origin, cb) => {
      // tillåter requests utan origin (t.ex. curl/postman)
      if (!origin) return cb(null, true);

      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("CORS_BLOCKED: " + origin), false);
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// gör så preflight alltid svarar
app.options("*", cors());

/* ============================= */
/* ========= SUPABASE ========== */
/* ============================= */

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const LICENSE_SECRET = process.env.LICENSE_SECRET;
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

// GG-XXXX-XXXX (snyggare + lätt att läsa)
function generateLicenseKey() {
  const part = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `GG-${part()}-${part()}`;
}

/* ============================= */
/* ========= PUBLIC API ======== */
/* ============================= */

app.get("/", (req, res) => res.send("GhostGuard Backend OK"));

app.post("/api/license/verify", async (req, res) => {
  try {
    const { license_key, hwid } = req.body;

    if (!license_key) {
      return res.status(400).json({ valid: false, reason: "MISSING_KEY" });
    }

    const { data: lic, error } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", license_key)
      .single();

    if (error || !lic) {
      return res.json({ valid: false, reason: "NOT_FOUND" });
    }

    if (lic.status !== "ACTIVE") {
      return res.json({ valid: false, reason: lic.status });
    }

    if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
      return res.json({ valid: false, reason: "EXPIRED" });
    }

    // HWID bind (första gången sparar vi hwid, annars kräver match)
    if (lic.hwid) {
      if (hwid && lic.hwid !== hwid) {
        return res.json({ valid: false, reason: "HWID_MISMATCH" });
      }
    } else if (hwid) {
      await supabase.from("licenses").update({ hwid }).eq("id", lic.id);
    }

    // last_seen (bra för adminpanel)
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
  } catch (e) {
    return res.status(500).json({ valid: false, reason: "SERVER_ERROR" });
  }
});

/* ============================= */
/* ========= ADMIN API ========= */
/* ============================= */

app.post("/admin/create-license", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { days_valid } = req.body;
    const days = Number(days_valid || 0);

    let expires_at = null;
    if (days > 0) {
      const d = new Date();
      d.setDate(d.getDate() + days);
      expires_at = d.toISOString();
    }

    const license_key = generateLicenseKey();

    const { error } = await supabase.from("licenses").insert([
      {
        license_key,
        status: "ACTIVE",
        expires_at,
        hwid: null,
      },
    ]);

    if (error) {
      return res.status(500).json({ success: false, error: error.message });
    }

    return res.json({ success: true, license_key });
  } catch (e) {
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

    if (error) {
      return res.status(500).json({ success: false, error: error.message });
    }

    return res.json({ success: true, data: data || [] });
  } catch (e) {
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

app.post("/admin/toggle-license", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { license_key, status } = req.body;

    if (!license_key || !status) {
      return res.status(400).json({ success: false, error: "MISSING_FIELDS" });
    }

    const { error } = await supabase
      .from("licenses")
      .update({ status })
      .eq("license_key", license_key);

    if (error) {
      return res.status(500).json({ success: false, error: error.message });
    }

    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

/* ============================= */
/* ========= CUSTOMERS ========= */
/* ============================= */

app.post("/admin/create-customer", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { username, password, license_key } = req.body;

    if (!username || !password || !license_key) {
      return res.status(400).json({ success: false, error: "Missing fields" });
    }

    const hash = crypto.createHash("sha256").update(password).digest("hex");

    const { error } = await supabase
      .from("customers")
      .insert([{ username, password: hash, license_key }]);

    if (error) {
      return res.status(500).json({ success: false, error: error.message });
    }

    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ success: false, error: "SERVER_ERROR" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) return res.json({ success: false });

    const hash = crypto.createHash("sha256").update(password).digest("hex");

    const { data: user, error } = await supabase
      .from("customers")
      .select("*")
      .eq("username", username)
      .eq("password", hash)
      .single();

    if (error || !user) return res.json({ success: false });

    return res.json({ success: true, license_key: user.license_key });
  } catch (e) {
    return res.status(500).json({ success: false });
  }
});

/* ============================= */

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("GhostGuard backend running on", port));
