import express from "express";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(express.json());

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
  const token = bearer.startsWith("Bearer ")
    ? bearer.slice(7)
    : null;

  if (!ADMIN_SECRET || token !== ADMIN_SECRET) {
    res.status(401).json({ success: false, error: "UNAUTHORIZED" });
    return false;
  }
  return true;
}

function generateLicenseKey() {
  const part = () =>
    crypto.randomBytes(2).toString("hex").toUpperCase();
  return `GG-${part()}-${part()}`;
}

/* ============================= */
/* ========= PUBLIC API ======== */
/* ============================= */

app.get("/", (req, res) => res.send("GhostGuard Backend OK"));

app.post("/api/license/verify", async (req, res) => {
  const { license_key, hwid } = req.body;

  if (!license_key)
    return res.status(400).json({ valid: false, reason: "MISSING_KEY" });

  const { data: lic } = await supabase
    .from("licenses")
    .select("*")
    .eq("license_key", license_key)
    .single();

  if (!lic)
    return res.json({ valid: false, reason: "NOT_FOUND" });

  if (lic.status !== "ACTIVE")
    return res.json({ valid: false, reason: lic.status });

  if (lic.expires_at && new Date(lic.expires_at) < new Date())
    return res.json({ valid: false, reason: "EXPIRED" });

  // HWID bind
  if (lic.hwid) {
    if (hwid && lic.hwid !== hwid)
      return res.json({ valid: false, reason: "HWID_MISMATCH" });
  } else if (hwid) {
    await supabase
      .from("licenses")
      .update({ hwid })
      .eq("id", lic.id);
  }

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
});

/* ============================= */
/* ========= ADMIN API ========= */
/* ============================= */

app.post("/admin/create-license", async (req, res) => {
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

  const { error } = await supabase
    .from("licenses")
    .insert([
      {
        license_key,
        status: "ACTIVE",
        expires_at,
        hwid: null
      }
    ]);

  if (error)
    return res
      .status(500)
      .json({ success: false, error: error.message });

  return res.json({ success: true, license_key });
});

app.get("/admin/licenses", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { data } = await supabase
    .from("licenses")
    .select("*")
    .order("created_at", { ascending: false });

  return res.json({ success: true, data });
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

/* ============================= */
/* ========= CUSTOMERS ========= */
/* ============================= */

app.post("/admin/create-customer", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { username, password, license_key } = req.body;

  if (!username || !password || !license_key)
    return res
      .status(400)
      .json({ success: false, error: "Missing fields" });

  const hash = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const { error } = await supabase
    .from("customers")
    .insert([
      { username, password: hash, license_key }
    ]);

  if (error)
    return res
      .status(500)
      .json({ success: false, error: error.message });

  return res.json({ success: true });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const hash = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const { data: user } = await supabase
    .from("customers")
    .select("*")
    .eq("username", username)
    .eq("password", hash)
    .single();

  if (!user)
    return res.json({ success: false });

  return res.json({
    success: true,
    license_key: user.license_key
  });
});

/* ============================= */

const port = process.env.PORT || 3000;
app.listen(port, () =>
  console.log("GhostGuard backend running on", port)
);
