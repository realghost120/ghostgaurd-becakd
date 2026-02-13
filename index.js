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

function generateLicenseKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const part = (n) =>
    Array.from({ length: n }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `GG-${part(4)}-${part(4)}`; // ex: GG-G123-1H41
}

app.post("/api/admin/licenses/create", async (req, res) => {
  // Enkel “admin key” skydd så ingen annan kan skapa licenser
  const adminKey = req.headers["x-admin-key"];
  if (!process.env.ADMIN_KEY || adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
  }

  const { expires_at } = req.body; // valfritt

  // Försök några gånger ifall collision (väldigt ovanligt, men safe)
  for (let i = 0; i < 5; i++) {
    const license_key = generateLicenseKey();

    const { data, error } = await supabase
      .from("licenses")
      .insert([
        {
          license_key,
          status: "ACTIVE",
          expires_at: expires_at ?? null,
          hwid: null,
        },
      ])
      .select("*")
      .single();

    if (!error && data) {
      return res.json({ ok: true, license: data });
    }

    // om unique collision -> loopa igen, annars fail
    if (!String(error?.message || "").toLowerCase().includes("duplicate")) {
      return res.status(500).json({ ok: false, error: "DB_ERROR", details: error?.message });
    }
  }

  return res.status(500).json({ ok: false, error: "FAILED_TO_GENERATE_UNIQUE_KEY" });
});



// health check
app.get("/", (req, res) => res.send("OK"));

app.post("/api/license/verify", async (req, res) => {
  const { license_key, hwid } = req.body;

  if (!license_key) return res.status(400).json({ valid: false, reason: "MISSING_KEY" });

  const { data: lic, error } = await supabase
    .from("licenses")
    .select("*")
    .eq("license_key", license_key)
    .single();

  if (error || !lic) return res.json({ valid: false, reason: "NOT_FOUND" });

  if (lic.status !== "ACTIVE") return res.json({ valid: false, reason: lic.status });

  if (lic.expires_at && new Date(lic.expires_at) < new Date())
    return res.json({ valid: false, reason: "EXPIRED" });

  // HWID bind (första gången)
  if (lic.hwid) {
    if (hwid && lic.hwid !== hwid) return res.json({ valid: false, reason: "HWID_MISMATCH" });
  } else if (hwid) {
    await supabase.from("licenses").update({ hwid }).eq("id", lic.id);
  }

  await supabase.from("licenses").update({ last_seen: new Date().toISOString() }).eq("id", lic.id);

  const payload = JSON.stringify({
    license_key,
    status: lic.status,
    expires_at: lic.expires_at,
    issued_at: Date.now()
  });

  const signature = crypto.createHmac("sha256", LICENSE_SECRET).update(payload).digest("hex");

  return res.json({ valid: true, payload, signature });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Listening on", port));
