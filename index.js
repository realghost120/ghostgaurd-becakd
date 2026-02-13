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
