require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const net = require("net");
const fs = require("fs");
const path = require("path");
const { spawnSync, spawn } = require("child_process");
const http = require("http");
const https = require("https");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");

// Configuration from environment
const {
  ADMIN_USER,
  ADMIN_PASS,
  HOSTNAME,
  SECRET_KEY,
  USE_HTTPS,
  TOKEN_MAX_AGE,
  OPENVPN_DIR,
  SECRET_DIR,
  LETSENCRYPT_DIR,
} = process.env;

const sslKey = path.join(LETSENCRYPT_DIR, HOSTNAME, "privkey.pem");
const sslCert = path.join(LETSENCRYPT_DIR, HOSTNAME, "fullchain.pem");
const ovpnDir = path.join(SECRET_DIR, "ovpns");
const MGMT_SOCK = path.join(OPENVPN_DIR, "management.sock");
const EASYRSA_DIR = path.join(OPENVPN_DIR, "easy-rsa");

const app = express();
app.use(express.json());

// Apply rate limiting to sensitive endpoints
const dlLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.use("/download", dlLimiter);

// admin auth using jwt
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed token" });
  }
  const token = auth.slice("Bearer ".length);
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    // optional: check payload.user === ADMIN_USER
    if (payload.user !== ADMIN_USER) throw new Error("Bad user");
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// URL-safe Base64 decode
function base64UrlDecode(str) {
  let s = str.replace(/_/g, "/").replace(/-/g, "+");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  return Buffer.from(s, "base64").toString("utf8");
}

// Email validator
function validateEmail(email) {
  return /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/.test(email);
}

// Generate token for download
function generateToken(email) {
  const ts = Math.floor(Date.now() / 1000);
  const payload = `${ts}:${email}`;
  const sig = crypto
    .createHmac("sha256", SECRET_KEY)
    .update(payload)
    .digest("hex");
  const raw = `${payload}.${sig}`;
  return Buffer.from(raw)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// Create certificate and package .ovpn + encrypted zip
async function createClient(email) {
  if (!validateEmail(email)) throw new Error(`Invalid email: ${email}`);
  const workDir = EASYRSA_DIR;

  const archivePath = path.join(ovpnDir, `${email}.7z`);
  if (fs.existsSync(archivePath)) {
    console.log(`Existing archive found for ${email}, revoking first…`);
    try {
      revokeClient(email);
    } catch (err) {
      console.warn(`Error revoking before create for ${email}:`, err.message);
    }
  }

  // Revoke existing cert if present
  const existing = path.join(workDir, "pki/issued", `${email}.crt`);
  if (fs.existsSync(existing)) {
    spawnSync(path.join(workDir, "easyrsa"), ["--batch", "revoke", email], {
      cwd: workDir,
    });
    ["issued", "private", "reqs"].forEach((dir) => {
      const ext = dir === "private" ? "key" : dir === "reqs" ? "req" : "crt";
      const f = path.join(workDir, `pki/${dir}/${email}.${ext}`);
      if (fs.existsSync(f)) fs.unlinkSync(f);
    });
    spawnSync(path.join(workDir, "easyrsa"), ["gen-crl"], { cwd: workDir });
  }

  // Build new client cert
  spawnSync(
    path.join(workDir, "easyrsa"),
    [
      "--batch",
      `--subject-alt-name=email:${email}`,
      "build-client-full",
      email,
      "nopass",
    ],
    { cwd: workDir, stdio: "inherit" }
  );

  // Assemble .ovpn content in memory
  const ca = fs.readFileSync(path.join(workDir, "pki/ca.crt"), "utf8");
  const cert = fs.readFileSync(
    path.join(workDir, `pki/issued/${email}.crt`),
    "utf8"
  );
  const key = fs.readFileSync(
    path.join(workDir, `pki/private/${email}.key`),
    "utf8"
  );
  const ovpnContent = [
    "client",
    "dev tun",
    "proto tcp",
    `remote ${HOSTNAME} 1194`,
    "resolv-retry infinite",
    "nobind",
    "remote-cert-tls server",
    "cipher AES-256-GCM",
    "verb 3",
    "<ca>",
    ca,
    "</ca>",
    "<cert>",
    cert,
    "</cert>",
    "<key>",
    key,
    "</key>",
    "reneg-sec 0",
    "verify-x509-name easyvpn name",
  ].join("\n");

  // Ensure output dir exists
  fs.mkdirSync(ovpnDir, { recursive: true });
  const ovpnPath = path.join(ovpnDir, `${email}.ovpn`);

  // Generate token and zip in-memory with AES256 encryption
  const token = generateToken(email);
  fs.writeFileSync(ovpnPath, ovpnContent, "utf8");
  spawnSync(
    "7z",
    ["a", "-t7z", "-mhe=on", `-p${token}`, archivePath, ovpnPath],
    {
      cwd: ovpnDir,
      stdio: "inherit",
    }
  );
  fs.unlinkSync(ovpnPath);

  const protocol = USE_HTTPS === "true" ? "https" : "http";
  return { token, url: `${protocol}://${HOSTNAME}/download?t=${token}` };
}

// reload ovpn using management sock
function reloadOpenVPNViaManagement() {
  return new Promise((resolve, reject) => {
    const client = net.createConnection({ path: MGMT_SOCK }, () => {
      client.write("signal SIGHUP\n", () => {
        client.write("exit\n");
        client.end();
      });
    });

    client.on("close", () => resolve());

    client.on("error", (err) => {
      client.destroy();
      reject(err);
    });

    setTimeout(() => {
      client.destroy();
      resolve();
    }, 2000);
  });
}

// Revoke client certificate
function revokeClient(email) {
  if (!validateEmail(email)) throw new Error(`Invalid email: ${email}`);
  const workDir = EASYRSA_DIR;

  const crt = path.join(workDir, "pki/issued", `${email}.crt`);
  if (!fs.existsSync(crt)) return false;

  spawnSync(path.join(workDir, "easyrsa"), ["--batch", "revoke", email], {
    cwd: workDir,
  });
  ["issued", "private", "reqs"].forEach((dir) => {
    const ext = dir === "private" ? "key" : dir === "reqs" ? "req" : "crt";
    const f = path.join(workDir, `pki/${dir}/${email}.${ext}`);
    if (fs.existsSync(f)) fs.unlinkSync(f);
  });
  const archive = path.join(ovpnDir, `${email}.7z`);
  if (fs.existsSync(archive)) fs.unlinkSync(archive);

  return true;
}

// Login endpoint
app.post("/login", (req, res) => {
  const { user, pass } = req.body;
  if (user !== ADMIN_USER || pass !== ADMIN_PASS) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  // Issue a token valid for, say, 1 hour
  const token = jwt.sign({ user }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

// Download endpoint
app.get("/download", (req, res) => {
  const tok = req.query.t;
  if (!tok) return res.status(400).send("Missing token");

  let raw;
  try {
    raw = base64UrlDecode(tok);
  } catch {
    return res.status(403).send("Invalid token");
  }
  const sep = raw.lastIndexOf(".");
  if (sep < 0) {
    return res.status(403).send("Invalid token");
  }
  const payload = raw.slice(0, sep);
  const sig = raw.slice(sep + 1);

  const expected = crypto
    .createHmac("sha256", SECRET_KEY)
    .update(payload)
    .digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return res.status(403).send("Invalid token");
  }
  const [tsStr, email] = payload.split(":");
  const ts = parseInt(tsStr, 10);
  const age = Math.floor(Date.now() / 1000) - ts;
  if (age > parseInt(TOKEN_MAX_AGE, 10)) {
    return res.status(403).send("Token expired");
  }
  if (!validateEmail(email)) {
    return res.status(400).send("Bad payload");
  }

  const filename = `${email}.ovpn`;
  const archivePath = path.join(ovpnDir, `${email}.7z`);

  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Content-Type", "application/x-openvpn-profile");

  const sevenZip = spawn("7z", ["x", "-so", `-p${tok}`, archivePath, filename]);
  sevenZip.on("error", (err) => {
    console.error("[7z spawn error]", err);
    if (!res.headersSent) {
      res.status(500).send("Server error");
    }
  });
  sevenZip.stdout.pipe(res);
  sevenZip.stderr.on("data", (d) => console.error("[7z]", d.toString()));
  sevenZip.on("exit", (code) => {
    if (code !== 0 && !res.headersSent) {
      res.status(403).send("Invalid token or corrupt archive");
    }
  });
});

// Create endpoint
app.post("/create", requireAdmin, async (req, res) => {
  const { emails } = req.body;
  if (!Array.isArray(emails) || emails.length === 0)
    return res.status(400).send("Missing emails array");

  const results = await Promise.all(
    emails.map(async (email) => {
      try {
        const { url } = await createClient(email);
        return { email, status: "success", downloadUrl: url };
      } catch (e) {
        console.error(`[create error] ${email}`, e);
        return { email, status: "error", message: e.message };
      }
    })
  );

  if (results.some((r) => r.status === "success")) {
    spawnSync(path.join(EASYRSA_DIR, "easyrsa"), ["gen-crl"], {
      cwd: EASYRSA_DIR,
    });
    try {
      await reloadOpenVPNViaManagement();
      console.log("OpenVPN reloaded after batch revoke");
    } catch (err) {
      console.warn("Batch reload failed:", err.message);
    }
  }

  res.json({ results });
});

// Revoke endpoint
app.post("/revoke", requireAdmin, async (req, res) => {
  const { emails } = req.body;
  if (!Array.isArray(emails) || emails.length === 0)
    return res.status(400).send("Missing emails array");

  const results = emails.map((email) => {
    try {
      const ok = revokeClient(email);
      if (!ok) {
        return { email, status: "error", message: "Certificate not found" };
      }
      return { email, status: "success" };
    } catch (e) {
      console.error(`[revoke error] ${email}`, e);
      return { email, status: "error", message: e.message };
    }
  });

  if (results.some((r) => r.status === "success")) {
    spawnSync(path.join(EASYRSA_DIR, "easyrsa"), ["gen-crl"], {
      cwd: EASYRSA_DIR,
    });
    try {
      await reloadOpenVPNViaManagement();
      console.log("OpenVPN reloaded after batch revoke");
    } catch (err) {
      console.warn("Batch reload failed:", err.message);
    }
  }

  res.json({ results });
});

// Endpoint to list currently connected VPN users
app.get("/connected-users", requireAdmin, async (req, res) => {
  const clients = [];

  const client = net.createConnection({ path: MGMT_SOCK }, () => {
    client.write("status 2\n");
    client.write("exit\n");
  });

  let data = "";

  client.on("data", (chunk) => {
    data += chunk.toString();
  });

  client.on("end", () => {
    const lines = data.split("\n");
    lines.forEach((line) => {
      if (line.startsWith("CLIENT_LIST")) {
        const parts = line.split(",");
        clients.push({
          common_name: parts[1],
          real_address: parts[2],
          bytes_received: parts[5],
          bytes_sent: parts[6],
          connected_since: parts[7],
        });
      }
    });
    res.json({ clients });
  });

  client.on("error", (err) => {
    console.error("Management interface error:", err);
    res.status(500).json({ error: "Unable to fetch connected users." });
  });
});

// Endpoint to list all valid VPN users (certificates)
app.get("/valid-users", requireAdmin, async (req, res) => {
  const certDir = path.join(EASYRSA_DIR, "pki/issued");

  fs.readdir(certDir, (err, files) => {
    if (err) {
      console.error("Error reading cert directory:", err);
      return res.status(500).json({ error: "Unable to fetch valid users." });
    }

    const users = files
      .filter((f) => f.endsWith(".crt") && f !== "easyvpn.crt")
      .map((f) => f.replace(".crt", ""));

    res.json({ users });
  });
});

// Start HTTP/HTTPS server
if (fs.existsSync(sslKey) && fs.existsSync(sslCert)) {
  https
    .createServer(
      {
        key: fs.readFileSync(sslKey),
        cert: fs.readFileSync(sslCert),
      },
      app
    )
    .listen(443, () => console.log("HTTPS on 443"));
} else {
  http.createServer(app).listen(80, () => console.log("HTTP on 80"));
}
