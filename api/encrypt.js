const crypto = require("crypto");

function encrypt(clearText, key) {
  const salt = Buffer.from(key.SaltValue, "ascii");
  const iv = Buffer.from(key.InitVector, "ascii");

  const derivedKey = crypto.pbkdf2Sync(
    key.PassPhrase,
    salt,
    key.PasswordIterations,
    key.Blocksize,
    "sha1"
  );

  const cipher = crypto.createCipheriv("aes-256-cbc", derivedKey, iv);
  let encrypted = cipher.update(clearText, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

module.exports = function handler(req, res) {
  // Enable CORS
  res.setHeader("Access-Control-Allow-Credentials", true);
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS,PATCH,DELETE,POST,PUT");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version"
  );
  res.setHeader("Content-Type", "application/json");

  if (req.method === "OPTIONS") {
    res.status(200).end();
    return;
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { text, key } = req.body;
    
    if (!text || !key) {
      return res.status(400).json({ error: "Missing text or key parameters" });
    }

    // Validate key parameters
    if (!key.PassPhrase || !key.SaltValue || !key.InitVector) {
      return res.status(400).json({ error: "Missing required key parameters" });
    }

    if (key.InitVector.length !== 16) {
      return res.status(400).json({ error: "InitVector must be exactly 16 characters" });
    }

    const encrypted = encrypt(text, key);
    res.status(200).json({ encrypted });
  } catch (error) {
    console.error("Encryption error:", error);
    res.status(500).json({ error: error.message });
  }
};;
