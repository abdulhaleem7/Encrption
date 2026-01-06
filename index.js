const crypto = require("crypto");
const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

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

function decrypt(cipherText, key) {
  const salt = Buffer.from(key.SaltValue, "ascii");
  const iv = Buffer.from(key.InitVector, "ascii");

  const derivedKey = crypto.pbkdf2Sync(
    key.PassPhrase,
    salt,
    key.PasswordIterations,
    key.Blocksize,
    "sha1"
  );

  const decipher = crypto.createDecipheriv("aes-256-cbc", derivedKey, iv);
  let decrypted = decipher.update(cipherText, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// API Routes
app.post("/api/encrypt", (req, res) => {
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
    res.json({ encrypted });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/decrypt", (req, res) => {
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

    const decrypted = decrypt(text, key);
    res.json({ decrypted });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🔐 AES Encryption Server is running on http://localhost:${PORT}`);
  console.log(`📂 Open your browser and navigate to http://localhost:${PORT}`);
});

module.exports = { encrypt, decrypt };
