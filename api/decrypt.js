const crypto = require("crypto");

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

export default function handler(req, res) {
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
    return res.status(200).end();
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

    const decrypted = decrypt(text, key);
    res.status(200).json({ decrypted });
  } catch (error) {
    console.error("Decryption error:", error);
    res.status(500).json({ error: error.message });
  }
};
