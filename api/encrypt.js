const { encrypt } = require("../lib/crypto");

module.exports = (req, res) => {
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
    res.status(500).json({ error: error.message });
  }
};
