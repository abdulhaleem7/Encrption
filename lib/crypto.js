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

module.exports = { encrypt, decrypt };
