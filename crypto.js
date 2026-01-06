// Client-side AES encryption/decryption using Web Crypto API

async function deriveKey(passphrase, salt, iterations, keySize) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: iterations,
      hash: "SHA-1"
    },
    keyMaterial,
    { name: "AES-CBC", length: keySize * 8 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(clearText, config) {
  try {
    const enc = new TextEncoder();
    const iv = enc.encode(config.InitVector);
    
    const key = await deriveKey(
      config.PassPhrase,
      config.SaltValue,
      config.PasswordIterations,
      config.Blocksize
    );

    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv: iv
      },
      key,
      enc.encode(clearText)
    );

    // Convert to base64
    const encryptedArray = new Uint8Array(encrypted);
    let binary = '';
    for (let i = 0; i < encryptedArray.length; i++) {
      binary += String.fromCharCode(encryptedArray[i]);
    }
    return btoa(binary);
  } catch (error) {
    throw new Error("Encryption failed: " + error.message);
  }
}

async function decrypt(cipherText, config) {
  try {
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    const iv = enc.encode(config.InitVector);
    
    const key = await deriveKey(
      config.PassPhrase,
      config.SaltValue,
      config.PasswordIterations,
      config.Blocksize
    );

    // Convert from base64
    const binaryString = atob(cipherText);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv
      },
      key,
      bytes
    );

    return dec.decode(decrypted);
  } catch (error) {
    throw new Error("Decryption failed: " + error.message);
  }
}

// Make functions available globally
window.encryptText = encrypt;
window.decryptText = decrypt;
