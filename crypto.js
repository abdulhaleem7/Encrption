// Client-side AES encryption/decryption using Web Crypto API

// ===== PBKDF2 METHOD (Original) =====
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

// ===== CLIENT KEY METHOD (New) =====

// Generate IV from bytes (16 bytes for AES)
function generateIVFromBytes(seed) {
  const enc = new TextEncoder();
  const seedBytes = enc.encode(seed);
  const iv = new Uint8Array(16);
  
  for (let i = 0; i < 16; i++) {
    iv[i] = seedBytes[i % seedBytes.length];
  }
  
  return iv;
}

// Import client key directly
async function importClientKey(clientKey, encryptionType) {
  const enc = new TextEncoder();
  const keyBytes = enc.encode(clientKey);
  
  // Determine key size based on encryption type
  let keySize;
  if (encryptionType === "AES-256-CBC" || encryptionType === "AES-256-GCM") {
    keySize = 32; // 256 bits
  } else if (encryptionType === "AES-192-CBC" || encryptionType === "AES-192-GCM") {
    keySize = 24; // 192 bits
  } else {
    keySize = 16; // 128 bits (AES-128)
  }

  // Derive exact key size from client key using SHA-256
  const hashBuffer = await crypto.subtle.digest("SHA-256", keyBytes);
  const key = hashBuffer.slice(0, keySize);

  const baseAlgo = encryptionType.includes("GCM") ? "AES-GCM" : "AES-CBC";
  return crypto.subtle.importKey(
    "raw",
    key,
    { name: baseAlgo },
    false,
    ["encrypt", "decrypt"]
  );
}

// Import client key for C# method (Direct UTF-8, no hashing)
async function importClientKeyDirect(clientKey, keySize = 32) {
  const enc = new TextEncoder();
  const keyBytes = enc.encode(clientKey);
  
  // Pad or truncate key to exact size needed
  const key = new Uint8Array(keySize);
  for (let i = 0; i < keySize; i++) {
    key[i] = keyBytes[i % keyBytes.length];
  }

  return crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt function
async function encrypt(clearText, config) {
  try {
    const enc = new TextEncoder();
    
    // Check if using PBKDF2 method or Client Key method
    if (config.method === "pbkdf2") {
      // PBKDF2 Method (Original)
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
    } else {
      // Client Key Method (New)
      const encryptionType = config.encryptionType || "AES-256-CBC";
      
      // Generate or use provided IV
      const iv = config.generateIV 
        ? generateIVFromBytes(config.clientKey) 
        : enc.encode(config.InitVector);
      
      const key = await importClientKey(config.clientKey, encryptionType);

      let encrypted;
      
      if (encryptionType.includes("GCM")) {
        // AES-GCM mode
        encrypted = await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: iv
          },
          key,
          enc.encode(clearText)
        );
      } else {
        // AES-CBC mode
        encrypted = await crypto.subtle.encrypt(
          {
            name: "AES-CBC",
            iv: iv
          },
          key,
          enc.encode(clearText)
        );
      }

      // Convert to base64
      const encryptedArray = new Uint8Array(encrypted);
      let binary = '';
      for (let i = 0; i < encryptedArray.length; i++) {
        binary += String.fromCharCode(encryptedArray[i]);
      }
      
      // Include IV in result if generated
      const result = btoa(binary);
      if (config.generateIV) {
        const ivStr = Array.from(iv).map(b => String.fromCharCode(b)).join('');
        return btoa(ivStr) + ":" + result;
      }
      
      return result;
    }
  } catch (error) {
    throw new Error("Encryption failed: " + error.message);
  }
}

// Decrypt function
async function decrypt(cipherText, config) {
  try {
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    
    // Check if using PBKDF2 method or Client Key method
    if (config.method === "pbkdf2") {
      // PBKDF2 Method (Original)
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
    } else {
      // Client Key Method (New)
      const encryptionType = config.encryptionType || "AES-256-CBC";
      
      let iv;
      let actualCipherText = cipherText;
      
      // Parse IV from ciphertext if it was generated
      if (config.generateIV && cipherText.includes(":")) {
        const parts = cipherText.split(":");
        const ivBase64 = parts[0];
        actualCipherText = parts[1];
        
        const ivBinary = atob(ivBase64);
        iv = new Uint8Array(ivBinary.length);
        for (let i = 0; i < ivBinary.length; i++) {
          iv[i] = ivBinary.charCodeAt(i);
        }
      } else {
        iv = enc.encode(config.InitVector);
      }
      
      const key = await importClientKey(config.clientKey, encryptionType);

      // Convert from base64
      const binaryString = atob(actualCipherText);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      let decrypted;
      
      if (encryptionType.includes("GCM")) {
        // AES-GCM mode
        decrypted = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: iv
          },
          key,
          bytes
        );
      } else {
        // AES-CBC mode
        decrypted = await crypto.subtle.decrypt(
          {
            name: "AES-CBC",
            iv: iv
          },
          key,
          bytes
        );
      }

      return dec.decode(decrypted);
    }
  } catch (error) {
    throw new Error("Decryption failed: " + error.message);
  }
}

// Make functions available globally
window.encryptText = encrypt;
window.decryptText = decrypt;
window.generateIVFromBytes = generateIVFromBytes;

// ===== C# COMPATIBLE DECRYPTION =====
// Decrypts text using C# compatible AES-CBC with direct UTF-8 key and zero IV
async function decryptCSharp(cipherText, clientKey) {
  try {
    const dec = new TextDecoder();
    
    // Clean the input: remove all whitespace and normalize
    let processedCipherText = cipherText
      .trim()
      .replace(/\s+/g, '');  // Remove all whitespace (spaces, newlines, tabs)
    
    // Try to decode from Base64
    let buffer;
    try {
      // Decode Base64 to binary
      const binaryString = atob(processedCipherText);
      buffer = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        buffer[i] = binaryString.charCodeAt(i);
      }
    } catch (ex) {
      // If Base64 decoding fails, provide helpful error
      throw new Error("Invalid Base64 format. Make sure you copied the encrypted text exactly as provided by C#.");
    }
    
    // Create zero-filled IV (16 bytes of zeros - matches C# default)
    const iv = new Uint8Array(16);
    
    // Import key (direct UTF-8, no hashing) - use natural key length or default to 32
    const enc = new TextEncoder();
    const keyBytes = enc.encode(clientKey);
    let keySize = 32; // default to 256-bit AES
    
    // If key is exactly 16 or 24 bytes, use that size
    if (keyBytes.length === 16) {
      keySize = 16;
    } else if (keyBytes.length === 24) {
      keySize = 24;
    }
    
    const key = await importClientKeyDirect(clientKey, keySize);
    
    // Decrypt using AES-CBC
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv
      },
      key,
      buffer
    );

    return dec.decode(decrypted);
  } catch (error) {
    throw new Error("C# Decryption failed: " + error.message);
  }
}

// ===== C# COMPATIBLE ENCRYPTION =====
// Encrypts text using C# compatible AES-CBC with direct UTF-8 key and zero IV
async function encryptCSharp(plainText, clientKey) {
  try {
    const enc = new TextEncoder();
    
    // Create zero-filled IV (16 bytes of zeros - matches C# default)
    const iv = new Uint8Array(16);
    
    // Import key (direct UTF-8, no hashing) - use natural key length or default to 32
    const keyBytes = enc.encode(clientKey);
    let keySize = 32; // default to 256-bit AES
    
    // If key is exactly 16 or 24 bytes, use that size
    if (keyBytes.length === 16) {
      keySize = 16;
    } else if (keyBytes.length === 24) {
      keySize = 24;
    }
    
    const key = await importClientKeyDirect(clientKey, keySize);
    
    // Encrypt using AES-CBC
    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv: iv
      },
      key,
      enc.encode(plainText)
    );
    
    // Convert to Base64
    const encryptedArray = new Uint8Array(encrypted);
    let binary = '';
    for (let i = 0; i < encryptedArray.length; i++) {
      binary += String.fromCharCode(encryptedArray[i]);
    }
    
    return btoa(binary);
  } catch (error) {
    throw new Error("C# Encryption failed: " + error.message);
  }
}

window.decryptCSharp = decryptCSharp;
window.encryptCSharp = encryptCSharp;
