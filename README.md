
# AES PBKDF2 Node.js Compatibility Project

This project encrypts and decrypts data in **exact compatibility** with the following C# stack:

- RijndaelManaged (AES)
- CBC mode
- PKCS7 padding
- PBKDF2 (Rfc2898DeriveBytes)
- UTF-8 plaintext
- Base64 ciphertext

## Run
```bash
npm install
npm start
```

Adjust the key parameters to match your C# values exactly.
