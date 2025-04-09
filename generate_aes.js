const crypto = require("crypto");
const fs = require("fs");

const aesKey = crypto.randomBytes(32); // 256-bit AES key
const publicKey = fs.readFileSync("public.pem", "utf8");

const encrypted = crypto.publicEncrypt(publicKey, aesKey);
fs.writeFileSync("aes_key.enc", encrypted);
console.log("AES key encrypted and saved to aes_key.enc");