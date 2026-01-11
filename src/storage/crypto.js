"use strict";

const crypto = require("node:crypto");

const META_KEY_KDF_SALT = "kdf_salt_b64";

function nowIso() {
  return new Date().toISOString();
}

function ensureKdfSalt(db) {
  const select = db.prepare("SELECT value FROM meta WHERE key = ?");
  const existing = select.get(META_KEY_KDF_SALT);
  if (existing && typeof existing.value === "string" && existing.value.trim()) {
    return existing.value.trim();
  }

  const salt = crypto.randomBytes(16).toString("base64");
  const insert = db.prepare("INSERT INTO meta (key, value) VALUES (?, ?)");
  insert.run(META_KEY_KDF_SALT, salt);
  return salt;
}

function deriveKey({ masterKey, saltB64 }) {
  const salt = Buffer.from(saltB64, "base64");
  return crypto.scryptSync(masterKey, salt, 32);
}

function encryptString({ plaintext, key }) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, tag, ciphertext]);
  return `enc:v1:${combined.toString("base64")}`;
}

function decryptString({ value, key }) {
  if (typeof value !== "string") return value;
  if (!value.startsWith("enc:v1:")) return value;

  const b64 = value.slice("enc:v1:".length);
  const combined = Buffer.from(b64, "base64");
  const iv = combined.subarray(0, 12);
  const tag = combined.subarray(12, 28);
  const ciphertext = combined.subarray(28);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}

function createCryptoContext({ db, masterKey }) {
  const normalizedMasterKey = (masterKey || "").toString();
  const saltB64 = ensureKdfSalt(db);

  if (!normalizedMasterKey) {
    return {
      enabled: false,
      createdAt: nowIso(),
      encryptString: (v) => v,
      decryptString: (v) => {
        if (typeof v === "string" && v.startsWith("enc:v1:")) {
          throw new Error("HAZUKI_MASTER_KEY is required to decrypt stored secrets");
        }
        return v;
      },
    };
  }

  const key = deriveKey({ masterKey: normalizedMasterKey, saltB64 });
  return {
    enabled: true,
    createdAt: nowIso(),
    encryptString: (plaintext) => encryptString({ plaintext, key }),
    decryptString: (value) => decryptString({ value, key }),
  };
}

module.exports = { createCryptoContext };
