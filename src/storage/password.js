"use strict";

const crypto = require("node:crypto");

const VERSION = "v1";
const KEYLEN = 64;

const DEFAULT_PARAMS = {
  N: 32768,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
};

function hashPassword(password) {
  if (typeof password !== "string" || password.length < 8) {
    throw new Error("Password must be at least 8 characters");
  }

  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, KEYLEN, DEFAULT_PARAMS);
  return [
    "scrypt",
    VERSION,
    `N=${DEFAULT_PARAMS.N}`,
    `r=${DEFAULT_PARAMS.r}`,
    `p=${DEFAULT_PARAMS.p}`,
    salt.toString("base64"),
    derived.toString("base64"),
  ].join(":");
}

function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== "string") return false;
  const parts = storedHash.split(":");
  if (parts.length !== 7) return false;
  const [algo, version, nPart, rPart, pPart, saltB64, hashB64] = parts;
  if (algo !== "scrypt" || version !== VERSION) return false;

  const N = Number.parseInt(nPart.replace("N=", ""), 10);
  const r = Number.parseInt(rPart.replace("r=", ""), 10);
  const p = Number.parseInt(pPart.replace("p=", ""), 10);
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;

  const salt = Buffer.from(saltB64, "base64");
  const expected = Buffer.from(hashB64, "base64");
  const actual = crypto.scryptSync(password, salt, expected.length, {
    N,
    r,
    p,
    maxmem: DEFAULT_PARAMS.maxmem,
  });
  return crypto.timingSafeEqual(actual, expected);
}

module.exports = { hashPassword, verifyPassword };

