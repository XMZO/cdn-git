"use strict";

const crypto = require("node:crypto");

function nowIso() {
  return new Date().toISOString();
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function generateToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function createSession({ db, userId, ttlSeconds }) {
  const token = generateToken();
  const tokenHash = sha256Hex(token);
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + Number(ttlSeconds) * 1000).toISOString();
  db.prepare(
    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"
  ).run(tokenHash, Number(userId), createdAt, expiresAt);
  return token;
}

function deleteSession({ db, token }) {
  const tokenHash = sha256Hex((token || "").toString());
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
}

function getSessionUser({ db, token }) {
  const tokenHash = sha256Hex((token || "").toString());
  const row = db
    .prepare(
      `
      SELECT
        s.user_id AS user_id,
        s.expires_at AS expires_at,
        u.username AS username
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
    `
    )
    .get(tokenHash);

  if (!row) return null;
  if (typeof row.expires_at !== "string") return null;
  if (Date.parse(row.expires_at) <= Date.now()) return null;
  return { id: row.user_id, username: row.username };
}

function cleanupExpiredSessions({ db }) {
  const now = nowIso();
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(now);
}

module.exports = {
  createSession,
  deleteSession,
  getSessionUser,
  cleanupExpiredSessions,
};

