"use strict";

const { hashPassword, verifyPassword } = require("./password");

function nowIso() {
  return new Date().toISOString();
}

function countUsers({ db }) {
  const row = db.prepare("SELECT COUNT(1) AS c FROM users").get();
  return row ? Number(row.c) : 0;
}

function createUser({ db, username, password }) {
  const u = (username || "").toString().trim();
  const p = (password || "").toString();
  if (!u) {
    const err = new Error("Username is required");
    err.statusCode = 400;
    throw err;
  }
  if (!p) {
    const err = new Error("Password is required");
    err.statusCode = 400;
    throw err;
  }

  const passwordHash = hashPassword(p);
  const ts = nowIso();
  db.prepare("INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)").run(
    u,
    passwordHash,
    ts,
    ts
  );
  return getUserByUsername({ db, username: u });
}

function ensureBootstrapAdmin({ db, username, password }) {
  if (countUsers({ db }) > 0) return false;

  const u = (username || "").toString().trim();
  const p = (password || "").toString();
  if (!u || !p) return false;

  createUser({ db, username: u, password: p });
  return true;
}

function getUserByUsername({ db, username }) {
  const u = (username || "").toString().trim();
  if (!u) return null;
  return db
    .prepare("SELECT id, username, password_hash, created_at, updated_at FROM users WHERE username = ?")
    .get(u);
}

function getUserById({ db, id }) {
  return db
    .prepare("SELECT id, username, created_at, updated_at FROM users WHERE id = ?")
    .get(Number(id));
}

function verifyUserPassword({ db, username, password }) {
  const user = getUserByUsername({ db, username });
  if (!user) return null;
  const ok = verifyPassword(password, user.password_hash);
  if (!ok) return null;
  return { id: user.id, username: user.username };
}

function updateUserPassword({ db, userId, newPassword }) {
  const passwordHash = hashPassword(newPassword);
  const ts = nowIso();
  db.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?").run(
    passwordHash,
    ts,
    Number(userId)
  );
}

module.exports = {
  countUsers,
  createUser,
  ensureBootstrapAdmin,
  getUserById,
  verifyUserPassword,
  updateUserPassword,
};
