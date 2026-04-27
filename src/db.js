const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const dataDir = path.join(__dirname, '..', 'data');
const dbPath = path.join(dataDir, 'authx-v1.db');

fs.mkdirSync(dataDir, { recursive: true });

const db = new DatabaseSync(dbPath);

function createSchema() {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'ANALYST', 'MANAGER')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      reset_token TEXT,
      reset_requested_at TEXT,
      locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1))
    );

    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'LOW' CHECK (severity IN ('LOW', 'MED', 'HIGH')),
      status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED')),
      owner_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      resource_id TEXT,
      timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      ip_address TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
}

function tableSql(name) {
  const stmt = db.prepare(`
    SELECT sql
    FROM sqlite_master
    WHERE type = 'table' AND name = ?
  `);

  const row = stmt.get(name);
  return row ? row.sql || '' : '';
}

function tableExists(name) {
  const stmt = db.prepare(`
    SELECT 1 AS found
    FROM sqlite_master
    WHERE type = 'table' AND name = ?
  `);

  return Boolean(stmt.get(name));
}

function hasExpectedSchema() {
  if (!tableExists('users') || !tableExists('tickets') || !tableExists('audit_logs')) {
    return false;
  }

  const usersSql = tableSql('users');
  const ticketsSql = tableSql('tickets');

  return (
    usersSql.includes('locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1))') &&
    usersSql.includes("role TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'ANALYST', 'MANAGER'))") &&
    ticketsSql.includes("severity TEXT NOT NULL DEFAULT 'LOW' CHECK (severity IN ('LOW', 'MED', 'HIGH'))") &&
    ticketsSql.includes("status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED'))")
  );
}

function migrateSchema() {
  db.exec(`
    PRAGMA foreign_keys = OFF;
    BEGIN TRANSACTION;

    ALTER TABLE users RENAME TO users_legacy;
    ALTER TABLE tickets RENAME TO tickets_legacy;
    ALTER TABLE audit_logs RENAME TO audit_logs_legacy;
  `);

  createSchema();

  db.exec(`
    INSERT INTO users (
      id,
      email,
      password,
      role,
      created_at,
      reset_token,
      reset_requested_at,
      locked
    )
    SELECT
      id,
      email,
      password,
      CASE
        WHEN role IN ('USER', 'ANALYST', 'MANAGER') THEN role
        ELSE 'USER'
      END,
      created_at,
      reset_token,
      reset_requested_at,
      0
    FROM users_legacy;

    INSERT INTO tickets (
      id,
      title,
      description,
      severity,
      status,
      owner_id,
      created_at,
      updated_at
    )
    SELECT
      id,
      title,
      description,
      CASE
        WHEN severity IN ('LOW', 'MED', 'HIGH') THEN severity
        ELSE 'LOW'
      END,
      CASE
        WHEN status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED') THEN status
        ELSE 'OPEN'
      END,
      owner_id,
      created_at,
      updated_at
    FROM tickets_legacy;

    INSERT INTO audit_logs (
      id,
      user_id,
      action,
      resource,
      resource_id,
      timestamp,
      ip_address
    )
    SELECT
      id,
      user_id,
      action,
      resource,
      resource_id,
      timestamp,
      ip_address
    FROM audit_logs_legacy;

    DROP TABLE users_legacy;
    DROP TABLE tickets_legacy;
    DROP TABLE audit_logs_legacy;

    COMMIT;
    PRAGMA foreign_keys = ON;
  `);
}

if (!tableExists('users')) {
  createSchema();
} else if (!hasExpectedSchema()) {
  migrateSchema();
}

const findUserByIdStmt = db.prepare(`
  SELECT id, email, password, role, created_at, reset_token, reset_requested_at, locked
  FROM users
  WHERE id = ?
`);

const findUserByEmailStmt = db.prepare(`
  SELECT id, email, password, role, created_at, reset_token, reset_requested_at, locked
  FROM users
  WHERE email = ?
`);

const findUserByResetTokenStmt = db.prepare(`
  SELECT id, email, password, role, created_at, reset_token, reset_requested_at, locked
  FROM users
  WHERE reset_token = ?
`);

const insertUserStmt = db.prepare(`
  INSERT INTO users (email, password, role)
  VALUES (?, ?, ?)
`);

const updateResetTokenStmt = db.prepare(`
  UPDATE users
  SET reset_token = ?, reset_requested_at = CURRENT_TIMESTAMP
  WHERE id = ?
`);

const updatePasswordStmt = db.prepare(`
  UPDATE users
  SET password = ?
  WHERE id = ?
`);

const insertTicketStmt = db.prepare(`
  INSERT INTO tickets (title, description, severity, status, owner_id)
  VALUES (?, ?, ?, ?, ?)
`);

const listTicketsByOwnerStmt = db.prepare(`
  SELECT id, title, description, severity, status, owner_id, created_at, updated_at
  FROM tickets
  WHERE owner_id = ?
  ORDER BY id DESC
`);

const countUsersStmt = db.prepare(`SELECT COUNT(*) AS total FROM users`);
const countTicketsStmt = db.prepare(`SELECT COUNT(*) AS total FROM tickets`);
const countTicketsByOwnerStmt = db.prepare(`
  SELECT COUNT(*) AS total
  FROM tickets
  WHERE owner_id = ?
`);

const insertAuditLogStmt = db.prepare(`
  INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
  VALUES (?, ?, ?, ?, ?)
`);

const listAuditLogsByUserStmt = db.prepare(`
  SELECT id, user_id, action, resource, resource_id, timestamp, ip_address
  FROM audit_logs
  WHERE user_id = ?
  ORDER BY id DESC
  LIMIT ?
`);

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function createUser({ email, password, role = 'USER' }) {
  const normalizedEmail = normalizeEmail(email);
  const safeRole = ['USER', 'ANALYST', 'MANAGER'].includes(role) ? role : 'USER';
  const result = insertUserStmt.run(normalizedEmail, String(password || ''), safeRole);
  return findUserById(Number(result.lastInsertRowid));
}

function findUserById(id) {
  if (!id) {
    return null;
  }

  return findUserByIdStmt.get(Number(id)) || null;
}

function findUserByEmail(email) {
  return findUserByEmailStmt.get(normalizeEmail(email)) || null;
}

function saveResetToken(userId, resetToken) {
  updateResetTokenStmt.run(String(resetToken), Number(userId));
  return findUserById(userId);
}

function findUserByResetToken(resetToken) {
  return findUserByResetTokenStmt.get(String(resetToken || '')) || null;
}

function updatePassword(userId, password) {
  updatePasswordStmt.run(String(password || ''), Number(userId));
  return findUserById(userId);
}

function createTicket({ title, description, severity = 'LOW', status = 'OPEN', ownerId }) {
  const safeSeverity = ['LOW', 'MED', 'HIGH'].includes(severity) ? severity : 'LOW';
  const safeStatus = ['OPEN', 'IN_PROGRESS', 'RESOLVED'].includes(status) ? status : 'OPEN';
  const result = insertTicketStmt.run(
    String(title || '').trim(),
    String(description || '').trim(),
    safeSeverity,
    safeStatus,
    Number(ownerId),
  );

  return result.lastInsertRowid;
}

function listTicketsByOwner(ownerId) {
  return listTicketsByOwnerStmt.all(Number(ownerId));
}

function countUsers() {
  const row = countUsersStmt.get();
  return row ? row.total : 0;
}

function countTickets() {
  const row = countTicketsStmt.get();
  return row ? row.total : 0;
}

function countTicketsByOwner(ownerId) {
  const row = countTicketsByOwnerStmt.get(Number(ownerId));
  return row ? row.total : 0;
}

function createAuditLog({ userId = null, action, resource, resourceId = '', ipAddress = '' }) {
  insertAuditLogStmt.run(
    userId ? Number(userId) : null,
    String(action || ''),
    String(resource || ''),
    String(resourceId || ''),
    String(ipAddress || ''),
  );
}

function listAuditLogsByUser(userId, limit = 10) {
  return listAuditLogsByUserStmt.all(Number(userId), Number(limit));
}

module.exports = {
  dbPath,
  countTickets,
  countTicketsByOwner,
  countUsers,
  createAuditLog,
  createTicket,
  createUser,
  findUserByEmail,
  findUserById,
  findUserByResetToken,
  listAuditLogsByUser,
  listTicketsByOwner,
  saveResetToken,
  updatePassword,
};
