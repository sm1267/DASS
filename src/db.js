const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { hashPassword } = require('./security');

const dataDir = path.join(__dirname, '..', 'data');
const dbPath = path.join(dataDir, 'authx-v2.db');

fs.mkdirSync(dataDir, { recursive: true });

const db = new DatabaseSync(dbPath);

function createSchema() {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'ANALYST', 'MANAGER')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1)),
      failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
      lock_until TEXT,
      reset_token_hash TEXT,
      reset_token_expires_at TEXT
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

function tableExists(name) {
  const stmt = db.prepare(`
    SELECT 1 AS found
    FROM sqlite_master
    WHERE type = 'table' AND name = ?
  `);

  return Boolean(stmt.get(name));
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

function hasExpectedSchema() {
  if (!tableExists('users') || !tableExists('tickets') || !tableExists('audit_logs')) {
    return false;
  }

  const usersSql = tableSql('users');

  return (
    usersSql.includes('password_hash TEXT NOT NULL') &&
    usersSql.includes('failed_login_attempts INTEGER NOT NULL DEFAULT 0') &&
    usersSql.includes('lock_until TEXT') &&
    usersSql.includes('reset_token_hash TEXT') &&
    usersSql.includes('reset_token_expires_at TEXT')
  );
}

function readLegacyRows(tableName) {
  if (!tableExists(tableName)) {
    return [];
  }

  const stmt = db.prepare(`SELECT * FROM ${tableName}`);
  return stmt.all();
}

function migrateSchema() {
  const legacyUsers = readLegacyRows('users');
  const legacyTickets = readLegacyRows('tickets');
  const legacyAuditLogs = readLegacyRows('audit_logs');

  db.exec(`
    PRAGMA foreign_keys = OFF;
    BEGIN TRANSACTION;
  `);

  try {
    if (tableExists('users')) {
      db.exec(`ALTER TABLE users RENAME TO users_legacy;`);
    }

    if (tableExists('tickets')) {
      db.exec(`ALTER TABLE tickets RENAME TO tickets_legacy;`);
    }

    if (tableExists('audit_logs')) {
      db.exec(`ALTER TABLE audit_logs RENAME TO audit_logs_legacy;`);
    }

    createSchema();

    const insertUserStmt = db.prepare(`
      INSERT INTO users (
        id,
        email,
        password_hash,
        role,
        created_at,
        locked,
        failed_login_attempts,
        lock_until,
        reset_token_hash,
        reset_token_expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertTicketStmt = db.prepare(`
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
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertAuditLogStmt = db.prepare(`
      INSERT INTO audit_logs (
        id,
        user_id,
        action,
        resource,
        resource_id,
        timestamp,
        ip_address
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const user of legacyUsers) {
      const role = ['USER', 'ANALYST', 'MANAGER'].includes(user.role) ? user.role : 'USER';
      const sourceSecret = user.password_hash || user.password || '';
      const passwordHash = String(sourceSecret).startsWith('scrypt$')
        ? sourceSecret
        : hashPassword(sourceSecret);

      insertUserStmt.run(
        user.id,
        user.email,
        passwordHash,
        role,
        user.created_at || new Date().toISOString(),
        Number(user.locked) === 1 ? 1 : 0,
        0,
        null,
        null,
        null,
      );
    }

    for (const ticket of legacyTickets) {
      const severity = ['LOW', 'MED', 'HIGH'].includes(ticket.severity) ? ticket.severity : 'LOW';
      const status = ['OPEN', 'IN_PROGRESS', 'RESOLVED'].includes(ticket.status)
        ? ticket.status
        : 'OPEN';

      insertTicketStmt.run(
        ticket.id,
        ticket.title,
        ticket.description,
        severity,
        status,
        ticket.owner_id,
        ticket.created_at || new Date().toISOString(),
        ticket.updated_at || ticket.created_at || new Date().toISOString(),
      );
    }

    for (const log of legacyAuditLogs) {
      insertAuditLogStmt.run(
        log.id,
        log.user_id ?? null,
        log.action,
        log.resource,
        log.resource_id || '',
        log.timestamp || new Date().toISOString(),
        log.ip_address || '',
      );
    }

    if (tableExists('users_legacy')) {
      db.exec(`DROP TABLE users_legacy;`);
    }

    if (tableExists('tickets_legacy')) {
      db.exec(`DROP TABLE tickets_legacy;`);
    }

    if (tableExists('audit_logs_legacy')) {
      db.exec(`DROP TABLE audit_logs_legacy;`);
    }

    db.exec(`
      COMMIT;
      PRAGMA foreign_keys = ON;
    `);
  } catch (error) {
    db.exec(`
      ROLLBACK;
      PRAGMA foreign_keys = ON;
    `);

    throw error;
  }
}

if (!tableExists('users')) {
  createSchema();
} else if (!hasExpectedSchema()) {
  migrateSchema();
}

const findUserByIdStmt = db.prepare(`
  SELECT
    id,
    email,
    password_hash,
    role,
    created_at,
    locked,
    failed_login_attempts,
    lock_until,
    reset_token_hash,
    reset_token_expires_at
  FROM users
  WHERE id = ?
`);

const findUserByEmailStmt = db.prepare(`
  SELECT
    id,
    email,
    password_hash,
    role,
    created_at,
    locked,
    failed_login_attempts,
    lock_until,
    reset_token_hash,
    reset_token_expires_at
  FROM users
  WHERE email = ?
`);

const findUserByResetTokenHashStmt = db.prepare(`
  SELECT
    id,
    email,
    password_hash,
    role,
    created_at,
    locked,
    failed_login_attempts,
    lock_until,
    reset_token_hash,
    reset_token_expires_at
  FROM users
  WHERE reset_token_hash = ?
`);

const insertUserStmt = db.prepare(`
  INSERT INTO users (email, password_hash, role)
  VALUES (?, ?, ?)
`);

const updatePasswordHashStmt = db.prepare(`
  UPDATE users
  SET password_hash = ?
  WHERE id = ?
`);

const updateResetTokenStmt = db.prepare(`
  UPDATE users
  SET reset_token_hash = ?, reset_token_expires_at = ?
  WHERE id = ?
`);

const clearResetTokenStmt = db.prepare(`
  UPDATE users
  SET reset_token_hash = NULL, reset_token_expires_at = NULL
  WHERE id = ?
`);

const setFailedLoginAttemptsStmt = db.prepare(`
  UPDATE users
  SET failed_login_attempts = ?, locked = ?, lock_until = ?
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

function createUser({ email, passwordHash, role = 'USER' }) {
  const normalizedEmail = normalizeEmail(email);
  const safeRole = ['USER', 'ANALYST', 'MANAGER'].includes(role) ? role : 'USER';
  const result = insertUserStmt.run(normalizedEmail, String(passwordHash || ''), safeRole);
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

function findUserByResetTokenHash(resetTokenHash) {
  return findUserByResetTokenHashStmt.get(String(resetTokenHash || '')) || null;
}

function updatePasswordHash(userId, passwordHash) {
  updatePasswordHashStmt.run(String(passwordHash || ''), Number(userId));
  return findUserById(userId);
}

function saveResetToken(userId, resetTokenHash, expiresAt) {
  updateResetTokenStmt.run(String(resetTokenHash || ''), String(expiresAt || ''), Number(userId));
  return findUserById(userId);
}

function clearResetToken(userId) {
  clearResetTokenStmt.run(Number(userId));
  return findUserById(userId);
}

function updateLoginState(userId, { failedLoginAttempts, locked, lockUntil }) {
  setFailedLoginAttemptsStmt.run(
    Number(failedLoginAttempts || 0),
    locked ? 1 : 0,
    lockUntil || null,
    Number(userId),
  );

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
  clearResetToken,
  createAuditLog,
  createTicket,
  createUser,
  findUserByEmail,
  findUserById,
  findUserByResetTokenHash,
  listAuditLogsByUser,
  listTicketsByOwner,
  saveResetToken,
  updateLoginState,
  updatePasswordHash,
};
