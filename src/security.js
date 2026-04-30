const crypto = require('node:crypto');

const SCRYPT_OPTIONS = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024,
};

const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(String(password || ''), salt, 64, SCRYPT_OPTIONS);
  return `scrypt$${salt}$${derivedKey.toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  const parts = String(storedHash || '').split('$');

  if (parts.length !== 3 || parts[0] !== 'scrypt') {
    return false;
  }

  const [, salt, expectedHashHex] = parts;
  const derivedKey = crypto.scryptSync(String(password || ''), salt, 64, SCRYPT_OPTIONS);
  const expectedHash = Buffer.from(expectedHashHex, 'hex');

  if (expectedHash.length !== derivedKey.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedHash, derivedKey);
}

function passwordPolicyErrors(password) {
  const value = String(password || '');
  const errors = [];

  if (value.length < 10) {
    errors.push('Parola trebuie sa aiba cel putin 10 caractere.');
  }

  if (!/[a-z]/.test(value)) {
    errors.push('Parola trebuie sa contina cel putin o litera mica.');
  }

  if (!/[A-Z]/.test(value)) {
    errors.push('Parola trebuie sa contina cel putin o litera mare.');
  }

  if (!/[0-9]/.test(value)) {
    errors.push('Parola trebuie sa contina cel putin o cifra.');
  }

  if (!/[^A-Za-z0-9]/.test(value)) {
    errors.push('Parola trebuie sa contina cel putin un caracter special.');
  }

  return errors;
}

function createResetToken() {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();

  return {
    token,
    tokenHash: hashResetToken(token),
    expiresAt,
  };
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

module.exports = {
  RESET_TOKEN_TTL_MS,
  createResetToken,
  hashPassword,
  hashResetToken,
  passwordPolicyErrors,
  verifyPassword,
};
