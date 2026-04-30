const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const {
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
} = require('./db');
const {
  createResetToken,
  hashPassword,
  hashResetToken,
  passwordPolicyErrors,
  verifyPassword,
} = require('./security');

const app = express();
const PORT = process.env.PORT || 3000;

const INVALID_CREDENTIALS_MESSAGE = 'Credentiale invalide.';
const RESET_REQUEST_SUCCESS_MESSAGE =
  'Daca exista un cont asociat acestui email, vei primi instructiuni pentru resetarea parolei.';
const LOGIN_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RATE_LIMIT_MAX_REQUESTS = 10;
const ACCOUNT_LOCK_THRESHOLD = 5;
const ACCOUNT_LOCK_DURATION_MS = 15 * 60 * 1000;
const LOGIN_MIN_RESPONSE_MS = 250;
const sessionMaxAgeMs = 30 * 60 * 1000;
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const loginRateLimitStore = new Map();
const dummyPasswordHash = hashPassword('dummy-password-for-uniform-login-timing');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use(
  session({
    name: 'authx.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: 'auto',
      sameSite: 'lax',
      maxAge: sessionMaxAgeMs,
    },
  }),
);

app.use((req, res, next) => {
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  res.locals.currentUser = req.session.userId ? findUserById(req.session.userId) : null;
  next();
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function wait(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function ensureMinimumDuration(startedAt) {
  const elapsed = Date.now() - startedAt;
  const remaining = LOGIN_MIN_RESPONSE_MS - elapsed;

  if (remaining > 0) {
    await wait(remaining);
  }
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }

  return req.socket.remoteAddress || 'unknown';
}

function logEvent(req, { userId = null, action, resource, resourceId = '' }) {
  createAuditLog({
    userId,
    action,
    resource,
    resourceId,
    ipAddress: getClientIp(req),
  });
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function readBodyField(req, fieldName, fallback = '') {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const value = body[fieldName];

  if (value === undefined || value === null) {
    return String(fallback);
  }

  return String(value);
}

function validateRegisterForm({ email, password }) {
  if (!email || !password) {
    return 'Emailul si parola sunt obligatorii.';
  }

  if (!isValidEmail(email)) {
    return 'Emailul introdus nu este valid.';
  }

  if (email.length > 254) {
    return 'Emailul este prea lung.';
  }

  if (password.length > 255) {
    return 'Parola este prea lunga.';
  }

  const policyErrors = passwordPolicyErrors(password);

  if (policyErrors.length > 0) {
    return policyErrors.join(' ');
  }

  return null;
}

function validateTicketForm({ title, description, severity }) {
  if (!title || !description) {
    return 'Titlul si descrierea sunt obligatorii.';
  }

  if (title.length > 120) {
    return 'Titlul este prea lung.';
  }

  if (description.length > 2000) {
    return 'Descrierea este prea lunga.';
  }

  if (!['LOW', 'MED', 'HIGH'].includes(severity)) {
    return 'Severitatea selectata nu este valida.';
  }

  return null;
}

function validateForgotPasswordForm(email) {
  if (!email) {
    return 'Emailul este obligatoriu.';
  }

  if (!isValidEmail(email)) {
    return 'Emailul introdus nu este valid.';
  }

  return null;
}

function isLocked(user) {
  if (!user || Number(user.locked) !== 1) {
    return false;
  }

  if (!user.lock_until) {
    return true;
  }

  return Date.parse(user.lock_until) > Date.now();
}

function hasLockExpired(user) {
  return Boolean(user && Number(user.locked) === 1 && user.lock_until && Date.parse(user.lock_until) <= Date.now());
}

function registerFailedIpAttempt(ipAddress) {
  const now = Date.now();
  const recentAttempts = (loginRateLimitStore.get(ipAddress) || []).filter(
    (timestamp) => now - timestamp < LOGIN_RATE_LIMIT_WINDOW_MS,
  );

  recentAttempts.push(now);
  loginRateLimitStore.set(ipAddress, recentAttempts);
}

function isIpRateLimited(ipAddress) {
  const now = Date.now();
  const recentAttempts = (loginRateLimitStore.get(ipAddress) || []).filter(
    (timestamp) => now - timestamp < LOGIN_RATE_LIMIT_WINDOW_MS,
  );

  loginRateLimitStore.set(ipAddress, recentAttempts);
  return recentAttempts.length >= LOGIN_RATE_LIMIT_MAX_REQUESTS;
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

function normalizeSeverity(severity) {
  return ['LOW', 'MED', 'HIGH'].includes(severity) ? severity : 'LOW';
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    setFlash(req, 'error', 'Trebuie sa te autentifici inainte de a accesa aceasta pagina.');
    return res.redirect('/login');
  }

  const sessionUser = findUserById(req.session.userId);

  if (!sessionUser) {
    req.session.destroy(() => {
      res.clearCookie('authx.sid');
      res.redirect('/login');
    });
    return;
  }

  return next();
}

app.get('/', (req, res) => {
  res.render('index', {
    dbPath,
    totalUsers: countUsers(),
    totalTickets: countTickets(),
  });
});

app.get('/register', (req, res) => {
  res.render('register', {
    form: { email: '' },
    error: null,
  });
});

app.post('/register', (req, res) => {
  const email = readBodyField(req, 'email').trim().toLowerCase();
  const password = readBodyField(req, 'password');
  const validationError = validateRegisterForm({ email, password });

  if (validationError) {
    return res.status(400).render('register', {
      form: { email },
      error: validationError,
    });
  }

  if (findUserByEmail(email)) {
    return res.status(409).render('register', {
      form: { email },
      error: 'Exista deja un utilizator cu acest email.',
    });
  }

  const user = createUser({
    email,
    passwordHash: hashPassword(password),
    role: 'USER',
  });

  logEvent(req, {
    userId: user.id,
    action: 'REGISTER',
    resource: 'auth',
    resourceId: user.id,
  });

  setFlash(req, 'success', 'Contul a fost creat. Te poti autentifica acum.');
  return res.redirect(303, '/login');
});

app.get('/login', (req, res) => {
  res.render('login', {
    form: { email: '' },
    error: null,
  });
});

app.post('/login', async (req, res) => {
  const startedAt = Date.now();
  const email = readBodyField(req, 'email').trim().toLowerCase();
  const password = readBodyField(req, 'password');
  const ipAddress = getClientIp(req);

  if (isIpRateLimited(ipAddress)) {
    logEvent(req, {
      action: 'RATE_LIMIT_BLOCK',
      resource: 'auth',
      resourceId: ipAddress,
    });

    await ensureMinimumDuration(startedAt);
    return res.status(429).render('login', {
      form: { email },
      error: 'Prea multe incercari. Incearca din nou peste cateva minute.',
    });
  }

  let user = findUserByEmail(email);

  if (hasLockExpired(user)) {
    user = updateLoginState(user.id, {
      failedLoginAttempts: 0,
      locked: false,
      lockUntil: null,
    });
  }

  const hashToVerify = user ? user.password_hash : dummyPasswordHash;
  const passwordMatches = verifyPassword(password, hashToVerify);

  if (!user) {
    registerFailedIpAttempt(ipAddress);

    logEvent(req, {
      action: 'FAILED_LOGIN_UNKNOWN_USER',
      resource: 'auth',
      resourceId: email,
    });

    await ensureMinimumDuration(startedAt);
    return res.status(401).render('login', {
      form: { email },
      error: INVALID_CREDENTIALS_MESSAGE,
    });
  }

  if (isLocked(user)) {
    registerFailedIpAttempt(ipAddress);

    logEvent(req, {
      userId: user.id,
      action: 'LOCKED_LOGIN_ATTEMPT',
      resource: 'auth',
      resourceId: user.id,
    });

    await ensureMinimumDuration(startedAt);
    return res.status(401).render('login', {
      form: { email },
      error: INVALID_CREDENTIALS_MESSAGE,
    });
  }

  if (!passwordMatches) {
    registerFailedIpAttempt(ipAddress);

    const nextFailedAttempts = Number(user.failed_login_attempts || 0) + 1;
    const shouldLock = nextFailedAttempts >= ACCOUNT_LOCK_THRESHOLD;
    const lockUntil = shouldLock
      ? new Date(Date.now() + ACCOUNT_LOCK_DURATION_MS).toISOString()
      : null;

    user = updateLoginState(user.id, {
      failedLoginAttempts: shouldLock ? 0 : nextFailedAttempts,
      locked: shouldLock,
      lockUntil,
    });

    logEvent(req, {
      userId: user.id,
      action: shouldLock ? 'ACCOUNT_LOCKED' : 'FAILED_LOGIN',
      resource: 'auth',
      resourceId: user.id,
    });

    await ensureMinimumDuration(startedAt);
    return res.status(401).render('login', {
      form: { email },
      error: INVALID_CREDENTIALS_MESSAGE,
    });
  }

  updateLoginState(user.id, {
    failedLoginAttempts: 0,
    locked: false,
    lockUntil: null,
  });
  loginRateLimitStore.delete(ipAddress);

  await regenerateSession(req);
  req.session.userId = user.id;
  req.session.userRole = user.role;

  logEvent(req, {
    userId: user.id,
    action: 'LOGIN',
    resource: 'auth',
    resourceId: user.id,
  });

  await ensureMinimumDuration(startedAt);
  setFlash(req, 'success', 'Autentificare reusita.');
  return res.redirect(303, '/dashboard');
});

app.get('/dashboard', requireAuth, (req, res) => {
  const user = findUserById(req.session.userId);
  const tickets = listTicketsByOwner(user.id);
  const recentLogs = listAuditLogsByUser(user.id, 8);

  res.render('dashboard', {
    user,
    ticketCount: countTicketsByOwner(user.id),
    recentTickets: tickets.slice(0, 5),
    recentLogs,
    sessionInfo: {
      cookieName: 'authx.sid',
      maxAgeMinutes: Math.round(sessionMaxAgeMs / 60000),
    },
  });
});

app.get('/tickets', requireAuth, (req, res) => {
  const user = findUserById(req.session.userId);

  res.render('tickets', {
    form: {
      title: '',
      description: '',
      severity: 'LOW',
    },
    error: null,
    tickets: listTicketsByOwner(user.id),
  });
});

app.post('/tickets', requireAuth, (req, res) => {
  const title = readBodyField(req, 'title').trim();
  const description = readBodyField(req, 'description').trim();
  const severity = readBodyField(req, 'severity', 'LOW').trim().toUpperCase();
  const user = findUserById(req.session.userId);
  const validationError = validateTicketForm({ title, description, severity });

  if (validationError) {
    return res.status(400).render('tickets', {
      form: { title, description, severity },
      error: validationError,
      tickets: listTicketsByOwner(user.id),
    });
  }

  const ticketId = createTicket({
    title,
    description,
    severity: normalizeSeverity(severity),
    ownerId: user.id,
  });

  logEvent(req, {
    userId: user.id,
    action: 'CREATE_TICKET',
    resource: 'ticket',
    resourceId: ticketId,
  });

  setFlash(req, 'success', 'Tichetul a fost creat.');
  return res.redirect(303, '/tickets');
});

app.post('/logout', requireAuth, (req, res) => {
  const userId = req.session.userId;

  logEvent(req, {
    userId,
    action: 'LOGOUT',
    resource: 'auth',
    resourceId: userId,
  });

  req.session.destroy(() => {
    res.clearCookie('authx.sid');
    res.redirect(303, '/login');
  });
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', {
    form: { email: '' },
    error: null,
  });
});

app.post('/forgot-password', (req, res) => {
  const email = readBodyField(req, 'email').trim().toLowerCase();
  const validationError = validateForgotPasswordForm(email);

  if (validationError) {
    return res.status(400).render('forgot-password', {
      form: { email },
      error: validationError,
    });
  }

  const user = findUserByEmail(email);

  if (user) {
    const resetToken = createResetToken();
    saveResetToken(user.id, resetToken.tokenHash, resetToken.expiresAt);

    logEvent(req, {
      userId: user.id,
      action: 'REQUEST_PASSWORD_RESET',
      resource: 'auth',
      resourceId: user.id,
    });

    console.log(
      `Reset link pentru ${user.email}: ${req.protocol}://${req.get('host')}/reset-password/${resetToken.token}`,
    );
  }

  setFlash(req, 'success', RESET_REQUEST_SUCCESS_MESSAGE);
  return res.redirect(303, '/forgot-password');
});

app.get('/reset-password/:token', (req, res) => {
  const tokenHash = hashResetToken(req.params.token);
  let user = findUserByResetTokenHash(tokenHash);

  if (user && user.reset_token_expires_at && Date.parse(user.reset_token_expires_at) <= Date.now()) {
    user = clearResetToken(user.id);
  }

  const isTokenValid =
    user &&
    user.reset_token_hash &&
    user.reset_token_expires_at &&
    Date.parse(user.reset_token_expires_at) > Date.now();

  return res.status(isTokenValid ? 200 : 404).render('reset-password', {
    token: req.params.token,
    user: isTokenValid ? user : null,
    error: isTokenValid ? null : 'Linkul de resetare nu este valid sau a expirat.',
  });
});

app.post('/reset-password/:token', (req, res) => {
  const token = String(req.params.token || '');
  const password = readBodyField(req, 'password');
  const tokenHash = hashResetToken(token);
  let user = findUserByResetTokenHash(tokenHash);

  if (user && user.reset_token_expires_at && Date.parse(user.reset_token_expires_at) <= Date.now()) {
    user = clearResetToken(user.id);
  }

  if (!user || !user.reset_token_hash || !user.reset_token_expires_at) {
    return res.status(404).render('reset-password', {
      token,
      user: null,
      error: 'Linkul de resetare nu este valid sau a expirat.',
    });
  }

  const policyErrors = passwordPolicyErrors(password);

  if (policyErrors.length > 0) {
    return res.status(400).render('reset-password', {
      token,
      user,
      error: policyErrors.join(' '),
    });
  }

  updatePasswordHash(user.id, hashPassword(password));
  clearResetToken(user.id);
  updateLoginState(user.id, {
    failedLoginAttempts: 0,
    locked: false,
    lockUntil: null,
  });

  logEvent(req, {
    userId: user.id,
    action: 'PASSWORD_RESET',
    resource: 'auth',
    resourceId: user.id,
  });

  setFlash(req, 'success', 'Parola a fost schimbata. Te poti autentifica folosind noua parola.');
  return res.redirect(303, '/login');
});

app.listen(PORT, () => {
  if (!process.env.SESSION_SECRET) {
    console.log('SESSION_SECRET nu este setat. A fost generat un secret aleator pentru sesiunea curenta.');
  }

  console.log(`AuthX v2 ruleaza la adresa http://localhost:${PORT}`);
});

module.exports = app;
