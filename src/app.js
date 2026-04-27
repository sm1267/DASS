const path = require('node:path');
const express = require('express');
const session = require('express-session');
const {
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
} = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Intentionally weak v1 session setup so we can harden it in v2.
app.use(
  session({
    name: 'authx.sid',
    secret: 'authx-dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: false,
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7,
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

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    setFlash(req, 'error', 'Trebuie sa te autentifici inainte de a accesa aceasta pagina.');
    return res.redirect('/login');
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
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
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

  const user = createUser({ email, password, role: 'USER' });
  logEvent(req, {
    userId: user.id,
    action: 'REGISTER',
    resource: 'auth',
    resourceId: user.id,
  });

  setFlash(req, 'success', 'Contul a fost creat. Te poti autentifica acum.');
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', {
    form: { email: '' },
    error: null,
  });
});

app.post('/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = findUserByEmail(email);

  if (!user) {
    logEvent(req, {
      action: 'FAILED_LOGIN_UNKNOWN_USER',
      resource: 'auth',
      resourceId: email,
    });

    return res.status(401).render('login', {
      form: { email },
      error: 'Nu exista niciun cont asociat acestui email.',
    });
  }

  if (user.password !== password) {
    logEvent(req, {
      userId: user.id,
      action: 'FAILED_LOGIN_WRONG_PASSWORD',
      resource: 'auth',
      resourceId: user.id,
    });

    return res.status(401).render('login', {
      form: { email },
      error: 'Parola este incorecta.',
    });
  }

  req.session.userId = user.id;
  req.session.userRole = user.role;

  logEvent(req, {
    userId: user.id,
    action: 'LOGIN',
    resource: 'auth',
    resourceId: user.id,
  });

  setFlash(req, 'success', 'Autentificare reusita.');
  return res.redirect('/dashboard');
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
      maxAgeDays: 7,
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
  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();
  const severity = String(req.body.severity || 'LOW').trim().toUpperCase();
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
    severity: ['LOW', 'MED', 'HIGH'].includes(severity) ? severity : 'LOW',
    ownerId: user.id,
  });

  logEvent(req, {
    userId: user.id,
    action: 'CREATE_TICKET',
    resource: 'ticket',
    resourceId: ticketId,
  });

  setFlash(req, 'success', 'Tichetul a fost creat.');
  return res.redirect('/tickets');
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
    res.redirect('/login');
  });
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', {
    form: { email: '' },
    error: null,
    resetPreview: null,
  });
});

app.post('/forgot-password', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = findUserByEmail(email);

  if (!user) {
    logEvent(req, {
      action: 'PASSWORD_RESET_UNKNOWN_USER',
      resource: 'auth',
      resourceId: email,
    });

    return res.status(404).render('forgot-password', {
      form: { email },
      error: 'Nu exista niciun cont asociat acestui email.',
      resetPreview: null,
    });
  }

  // Intentionally predictable and reusable token for v1.
  const resetToken = `reset-${user.id}`;
  saveResetToken(user.id, resetToken);

  logEvent(req, {
    userId: user.id,
    action: 'REQUEST_PASSWORD_RESET',
    resource: 'auth',
    resourceId: user.id,
  });

  return res.render('forgot-password', {
    form: { email },
    error: null,
    resetPreview: {
      token: resetToken,
      url: `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`,
    },
  });
});

app.get('/reset-password/:token', (req, res) => {
  const user = findUserByResetToken(req.params.token);

  res.render('reset-password', {
    token: req.params.token,
    user,
    error: user ? null : 'Linkul de resetare nu este valid.',
  });
});

app.post('/reset-password/:token', (req, res) => {
  const user = findUserByResetToken(req.params.token);
  const password = String(req.body.password || '');

  if (!user) {
    return res.status(404).render('reset-password', {
      token: req.params.token,
      user: null,
      error: 'Linkul de resetare nu este valid.',
    });
  }

  if (!password) {
    return res.status(400).render('reset-password', {
      token: req.params.token,
      user,
      error: 'Este necesara o parola noua.',
    });
  }

  updatePassword(user.id, password);

  logEvent(req, {
    userId: user.id,
    action: 'PASSWORD_RESET',
    resource: 'auth',
    resourceId: user.id,
  });

  setFlash(req, 'success', 'Parola a fost schimbata. Te poti autentifica folosind noua parola.');
  return res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`AuthX v1 ruleaza la adresa http://localhost:${PORT}`);
});

module.exports = app;
