# AuthX v1

AuthX v1 is an intentionally vulnerable authentication demo built for the DASS course project. It covers registration, login, logout, and password reset using `Express`, `express-session`, `EJS`, and SQLite through Node's built-in `node:sqlite` module.

## What v1 includes

- user registration saved in SQLite
- login with server-side sessions
- logout
- forgot/reset password flow
- dashboard for authenticated users

## Weaknesses intentionally left in place

The application UI does not advertise these weaknesses directly; they are documented here for the project and for the later v2 hardening step.

- passwords are stored in plaintext
- weak password policy
- register only checks that email and password are present
- different login errors for nonexistent user vs wrong password
- no brute-force protection or rate limiting
- predictable and reusable reset tokens
- incomplete session cookie settings

## Local run

If `npm` is not recognized in the current terminal, open a new terminal window first.

```bash
npm install
npm start
```

Open `http://localhost:3000`.

## Data

- SQLite database file: `data/authx-v1.db`
- The app creates the database automatically on first run.

## Suggested PoCs for v1

- register with a very weak password such as `123`
- attempt login with an unknown email and then a known email + wrong password
- inspect the `users` table and confirm passwords are readable
- generate a reset link twice for the same account and observe the same token
- reuse the same reset token multiple times
