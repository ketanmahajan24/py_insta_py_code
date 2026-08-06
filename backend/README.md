# Password Reset/Change API (practice backend)

A small Flask API to pair with the `reset-password-clone.html` front end.
Built for a skills-practice/portfolio task — read the code, it's meant to
be readable end to end.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Server runs at `http://localhost:5000`. A demo account is seeded on startup:

- username: `apnibaatein.22`
- password: `Ketan@123`

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | – | Liveness check |
| POST | `/api/auth/register` | – | `{username, email, password}` |
| POST | `/api/auth/login` | – | `{username, password}` → sets session cookie |
| POST | `/api/auth/logout` | – | Clears session |
| POST | `/api/password/change` | session | `{oldPassword, newPassword, confirmPassword, logoutEverywhere}` |
| POST | `/api/password/forgot` | – | `{email}` → prints a reset link to the console |
| GET | `/api/password/reset/<uidb36>/<token>` | – | Checks if a reset link is still valid |
| POST | `/api/password/reset/<uidb36>/<token>` | – | `{newPassword, confirmPassword}` |

## How it maps to the front end

- The **Old password + New password + Confirm password** form → `POST /api/password/change` (requires being logged in first via `/api/auth/login`).
- The reset-link URL pattern in the original screenshot (`?uidb36=...&token=...`) → `/api/password/reset/<uidb36>/<token>`, issued by `POST /api/password/forgot`.
- The **"Log out everywhere else"** checkbox → pass `logoutEverywhere: true` in the change-password call. It bumps a `session_version` counter server-side. Full multi-device enforcement needs token-based auth (see notes below) — this endpoint lays the groundwork but doesn't have other devices to kick out yet.

## Wiring up the HTML front end

The front end currently does all validation locally and never calls a
server. To connect it:

1. Serve the HTML file over HTTP instead of opening it as a `file://` — e.g. `python -m http.server 5500` from the folder it's in — so cookies and CORS work normally.
2. In the front end's `<script>`, replace the local-only validation in the `submit` handler with a `fetch()` call, e.g.:

```js
const res = await fetch('http://localhost:5000/api/password/change', {
  method: 'POST',
  credentials: 'include', // sends the session cookie
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    oldPassword: oldPasswordInput.value,
    newPassword: passwordInput.value,
    confirmPassword: confirmInput.value,
    logoutEverywhere: document.getElementById('logoutEverywhere').checked,
  }),
});
const data = await res.json();
if (!res.ok) {
  // data.field tells you which input to show the error on, data.error is the message
} else {
  // show the success state
}
```

Happy to wire this up directly if you want the front end actually talking
to this API instead of validating locally — just ask.

## What's intentionally simplified (and what a real version needs)

This is scoped for learning, not production. If you extend it:

- **Storage** — `USERS` is a plain in-memory dict; it resets every time
  the server restarts. Swap it for SQLite/Postgres via SQLAlchemy.
- **Secret key** — `SECRET_KEY` defaults to a placeholder. Set a real
  one via the `SECRET_KEY` environment variable before deploying anywhere.
- **Email** — reset links are printed to the console, not emailed. Wire
  up a real provider (SES, SendGrid, Postmark, etc.) in `forgot_password()`.
- **Password hashing** — uses Werkzeug's built-in `scrypt`, which is fine
  for practice. For production, argon2 (via `argon2-cffi`) is the current
  best-practice choice.
- **HTTPS/cookies** — `SESSION_COOKIE_SECURE` is `False` for local HTTP
  testing. Set it `True` (and serve over HTTPS) in production, or the
  session cookie is sent in the clear.
- **"Logout everywhere"** — real enforcement needs either a server-side
  session store (so you can list and revoke a user's other sessions) or
  JWT-based auth with a version claim checked on every request.
- **CORS** — origins are hardcoded to common local dev ports in
  `FRONTEND_ORIGINS`. Update this (or set the env var) for wherever you
  actually host the front end.
