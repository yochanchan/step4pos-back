## POS + Auth Stack Overview

This repository contains two applications:

- `pos-fastapi/`  FastAPI backend with JWT auth, Argon2 password hashing, Azure Database for MySQL (async SQLAlchemy), and Google OAuth 2.0 (OIDC) integration.
- `sample-next/`  Next.js (App Router, TypeScript) frontend that consumes the backend APIs from the `/login` page.

Each project maintains its own dependencies and tooling but they are expected to work together through the APIs documented below.

---

## Backend (`pos-fastapi/`)

### Requirements

- Python 3.11+
- MySQL 8 (Azure Database for MySQL compatible)
- Pip and virtual environment tooling

### Installation

```
cd pos-fastapi
python -m venv env
./env/Scripts/activate  # Windows
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file (a sample was provided) containing:

```
DATABASE_URL="mysql+asyncmy://USER:PASSWORD@HOST:3306/DATABASE?charset=utf8mb4"
# optionally use legacy DB_* vars if DATABASE_URL is omitted
# DB_HOST=..., DB_USER=..., etc.

JWT_SECRET="a long random string"
ACCESS_TOKEN_TTL_MIN=15
REFRESH_TOKEN_TTL_DAY=14

CORS_ORIGINS="http://localhost:3000"

REFRESH_COOKIE_NAME="pos_refresh_token"
REFRESH_COOKIE_SECURE=true
REFRESH_COOKIE_PATH="/"
REFRESH_COOKIE_SAMESITE="lax"
REFRESH_COOKIE_DOMAIN=

# Google OAuth config
GOOGLE_CLIENT_ID="...apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="..."
GOOGLE_REDIRECT_URI="http://localhost:8000/auth/google/callback"
# GOOGLE_COOKIE_SECURE=false  # optional: override auto-detection for non-HTTPS local testing
```

Authorized redirect URIs in Google Cloud Console:

- http://localhost:8000/auth/google/callback
- https://app-002-gen10-step3-1-py-oshima31.azurewebsites.net/auth/google/callback

> NOTE: To use Azure TLS certificates, set `SSL_CA_PATH` to the CA chain file and ensure the file is mounted inside the container/host.

### Database tables

The service expects the following tables:

- `users`  local accounts and shared profile data
- `auth_identities`  Google and future social provider identities, foreign key to `users`
- `refresh_tokens`  hashed refresh tokens with reuse detection
- `item_code`, `deal`, `deal_detail`  legacy POS tables still consumed via `app/api/routes/legacy_pos.py`

The full schemas are captured in `app/db/models/`.

### Running the server

```
cd pos-fastapi
uvicorn app.main:create_app --factory --reload
```

### Code structure (MVP)

- `app/main.py` creates the FastAPI instance and wires CORS, error handlers, and routers.
- `app/services/auth.py` bundles password hashing, JWT issuance, refresh tokens, and signup/login helpers.
- Legacy POS helpers stay in `app/services/pos_legacy.py`; Google OAuth helpers live in `app/services/google_oauth.py`.

### Running tests

```
cd pos-fastapi
./env/Scripts/activate
python -m pytest -q
```

> Tests currently target SQLite (aiosqlite) for speed; production uses MySQL. Verify against staging MySQL before release.

### API summary

| Method | Path                      | Description                                    |
| ------ | ------------------------- | ---------------------------------------------- |
| POST   | `/auth/signup`            | Email/password signup, returns access token    |
| POST   | `/auth/login`             | Email/password login, returns access token     |
| POST   | `/auth/refresh`           | Rotate refresh token via HttpOnly cookie       |
| POST   | `/auth/logout`            | Revoke refresh token and clear cookie          |
| GET    | `/auth/me`                | Return authenticated user (Bearer JWT)         |
| GET    | `/auth/google/login`      | Redirect to Google authorization endpoint      |
| GET    | `/auth/google/callback`   | Handle Google OIDC callback, issue new tokens  |
| GET    | `/item?prd_code=xxx`      | Lookup product in legacy POS tables            |
| POST   | `/deal`                   | Insert purchase + details into legacy POS      |

---

## Frontend (`sample-next/`)

### Requirements

- Node.js 18+ (Next.js 15 requires Node >=18.17)
- npm (or pnpm/yarn, adjust commands accordingly)

### Installation

```
cd sample-next
npm install
```

### Environment Variables

Create `.env.local` with:

```
NEXT_PUBLIC_API_ENDPOINT="http://localhost:8000"
```

Ensure the origin matches what the backend allows for CORS.

### Development

```
cd sample-next
npm run dev
```

### Login page behaviour

- Email/password login and signup use `/auth/*` endpoints.
- Automatic refresh token handling is implemented in `src/lib/api.ts`.
- The Google login button navigates to `/auth/google/login?redirect=/`.
- After login/signup/social login, the app redirects to `/`.

---

## Integration Notes

- Configure CORS to allow credentials and set `REFRESH_COOKIE_*` to align with the frontend domain.
- The frontend relies on HttpOnly refresh cookies; ensure HTTPS and SameSite in production.
- For Azure MySQL, use the provided DigiCert CA and set `SSL_CA_PATH`.
---

## Security & Secrets

- Do not commit real secrets. .env and .env.* are ignored; use .env.example as a template.
- If secrets were ever pushed, rotate them (DB password, JWT_SECRET, OAuth secrets) and purge history if needed (e.g., git filter-repo).
- Configure CI/CD with GitHub Actions Secrets (e.g., publish profiles, database credentials).
- Enable GitHub secret scanning or add a pre-commit hook (e.g., gitleaks) for local checks.
- TLS CA: DigiCertGlobalRootG2.crt.pem is a public root CA and is intentionally tracked. For other certs/keys, do not commit them; provide paths via env (e.g., SSL_CA_PATH).
