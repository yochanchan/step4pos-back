## POS + Auth Stack Overview

This repository contains two applications:

- `pos-fastapi/` — FastAPI backend with JWT auth, Argon2 password hashing, Azure Database for MySQL (async SQLAlchemy), and LINE OIDC integration.
- `sample-next/` — Next.js (App Router, TypeScript) frontend that consumes the backend APIs from the `/login` page.

Each project maintains its own dependencies and tooling but they are expected to work together through the APIs documented below.

---

## Backend (`pos-fastapi/`)

### Requirements

- Python 3.11+
- MySQL 8 (Azure Database for MySQL compatible)
- Pip and virtual environment tooling

### Installation

```bash
cd pos-fastapi
python -m venv env
.\env\Scripts\activate
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file (a sample was provided) containing:

```bash
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
REFRESH_COOKIE_DOMAIN= # optional

# LINE OIDC config
OIDC_LINE_CLIENT_ID="..."
OIDC_LINE_CLIENT_SECRET="..."
OIDC_LINE_REDIRECT_URI="https://your-frontend-domain/auth/line/callback"
```

> NOTE: To use Azure TLS certificates, set `SSL_CA_PATH` to the CA chain file and ensure the file is mounted inside the container/host.

### Database tables

The service expects the following tables:

- `users` — local accounts and shared profile data
- `auth_identities` — line and future social provider identities, foreign key to `users`
- `refresh_tokens` — hashed refresh tokens with reuse detection
- `item_code`, `deal`, `deal_detail` — legacy POS tables still consumed via `app/api/routes/legacy_pos.py`

The full schemas are captured in `app/db/models/`.

### Running the server

```bash
cd pos-fastapi
uvicorn app.main:create_app --factory --reload
```

### Running tests

```bash
cd pos-fastapi
.\env\Scripts\activate
python -m pytest -q
```

> Tests currently target an in-memory SQLite database with SQLAlchemy’s async engine; production uses MySQL. Be sure to run integration tests against MySQL before deployment.

### API summary

| Method | Path                  | Description                                    |
| ------ | --------------------- | ---------------------------------------------- |
| POST   | `/auth/signup`        | Email/password signup, returns access token    |
| POST   | `/auth/login`         | Email/password login, returns access token     |
| POST   | `/auth/refresh`       | Rotate refresh token via HttpOnly cookie       |
| POST   | `/auth/logout`        | Revoke refresh token and clear cookie          |
| GET    | `/auth/me`            | Return authenticated user (Bearer JWT)         |
| GET    | `/auth/line/login`    | Redirect to LINE authorization endpoint        |
| GET    | `/auth/line/callback` | Handle LINE OIDC callback, issue new tokens    |
| GET    | `/item?prd_code=xxx`  | Lookup product in legacy POS tables            |
| POST   | `/deal`               | Insert purchase + details into legacy POS      |

---

## Frontend (`sample-next/`)

### Requirements

- Node.js 18+ (Next.js 15 requires Node >=18.17)
- npm (or pnpm/yarn, adjust commands accordingly)

### Installation

```bash
cd sample-next
npm install
```

### Environment Variables

Create `.env.local` with:

```bash
NEXT_PUBLIC_API_ENDPOINT="http://localhost:8000"
```

Ensure the origin matches what the backend allows for CORS.

### Development

```bash
cd sample-next
npm run dev
```

### Linting

```bash
npm run lint
```

### Login page behaviour

- Email/password login and signup (zs validated) communicate with the `/auth` endpoints.
- Automatic refresh token handling is implemented in `src/lib/api.ts`.
- The LINE login button navigates to the backend redirect `/auth/line/login`.
- When already logged in, the header shows the current user and provides a logout button.

---

## Integration Notes

- Configure CORS to allow credentials and set `REFRESH_COOKIE_*` to align with the frontend domain.
- The frontend relies exclusively on HttpOnly refresh cookies; make sure HTTPS and SameSite settings are correct in production.
- For MySQL deployments on Azure, load the DigiCert CA (see `pos-fastapi/DigiCertGlobalRootG2.crt.pem`) and point `SSL_CA_PATH` accordingly.
- LINE OIDC requires redirect URL matching and verified channel credentials.

### Suggested further work

- Add production-ready logging & monitoring hooks for authentication events.
- Introduce e2e smoke tests running against a staging MySQL database.
