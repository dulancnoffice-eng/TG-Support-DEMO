# Deploy OrbitDesk / TG Support Platform on Vercel

This repository can run on Vercel as an Express Function plus static files from `public/`.

## 1. Create/connect PostgreSQL

Use a PostgreSQL provider that Vercel can reach, for example Neon from the Vercel Marketplace, Supabase, or another managed PostgreSQL service.

Copy its PostgreSQL connection string into the Vercel environment variable `DATABASE_URL`.

## 2. Add Vercel environment variables

In Vercel: Project -> Settings -> Environment Variables.

Add these for **Production** (and Preview too if you want preview deployments to work):

```env
DATABASE_URL=postgresql://...
JWT_SECRET=<long-random-secret>
BOT_TOKEN_ENCRYPTION_KEY=<64-hex-character-key>
MASTER_ADMIN_ID=MASTER-ADMIN-001
MASTER_ADMIN_NAME=Master Admin
MASTER_ADMIN_EMAIL=your-email@example.com
MASTER_ADMIN_PASSWORD=<your-private-password-at-least-12-characters>
NODE_ENV=production
```

Generate secrets locally if OpenSSL is available:

```bash
openssl rand -hex 32
openssl rand -base64 48
```

Use the 64-hex-character output for `BOT_TOKEN_ENCRYPTION_KEY`. Use the other random value for `JWT_SECRET`.

Do **not** commit real passwords or database URLs to GitHub.

## 3. Redeploy

Environment variable changes require a new deployment. In Vercel, open Deployments and redeploy the latest production deployment.

## 4. Verify

Open:

```text
https://YOUR-APP.vercel.app/api/health
```

Expected:

```json
{"ok":true,"service":"tg-support-platform","database":"ready","runtime":"vercel"}
```

Then open the root site and sign in with:

```text
ID: MASTER-ADMIN-001
Password: the value you set as MASTER_ADMIN_PASSWORD in Vercel
```

## If `/api/health` says setupRequired

Add every environment variable named in its `missing` array, then redeploy.

## Why the previous package crashed

The previous build was optimized for Render. `render.yaml` is a Render deployment file; Vercel does not use it to create PostgreSQL or populate environment variables. The old server also ran database initialization and `process.exit(1)` at module startup. In a Vercel Function, a missing `DATABASE_URL` or bootstrap secret therefore terminated the function and produced `FUNCTION_INVOCATION_FAILED`.
