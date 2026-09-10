# OrbitDesk / TG Support Platform
## Vercel deployment

If you are deploying this repository on **Vercel**, read [`VERCEL-DEPLOY.md`](./VERCEL-DEPLOY.md) first. Vercel does not read `render.yaml`, so PostgreSQL and the required environment variables must be configured in Vercel.


A GitHub-ready starter for a SaleSmartly-style customer service console, built from the supplied Telegram customer service UI and expanded around a hierarchical permission model.

## Account structure

```text
MASTER_ADMIN (global)
└── Workspace
    ├── WORKSPACE_ADMIN 1
    │   ├── TEAM_ADMIN / AGENT 1
    │   ├── TEAM_ADMIN / AGENT 2
    │   ├── TEAM_ADMIN / AGENT 3
    │   └── TEAM_ADMIN / AGENT 4
    ├── WORKSPACE_ADMIN 2
    │   └── up to 3–4 child IDs
    └── WORKSPACE_ADMIN 3
        └── up to 3–4 child IDs
```

Default limits are configurable per workspace.

## What is included

- Master Admin bootstrap ID controlled by environment variables.
- Workspace creation and workspace switching.
- Hierarchical user accounts with `parent_user_id`.
- Role-based access control: `MASTER_ADMIN`, `WORKSPACE_ADMIN`, `TEAM_ADMIN`, `AGENT`, `VIEWER`.
- Per-workspace Admin limits and per-Admin child account limits.
- Telegram bot account records.
- AES-256-GCM encryption for bot tokens at rest.
- Bot-to-user assignments with read/reply/manage permissions.
- Customer, conversation, message and audit log database tables.
- JWT login.
- Rate limiting and common HTTP security headers.
- Production backend API plus a GitHub Pages-compatible frontend demo mode.
- GitHub Actions workflow for publishing the frontend demo to GitHub Pages.
- Dockerfile for backend deployment.
- Unified inbox UI, customer panel, analytics placeholders, workspace/team/bot management screens.

## Important deployment point

GitHub Pages can only host the frontend demo. It **cannot safely run authentication, store Telegram bot tokens, receive Telegram webhooks, enforce permissions, or keep PostgreSQL data**.

For a practical deployment, keep the code in GitHub and deploy the Node backend to a server platform such as Render/Railway/Fly.io/AWS/DigitalOcean, with PostgreSQL. The included `render.yaml` is a starting point for Render.

## Local setup

1. Create a PostgreSQL database.
2. Run the schema:

```bash
psql "$DATABASE_URL" -f sql/schema.sql
```

3. Copy environment settings:

```bash
cp .env.example .env
```

4. Set secure values in `.env`.

5. Install and run:

```bash
npm install
npm start
```

6. Open `http://localhost:3000`.

On first start, if no Master Admin exists and the bootstrap environment fields are configured, the server creates:

- ID: value from `MASTER_ADMIN_ID`
- Name: value from `MASTER_ADMIN_NAME`
- Login email: value from `MASTER_ADMIN_EMAIL`
- Password: value from `MASTER_ADMIN_PASSWORD`

Change the bootstrap password immediately and remove `MASTER_ADMIN_PASSWORD` from the environment after initial setup.

## API routes in this starter

```text
POST /api/auth/login
GET  /api/me
GET  /api/workspaces
POST /api/workspaces
GET  /api/users
POST /api/users
GET  /api/bots
POST /api/bots
POST /api/bots/:botId/assign
GET  /api/audit
GET  /api/health
```

## Permission model

| Capability | Master Admin | Workspace Admin | Team Admin | Agent |
|---|---|---|---|---|
| Create workspace | Global | No | No | No |
| Create child accounts | Global | Own workspace | Own branch | No |
| Connect bot token | Global | Own workspace | No | No |
| Assign bot access | Global | Workspace | Own branch | No |
| Reply to chats | Yes | Yes | Yes | Assigned bots only |
| View analytics | Global | Workspace | Team | Self / limited |
| View audit log | Global | Workspace | No | No |

## Production modules still needed

This starter establishes the tenancy and RBAC foundation. A SaleSmartly-class production product still needs:

1. **Telegram integration service**
   - webhook verification and update ingestion
   - send message/media endpoints
   - message deduplication
   - retries and dead-letter handling
   - token validation

2. **Realtime inbox**
   - WebSocket or Server-Sent Events
   - presence / online state
   - unread counters
   - typing events
   - agent assignment updates

3. **Conversation routing**
   - round-robin / least-loaded / sticky ownership
   - queue priorities
   - reception limits per agent
   - working hours and offline routing

4. **Security**
   - refresh-token or secure cookie session model
   - password reset and forced password change
   - 2FA for Master/Workspace Admins
   - CSRF protection if cookie auth is used
   - IP/device/session controls
   - secret rotation
   - encrypted backups

5. **Customer CRM**
   - custom fields
   - tags and segments
   - internal notes
   - merge duplicate customers
   - full conversation timeline

6. **Automation / AI**
   - rules engine
   - auto replies
   - AI reply suggestions
   - human handoff
   - translation
   - prompt/version management
   - safety and confidence thresholds

7. **Supervisor features**
   - QA review
   - conversation takeover
   - internal comments / mentions
   - SLA alerts
   - performance scorecards

8. **Analytics**
   - first response time
   - resolution time
   - missed conversations
   - agent utilization
   - bot containment and handoff rate
   - CSAT
   - per-workspace / per-bot / per-agent drilldown

9. **Operations**
   - Dockerfile
   - staging + production environments
   - GitHub Actions tests/deploy
   - migrations
   - logs/metrics/error tracking
   - database backups

## Telegram architecture recommendation

```text
Telegram
   ↓ webhook
Public API / Webhook Receiver
   ↓
Message Ingestion Queue
   ↓
Conversation Service ── PostgreSQL
   ├── Routing Service
   ├── Automation / AI Service
   └── Realtime Gateway → Browser Agents

Browser Agent
   ↓ authenticated action
Backend Authorization
   ↓ workspace + bot assignment check
Telegram Send API
```

Agents should never call Telegram directly and should never receive a bot token.

## Suggested next repository milestone

The next coding milestone should be Telegram webhook ingestion + real conversation/message APIs + WebSocket/SSE updates. That converts the current management foundation into a genuinely live support console.


## First production deployment

The server now automatically applies `sql/schema.sql` on startup. On a fresh database it then creates the Master Admin.

Required deployment environment values:

```env
MASTER_ADMIN_ID=MASTER-ADMIN-001
MASTER_ADMIN_NAME=Master Admin
MASTER_ADMIN_EMAIL=your-real-email@example.com
MASTER_ADMIN_PASSWORD=use-a-strong-password-at-least-12-characters
```

`render.yaml` marks the email and password as `sync: false`, so Render will ask you to provide them when creating the Blueprint. Do not commit the real password to GitHub.