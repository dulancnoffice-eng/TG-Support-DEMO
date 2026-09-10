require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { z } = require('zod');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 10_000
});
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const MASTER_ADMIN_ID = process.env.MASTER_ADMIN_ID || 'MASTER-ADMIN-001';

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
if (process.env.APP_ORIGIN) app.use(cors({ origin: process.env.APP_ORIGIN, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 240 }));
app.use(express.static(path.join(__dirname, 'public')));

const ROLES = ['MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN','AGENT','VIEWER'];
const CREATE_MATRIX = {
  MASTER_ADMIN: ['WORKSPACE_ADMIN','TEAM_ADMIN','AGENT','VIEWER'],
  WORKSPACE_ADMIN: ['TEAM_ADMIN','AGENT','VIEWER'],
  TEAM_ADMIN: ['AGENT','VIEWER'],
  AGENT: [],
  VIEWER: []
};

function newId(prefix='USR') {
  return `${prefix}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}
function getEncryptionKey() {
  const raw = process.env.BOT_TOKEN_ENCRYPTION_KEY || '';
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
  return crypto.createHash('sha256').update(raw || 'dev-only-bot-key').digest();
}
function encryptToken(token) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext: encrypted.toString('base64'), iv: iv.toString('base64'), tag: tag.toString('base64') };
}
function signUser(user) {
  return jwt.sign({ sub: user.id, role: user.role, workspaceId: user.workspace_id || null }, JWT_SECRET, { expiresIn: '12h' });
}
async function audit(req, action, entityType, entityId, details = {}) {
  try {
    await pool.query(
      `INSERT INTO audit_logs(workspace_id, actor_user_id, action, entity_type, entity_id, details, ip_address)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [req.user?.workspace_id || null, req.user?.id || null, action, entityType, entityId ? String(entityId) : null, JSON.stringify(details), req.ip || null]
    );
  } catch (e) {
    console.error('audit failed:', e.message);
  }
}
async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT id, workspace_id, parent_user_id, role, name, email, username, status FROM users WHERE id=$1', [payload.sub]);
    if (!rows[0] || rows[0].status !== 'active') return res.status(401).json({ error: 'Account unavailable' });
    req.user = rows[0];
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}
function allow(...roles) {
  return (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Permission denied' });
}
function workspaceScope(req, requestedWorkspaceId) {
  if (req.user.role === 'MASTER_ADMIN') return requestedWorkspaceId || null;
  return req.user.workspace_id;
}

const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);

let readinessPromise = null;

function requiredEnvStatus() {
  const required = ['DATABASE_URL','JWT_SECRET','BOT_TOKEN_ENCRYPTION_KEY','MASTER_ADMIN_EMAIL','MASTER_ADMIN_PASSWORD'];
  return required.filter(key => !process.env[key]);
}

async function ensureReady() {
  if (!readinessPromise) {
    readinessPromise = (async () => {
      const missing = requiredEnvStatus();
      if (missing.length) {
        const err = new Error(`Missing environment variables: ${missing.join(', ')}`);
        err.code = 'SETUP_REQUIRED';
        err.missing = missing;
        throw err;
      }
      await initializeDatabase();
      await bootstrapMaster();
      return true;
    })().catch(err => {
      readinessPromise = null;
      throw err;
    });
  }
  return readinessPromise;
}

app.get('/api/health', async (req,res) => {
  try {
    await ensureReady();
    res.json({ ok: true, service: 'tg-support-platform', database: 'ready', runtime: process.env.VERCEL ? 'vercel' : 'node' });
  } catch (err) {
    console.error('Health/readiness failed:', err.message);
    if (err.code === 'SETUP_REQUIRED') {
      return res.status(503).json({ ok:false, setupRequired:true, error:'Deployment environment is incomplete', missing:err.missing });
    }
    res.status(503).json({ ok:false, setupRequired:false, error:'Database initialization failed' });
  }
});

app.use('/api', async (req,res,next) => {
  if (req.path === '/health') return next();
  try {
    await ensureReady();
    next();
  } catch (err) {
    console.error('API readiness failed:', err.message);
    if (err.code === 'SETUP_REQUIRED') {
      return res.status(503).json({ error:'Backend setup incomplete', missing:err.missing });
    }
    return res.status(503).json({ error:'Database is unavailable or initialization failed' });
  }
});

app.post('/api/auth/login', asyncRoute(async (req,res) => {
  const input = z.object({ login: z.string().min(1), password: z.string().min(1) }).parse(req.body);
  const { rows } = await pool.query(
    `SELECT * FROM users WHERE lower(coalesce(email,''))=lower($1) OR lower(coalesce(username,''))=lower($1) OR id=$1 LIMIT 1`,
    [input.login]
  );
  const user = rows[0];
  if (!user || !(await bcrypt.compare(input.password, user.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });
  await pool.query('UPDATE users SET last_login_at=now() WHERE id=$1', [user.id]);
  res.json({ token: signUser(user), user: { id:user.id, name:user.name, role:user.role, workspaceId:user.workspace_id } });
}));

app.get('/api/me', auth, (req,res) => res.json({ user: req.user }));

app.get('/api/workspaces', auth, asyncRoute(async (req,res) => {
  if (req.user.role === 'MASTER_ADMIN') {
    const { rows } = await pool.query(`SELECT w.*, count(u.id) FILTER (WHERE u.role='WORKSPACE_ADMIN')::int AS admin_count FROM workspaces w LEFT JOIN users u ON u.workspace_id=w.id GROUP BY w.id ORDER BY w.created_at DESC`);
    return res.json({ items: rows });
  }
  const { rows } = await pool.query('SELECT * FROM workspaces WHERE id=$1', [req.user.workspace_id]);
  res.json({ items: rows });
}));

app.post('/api/workspaces', auth, allow('MASTER_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({
    name: z.string().min(2).max(120),
    slug: z.string().regex(/^[a-z0-9-]{2,80}$/),
    maxWorkspaceAdmins: z.number().int().min(1).max(20).default(3),
    maxChildrenPerAdmin: z.number().int().min(1).max(50).default(4)
  }).parse(req.body);
  const { rows } = await pool.query(
    `INSERT INTO workspaces(name,slug,max_workspace_admins,max_children_per_admin,created_by) VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [input.name,input.slug,input.maxWorkspaceAdmins,input.maxChildrenPerAdmin,req.user.id]
  );
  await audit(req,'workspace.create','workspace',rows[0].id,{name:input.name});
  res.status(201).json({ item: rows[0] });
}));

app.get('/api/users', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws && req.user.role !== 'MASTER_ADMIN') return res.json({ items: [] });
  const params = [];
  let where = '';
  if (ws) { params.push(ws); where = 'WHERE workspace_id=$1'; }
  const { rows } = await pool.query(`SELECT id,workspace_id,parent_user_id,role,name,email,username,status,last_login_at,created_at FROM users ${where} ORDER BY created_at`, params);
  res.json({ items: rows });
}));

app.post('/api/users', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({
    workspaceId: z.string().uuid().optional(),
    parentUserId: z.string().max(64).optional(),
    role: z.enum(ROLES),
    name: z.string().min(2).max(120),
    email: z.string().email().optional(),
    username: z.string().min(3).max(80).optional(),
    password: z.string().min(8).max(128)
  }).parse(req.body);
  if (!CREATE_MATRIX[req.user.role].includes(input.role)) return res.status(403).json({ error: `Your role cannot create ${input.role}` });
  const ws = workspaceScope(req, input.workspaceId);
  if (!ws) return res.status(400).json({ error: 'workspaceId is required' });

  if (input.role === 'WORKSPACE_ADMIN') {
    const { rows:[workspace] } = await pool.query('SELECT max_workspace_admins FROM workspaces WHERE id=$1', [ws]);
    if (!workspace) return res.status(404).json({ error: 'Workspace not found' });
    const { rows:[count] } = await pool.query(`SELECT count(*)::int AS n FROM users WHERE workspace_id=$1 AND role='WORKSPACE_ADMIN' AND status='active'`, [ws]);
    if (count.n >= workspace.max_workspace_admins) return res.status(409).json({ error: 'Workspace admin limit reached' });
  }

  let parentId = input.parentUserId || (req.user.role === 'MASTER_ADMIN' ? null : req.user.id);
  if (req.user.role === 'TEAM_ADMIN') parentId = req.user.id;
  if (parentId) {
    const { rows:[parent] } = await pool.query('SELECT id,workspace_id,role FROM users WHERE id=$1', [parentId]);
    if (!parent || String(parent.workspace_id) !== String(ws)) return res.status(400).json({ error: 'Invalid parent account' });
    const { rows:[workspace] } = await pool.query('SELECT max_children_per_admin FROM workspaces WHERE id=$1', [ws]);
    const { rows:[count] } = await pool.query(`SELECT count(*)::int AS n FROM users WHERE parent_user_id=$1 AND status='active'`, [parentId]);
    if (count.n >= workspace.max_children_per_admin) return res.status(409).json({ error: 'Child account limit reached for this admin' });
  }

  const id = newId(input.role === 'WORKSPACE_ADMIN' ? 'ADM' : input.role === 'TEAM_ADMIN' ? 'TEAM' : 'USR');
  const hash = await bcrypt.hash(input.password, 12);
  const { rows } = await pool.query(
    `INSERT INTO users(id,workspace_id,parent_user_id,role,name,email,username,password_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING id,workspace_id,parent_user_id,role,name,email,username,status,created_at`,
    [id,ws,parentId,input.role,input.name,input.email||null,input.username||null,hash]
  );
  await audit(req,'user.create','user',id,{role:input.role,parentUserId:parentId});
  res.status(201).json({ item: rows[0] });
}));

app.get('/api/bots', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws) return res.json({ items: [] });
  if (['MASTER_ADMIN','WORKSPACE_ADMIN'].includes(req.user.role)) {
    const { rows } = await pool.query(`SELECT id,workspace_id,platform,name,external_bot_id,status,auto_reply,created_at FROM bots WHERE workspace_id=$1 ORDER BY created_at DESC`, [ws]);
    return res.json({ items: rows });
  }
  const { rows } = await pool.query(
    `SELECT b.id,b.workspace_id,b.platform,b.name,b.external_bot_id,b.status,b.auto_reply,b.created_at,ba.can_read,ba.can_reply,ba.can_manage
     FROM bots b JOIN bot_assignments ba ON ba.bot_id=b.id WHERE b.workspace_id=$1 AND ba.user_id=$2 ORDER BY b.created_at DESC`,
    [ws,req.user.id]
  );
  res.json({ items: rows });
}));

app.post('/api/bots', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({
    workspaceId: z.string().uuid().optional(),
    platform: z.enum(['telegram']).default('telegram'),
    name: z.string().min(2).max(120),
    externalBotId: z.string().max(120).optional(),
    token: z.string().min(20),
    autoReply: z.boolean().default(false)
  }).parse(req.body);
  const ws = workspaceScope(req, input.workspaceId);
  if (!ws) return res.status(400).json({ error: 'workspaceId is required' });
  const enc = encryptToken(input.token);
  const { rows } = await pool.query(
    `INSERT INTO bots(workspace_id,platform,name,external_bot_id,token_ciphertext,token_iv,token_tag,auto_reply,created_by)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING id,workspace_id,platform,name,external_bot_id,status,auto_reply,created_at`,
    [ws,input.platform,input.name,input.externalBotId||null,enc.ciphertext,enc.iv,enc.tag,input.autoReply,req.user.id]
  );
  await audit(req,'bot.create','bot',rows[0].id,{platform:input.platform,name:input.name});
  res.status(201).json({ item: rows[0] });
}));

app.post('/api/bots/:botId/assign', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({ userId: z.string().min(1), canRead:z.boolean().default(true), canReply:z.boolean().default(true), canManage:z.boolean().default(false) }).parse(req.body);
  const { rows:[bot] } = await pool.query('SELECT id,workspace_id FROM bots WHERE id=$1', [req.params.botId]);
  const { rows:[target] } = await pool.query('SELECT id,workspace_id,parent_user_id,role FROM users WHERE id=$1', [input.userId]);
  if (!bot || !target || String(bot.workspace_id) !== String(target.workspace_id)) return res.status(404).json({ error: 'Bot or user not found in same workspace' });
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id) !== String(bot.workspace_id)) return res.status(403).json({ error: 'Cross-workspace assignment denied' });
  if (req.user.role === 'TEAM_ADMIN' && target.parent_user_id !== req.user.id && target.id !== req.user.id) return res.status(403).json({ error: 'Team admin can assign only within own branch' });
  await pool.query(
    `INSERT INTO bot_assignments(bot_id,user_id,can_read,can_reply,can_manage,assigned_by)
     VALUES($1,$2,$3,$4,$5,$6)
     ON CONFLICT(bot_id,user_id) DO UPDATE SET can_read=excluded.can_read,can_reply=excluded.can_reply,can_manage=excluded.can_manage,assigned_by=excluded.assigned_by,assigned_at=now()`,
    [bot.id,target.id,input.canRead,input.canReply,input.canManage,req.user.id]
  );
  await audit(req,'bot.assign','bot',bot.id,{userId:target.id,canRead:input.canRead,canReply:input.canReply,canManage:input.canManage});
  res.json({ ok:true });
}));

app.get('/api/audit', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN'), asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  const params = [];
  let where = '';
  if (ws) { params.push(ws); where='WHERE a.workspace_id=$1'; }
  const { rows } = await pool.query(
    `SELECT a.id,a.workspace_id,a.actor_user_id,u.name AS actor_name,a.action,a.entity_type,a.entity_id,a.details,a.created_at
     FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id ${where} ORDER BY a.created_at DESC LIMIT 200`, params
  );
  res.json({ items: rows });
}));

async function initializeDatabase() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');
  const schemaPath = path.join(__dirname, 'sql', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(schema);
  console.log('Database schema is ready');
}

async function bootstrapMaster() {
  const { rows } = await pool.query(`SELECT id FROM users WHERE role='MASTER_ADMIN' LIMIT 1`);
  if (rows[0]) {
    console.log(`Master Admin already exists: ${rows[0].id}`);
    return;
  }

  const email = process.env.MASTER_ADMIN_EMAIL;
  const password = process.env.MASTER_ADMIN_PASSWORD;
  const name = process.env.MASTER_ADMIN_NAME || 'Master Admin';
  if (!email || !password) {
    throw new Error('No Master Admin exists. Set MASTER_ADMIN_EMAIL and MASTER_ADMIN_PASSWORD in the deployment environment.');
  }
  if (password.length < 12) {
    throw new Error('MASTER_ADMIN_PASSWORD must be at least 12 characters');
  }

  const hash = await bcrypt.hash(password, 12);
  const result = await pool.query(
    `INSERT INTO users(id,workspace_id,parent_user_id,role,name,email,username,password_hash)
     VALUES($1,NULL,NULL,'MASTER_ADMIN',$2,$3,$4,$5)
     ON CONFLICT (id) DO NOTHING
     RETURNING id`,
    [MASTER_ADMIN_ID,name,email,MASTER_ADMIN_ID,hash]
  );
  if (result.rows[0]) console.log(`Bootstrapped Master Admin: ${MASTER_ADMIN_ID}`);
  else console.log(`Master Admin already created by another instance: ${MASTER_ADMIN_ID}`);
}

// On Vercel, files in /public are served by Vercel's CDN. Redirect browser routes
// to the static app instead of depending on express.static/sendFile inside the function.
app.get('*', (req,res) => res.redirect(302, '/index.html'));

app.use((err,req,res,next) => {
  console.error(err);
  if (err instanceof z.ZodError) return res.status(400).json({ error:'Invalid request', issues:err.issues });
  if (err.code === '23505') return res.status(409).json({ error:'A unique value already exists' });
  res.status(500).json({ error:'Internal server error' });
});

module.exports = app;

// Local / Render-style execution. Vercel imports the Express app as a Function, so
// do not run process-level startup or exit the process there.
if (!process.env.VERCEL && require.main === module) {
  ensureReady()
    .then(() => app.listen(PORT, () => console.log(`TG Support Platform running on :${PORT}`)))
    .catch(err => {
      console.error('Startup failed:', err.message);
      process.exitCode = 1;
    });
}
