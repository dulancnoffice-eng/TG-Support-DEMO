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
app.use('/api/', rateLimit({
  windowMs: 60_000,
  limit: 300,
  skip: req => req.path.startsWith('/telegram/webhook/')
}));
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
function decryptToken(bot) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', getEncryptionKey(), Buffer.from(bot.token_iv, 'base64'));
  decipher.setAuthTag(Buffer.from(bot.token_tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(bot.token_ciphertext, 'base64')),
    decipher.final()
  ]).toString('utf8');
}
function signUser(user) {
  return jwt.sign({ sub: user.id, role: user.role, workspaceId: user.workspace_id || null }, JWT_SECRET, { expiresIn: '12h' });
}
function requestBaseUrl(req) {
  const configured = (process.env.PUBLIC_BASE_URL || '').trim().replace(/\/$/, '');
  if (configured) return configured;
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  const host = forwardedHost || req.get('host');
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const proto = forwardedProto || req.protocol || 'https';
  return `${proto}://${host}`;
}
async function telegramApi(token, method, payload = {}) {
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(12_000)
  });
  const data = await response.json().catch(() => null);
  if (!response.ok || !data?.ok) {
    const err = new Error(data?.description || `Telegram ${method} failed (${response.status})`);
    err.code = 'TELEGRAM_API_ERROR';
    throw err;
  }
  return data.result;
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
    res.json({ ok: true, service: 'orbitdesk', database: 'ready', telegram: 'webhook-enabled', runtime: process.env.VERCEL ? 'vercel' : 'node' });
  } catch (err) {
    console.error('Health/readiness failed:', err.message);
    if (err.code === 'SETUP_REQUIRED') {
      return res.status(503).json({ ok:false, setupRequired:true, error:'Deployment environment is incomplete', missing:err.missing });
    }
    res.status(503).json({ ok:false, setupRequired:false, error:'Database initialization failed', detail: process.env.NODE_ENV === 'production' ? undefined : err.message });
  }
});

app.use('/api', async (req,res,next) => {
  if (req.path === '/health') return next();
  try {
    await ensureReady();
    next();
  } catch (err) {
    console.error('API readiness failed:', err.message);
    if (err.code === 'SETUP_REQUIRED') return res.status(503).json({ error:'Backend setup incomplete', missing:err.missing });
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
    if (count.n >= workspace.max_children_per_admin) return res.status(409).json({ error: 'Parent admin child-ID limit reached' });
  }

  const id = newId(input.role === 'WORKSPACE_ADMIN' ? 'ADM' : input.role === 'TEAM_ADMIN' ? 'TEAM' : 'USR');
  const hash = await bcrypt.hash(input.password, 12);
  const { rows } = await pool.query(
    `INSERT INTO users(id,workspace_id,parent_user_id,role,name,email,username,password_hash)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING id,workspace_id,parent_user_id,role,name,email,username,status,created_at`,
    [id,ws,parentId,input.role,input.name,input.email||null,input.username||null,hash]
  );
  await audit(req,'user.create','user',id,{role:input.role,name:input.name,parentUserId:parentId});
  res.status(201).json({ item: rows[0] });
}));

async function getBotForAdmin(req, botId) {
  const { rows:[bot] } = await pool.query('SELECT * FROM bots WHERE id=$1', [botId]);
  if (!bot) return null;
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id) !== String(bot.workspace_id)) return null;
  return bot;
}

app.get('/api/bots', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  const adminLike = ['MASTER_ADMIN','WORKSPACE_ADMIN'].includes(req.user.role);
  if (!ws && req.user.role !== 'MASTER_ADMIN') return res.json({ items: [] });
  const params = ws ? (adminLike ? [ws] : [ws, req.user.id]) : [];
  const permissionJoin = adminLike ? '' : `JOIN bot_assignments selfba ON selfba.bot_id=b.id AND selfba.user_id=$2 AND selfba.can_read=true`;
  const whereSql = ws ? 'WHERE b.workspace_id=$1' : '';
  const { rows } = await pool.query(
    `SELECT b.id,b.workspace_id,b.platform,b.name,b.external_bot_id,b.external_bot_username,b.status,b.auto_reply,b.webhook_status,b.webhook_url,b.last_webhook_error,b.created_at,
            COALESCE(json_agg(json_build_object('userId',ba.user_id,'canRead',ba.can_read,'canReply',ba.can_reply,'canManage',ba.can_manage)) FILTER (WHERE ba.user_id IS NOT NULL),'[]'::json) AS assignments
       FROM bots b
       ${permissionJoin}
       LEFT JOIN bot_assignments ba ON ba.bot_id=b.id
      ${whereSql}
      GROUP BY b.id
      ORDER BY b.created_at DESC`, params
  );
  res.json({ items: rows });
}));

async function registerWebhook(req, bot) {
  const token = decryptToken(bot);
  const me = await telegramApi(token, 'getMe');
  const secret = bot.webhook_secret || crypto.randomBytes(24).toString('base64url');
  const webhookUrl = `${requestBaseUrl(req)}/api/telegram/webhook/${bot.id}`;
  await telegramApi(token, 'setWebhook', {
    url: webhookUrl,
    secret_token: secret,
    allowed_updates: ['message','edited_message'],
    drop_pending_updates: false
  });
  await pool.query(
    `UPDATE bots
        SET external_bot_id=$2, external_bot_username=$3, webhook_secret=$4, webhook_url=$5,
            webhook_status='ACTIVE', last_webhook_error=NULL, status='ACTIVE', updated_at=now()
      WHERE id=$1`,
    [bot.id, String(me.id), me.username || null, secret, webhookUrl]
  );
  return { me, webhookUrl };
}

app.post('/api/bots', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({
    workspaceId: z.string().uuid().optional(),
    platform: z.enum(['telegram']).default('telegram'),
    name: z.string().min(2).max(120),
    token: z.string().min(20),
    autoReply: z.boolean().default(false)
  }).parse(req.body);
  const ws = workspaceScope(req, input.workspaceId);
  if (!ws) return res.status(400).json({ error: 'workspaceId is required' });

  const me = await telegramApi(input.token, 'getMe');
  const existing = await pool.query(`SELECT id,name FROM bots WHERE workspace_id=$1 AND platform='telegram' AND external_bot_id=$2 LIMIT 1`, [ws, String(me.id)]);
  if (existing.rows[0]) return res.status(409).json({ error: `This Telegram bot is already connected as ${existing.rows[0].name}` });

  const id = crypto.randomUUID();
  const enc = encryptToken(input.token);
  const secret = crypto.randomBytes(24).toString('base64url');
  const { rows } = await pool.query(
    `INSERT INTO bots(id,workspace_id,platform,name,external_bot_id,external_bot_username,token_ciphertext,token_iv,token_tag,webhook_secret,auto_reply,created_by)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING *`,
    [id,ws,input.platform,input.name,String(me.id),me.username||null,enc.ciphertext,enc.iv,enc.tag,secret,input.autoReply,req.user.id]
  );

  let webhook = { ok:true };
  try {
    const sync = await registerWebhook(req, rows[0]);
    webhook = { ok:true, url:sync.webhookUrl };
  } catch (err) {
    webhook = { ok:false, error:err.message };
    await pool.query(`UPDATE bots SET status='ERROR', webhook_status='ERROR', last_webhook_error=$2, updated_at=now() WHERE id=$1`, [id, err.message.slice(0,1000)]);
  }
  await audit(req,'bot.create','bot',id,{platform:input.platform,name:input.name,telegramUsername:me.username,webhookOk:webhook.ok});
  const { rows:[item] } = await pool.query(`SELECT id,workspace_id,platform,name,external_bot_id,external_bot_username,status,auto_reply,webhook_status,webhook_url,last_webhook_error,created_at FROM bots WHERE id=$1`, [id]);
  res.status(201).json({ item, webhook });
}));

app.get('/api/bots/:botId/assignments', auth, asyncRoute(async (req,res) => {
  const bot = await getBotForAdmin(req, req.params.botId);
  if (!bot) return res.status(404).json({ error:'Bot not found in your scope' });
  const { rows } = await pool.query(
    `SELECT ba.user_id,u.name,u.role,u.parent_user_id,ba.can_read,ba.can_reply,ba.can_manage,ba.assigned_at
       FROM bot_assignments ba JOIN users u ON u.id=ba.user_id
      WHERE ba.bot_id=$1 ORDER BY u.role,u.name`, [bot.id]
  );
  res.json({ items:rows });
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

app.delete('/api/bots/:botId/assign/:userId', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const { rows:[bot] } = await pool.query('SELECT id,workspace_id FROM bots WHERE id=$1', [req.params.botId]);
  const { rows:[target] } = await pool.query('SELECT id,workspace_id,parent_user_id FROM users WHERE id=$1', [req.params.userId]);
  if (!bot || !target || String(bot.workspace_id) !== String(target.workspace_id)) return res.status(404).json({ error:'Bot/user not found in same workspace' });
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id) !== String(bot.workspace_id)) return res.status(403).json({ error:'Cross-workspace assignment denied' });
  if (req.user.role === 'TEAM_ADMIN' && target.parent_user_id !== req.user.id && target.id !== req.user.id) return res.status(403).json({ error:'Team admin can unassign only within own branch' });
  await pool.query('DELETE FROM bot_assignments WHERE bot_id=$1 AND user_id=$2', [bot.id,target.id]);
  await audit(req,'bot.unassign','bot',bot.id,{userId:target.id});
  res.json({ ok:true });
}));

app.post('/api/bots/:botId/sync', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN'), asyncRoute(async (req,res) => {
  const bot = await getBotForAdmin(req, req.params.botId);
  if (!bot) return res.status(404).json({ error:'Bot not found in your scope' });
  try {
    const result = await registerWebhook(req, bot);
    await audit(req,'bot.webhook.sync','bot',bot.id,{webhookUrl:result.webhookUrl,telegramUsername:result.me.username});
    res.json({ ok:true, webhookUrl:result.webhookUrl, telegramBot:{id:result.me.id,username:result.me.username} });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error:'This Telegram bot token is already attached to another bot record in this workspace. Delete the duplicate bot record.' });
    await pool.query(`UPDATE bots SET status='ERROR',webhook_status='ERROR',last_webhook_error=$2,updated_at=now() WHERE id=$1`, [bot.id,err.message.slice(0,1000)]).catch(()=>{});
    throw err;
  }
}));

app.delete('/api/bots/:botId', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN'), asyncRoute(async (req,res) => {
  const bot = await getBotForAdmin(req, req.params.botId);
  if (!bot) return res.status(404).json({ error:'Bot not found in your scope' });
  try {
    const token = decryptToken(bot);
    await telegramApi(token, 'deleteWebhook', { drop_pending_updates:false });
  } catch (err) {
    console.warn('deleteWebhook failed:', err.message);
  }
  await pool.query('DELETE FROM bots WHERE id=$1', [bot.id]);
  await audit(req,'bot.delete','bot',bot.id,{name:bot.name});
  res.json({ ok:true });
}));

function telegramMessageBody(message) {
  if (message.text) return message.text;
  if (message.caption) return message.caption;
  if (message.photo) return '[Photo]';
  if (message.video) return '[Video]';
  if (message.voice) return '[Voice message]';
  if (message.audio) return '[Audio]';
  if (message.document) return `[Document${message.document.file_name ? `: ${message.document.file_name}` : ''}]`;
  if (message.sticker) return '[Sticker]';
  if (message.location) return '[Location]';
  if (message.contact) return '[Contact]';
  return '[Unsupported Telegram message]';
}

// PUBLIC TELEGRAM WEBHOOK. Authentication is the per-bot Telegram secret header, not a user JWT.
app.post('/api/telegram/webhook/:botId', asyncRoute(async (req,res) => {
  const { rows:[bot] } = await pool.query('SELECT id,workspace_id,webhook_secret FROM bots WHERE id=$1', [req.params.botId]);
  if (!bot || !bot.webhook_secret) return res.status(404).json({ ok:false });
  const supplied = String(req.get('x-telegram-bot-api-secret-token') || '');
  const expected = String(bot.webhook_secret);
  const valid = supplied.length === expected.length && crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
  if (!valid) return res.status(403).json({ ok:false });

  const update = req.body || {};
  const message = update.message || update.edited_message;
  if (!message || !message.chat) return res.json({ ok:true });

  const from = message.from || message.chat;
  const externalUserId = String(from.id || message.chat.id);
  const chatId = String(message.chat.id);
  const displayName = [from.first_name, from.last_name].filter(Boolean).join(' ') || from.username || message.chat.title || `Telegram ${externalUserId}`;
  const username = from.username || null;
  const body = telegramMessageBody(message);
  const externalMessageId = `${chatId}:${message.message_id}`;

  const { rows:[customer] } = await pool.query(
    `INSERT INTO customers(workspace_id,platform,external_user_id,display_name,metadata)
     VALUES($1,'telegram',$2,$3,$4::jsonb)
     ON CONFLICT(workspace_id,platform,external_user_id)
     DO UPDATE SET display_name=excluded.display_name,
                   metadata=customers.metadata || excluded.metadata,
                   updated_at=now()
     RETURNING *`,
    [bot.workspace_id,externalUserId,displayName,JSON.stringify({ telegram_chat_id:chatId, telegram_username:username, chat_type:message.chat.type })]
  );

  let { rows:[conversation] } = await pool.query(
    `SELECT * FROM conversations
      WHERE workspace_id=$1 AND bot_id=$2 AND customer_id=$3 AND status <> 'resolved'
      ORDER BY created_at DESC LIMIT 1`,
    [bot.workspace_id,bot.id,customer.id]
  );
  if (!conversation) {
    const created = await pool.query(
      `INSERT INTO conversations(workspace_id,bot_id,customer_id,status,unread_count,last_message_at)
       VALUES($1,$2,$3,'waiting',0,now()) RETURNING *`,
      [bot.workspace_id,bot.id,customer.id]
    );
    conversation = created.rows[0];
  }

  const inserted = await pool.query(
    `INSERT INTO messages(conversation_id,sender_type,body,external_message_id,media,created_at)
     VALUES($1,'customer',$2,$3,$4::jsonb,to_timestamp($5))
     ON CONFLICT DO NOTHING
     RETURNING id`,
    [conversation.id,body,externalMessageId,JSON.stringify({ telegram:update }),Number(message.date || Math.floor(Date.now()/1000))]
  );
  if (inserted.rowCount) {
    await pool.query(
      `UPDATE conversations SET unread_count=unread_count+1,last_message_at=to_timestamp($2),updated_at=now() WHERE id=$1`,
      [conversation.id,Number(message.date || Math.floor(Date.now()/1000))]
    );
  }
  res.json({ ok:true });
}));

async function getConversationForUser(req, conversationId, needReply=false) {
  const { rows:[c] } = await pool.query(
    `SELECT c.*,b.name AS bot_name,b.token_ciphertext,b.token_iv,b.token_tag,
            cu.display_name,cu.external_user_id,cu.tags,cu.metadata AS customer_metadata,
            au.name AS assigned_name
       FROM conversations c
       JOIN bots b ON b.id=c.bot_id
       JOIN customers cu ON cu.id=c.customer_id
       LEFT JOIN users au ON au.id=c.assigned_user_id
      WHERE c.id=$1`, [conversationId]
  );
  if (!c) return null;
  if (req.user.role === 'MASTER_ADMIN') return c;
  if (String(req.user.workspace_id) !== String(c.workspace_id)) return null;
  if (req.user.role === 'WORKSPACE_ADMIN') return c;
  const { rows:[permission] } = await pool.query('SELECT can_read,can_reply FROM bot_assignments WHERE bot_id=$1 AND user_id=$2', [c.bot_id,req.user.id]);
  if (!permission || !permission.can_read || (needReply && !permission.can_reply)) return null;
  return c;
}

app.get('/api/conversations', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws) return res.json({ items:[] });
  const status = String(req.query.status || '').trim();
  const params = [ws];
  let permissionJoin = '';
  if (!['MASTER_ADMIN','WORKSPACE_ADMIN'].includes(req.user.role)) {
    params.push(req.user.id);
    permissionJoin = `JOIN bot_assignments p ON p.bot_id=c.bot_id AND p.user_id=$2 AND p.can_read=true`;
  }
  if (status) params.push(status);
  const statusSql = status ? `AND c.status=$${params.length}` : '';
  const { rows } = await pool.query(
    `SELECT c.id,c.workspace_id,c.bot_id,c.customer_id,c.assigned_user_id,c.status,c.priority,c.unread_count,c.last_message_at,c.created_at,
            cu.display_name,cu.external_user_id,cu.tags,cu.metadata AS customer_metadata,
            b.name AS bot_name,b.external_bot_username,
            au.name AS assigned_name,
            lm.body AS last_message
       FROM conversations c
       ${permissionJoin}
       JOIN customers cu ON cu.id=c.customer_id
       JOIN bots b ON b.id=c.bot_id
       LEFT JOIN users au ON au.id=c.assigned_user_id
       LEFT JOIN LATERAL (SELECT body FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) lm ON true
      WHERE c.workspace_id=$1 ${statusSql}
      ORDER BY c.last_message_at DESC NULLS LAST, c.created_at DESC
      LIMIT 300`, params
  );
  res.json({ items:rows });
}));

app.get('/api/conversations/:conversationId/messages', auth, asyncRoute(async (req,res) => {
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  const { rows } = await pool.query(
    `SELECT id,sender_type,sender_user_id,body,media,external_message_id,created_at
       FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC LIMIT 1000`, [conversation.id]
  );
  await pool.query('UPDATE conversations SET unread_count=0 WHERE id=$1', [conversation.id]);
  res.json({ conversation, items:rows });
}));

app.post('/api/conversations/:conversationId/messages', auth, asyncRoute(async (req,res) => {
  const input = z.object({ text:z.string().min(1).max(4096) }).parse(req.body);
  const conversation = await getConversationForUser(req, req.params.conversationId, true);
  if (!conversation) return res.status(403).json({ error:'You do not have reply permission for this conversation' });
  const chatId = conversation.customer_metadata?.telegram_chat_id;
  if (!chatId) return res.status(409).json({ error:'Telegram chat ID is missing for this customer' });
  const token = decryptToken(conversation);
  const sent = await telegramApi(token, 'sendMessage', { chat_id:chatId, text:input.text });
  const externalMessageId = `${chatId}:${sent.message_id}`;
  const { rows:[saved] } = await pool.query(
    `INSERT INTO messages(conversation_id,sender_type,sender_user_id,body,external_message_id,created_at)
     VALUES($1,'agent',$2,$3,$4,to_timestamp($5)) RETURNING *`,
    [conversation.id,req.user.id,input.text,externalMessageId,Number(sent.date || Math.floor(Date.now()/1000))]
  );
  await pool.query(
    `UPDATE conversations
        SET status=CASE WHEN status='waiting' THEN 'in_progress' ELSE status END,
            assigned_user_id=COALESCE(assigned_user_id,$2),unread_count=0,last_message_at=now(),updated_at=now()
      WHERE id=$1`,
    [conversation.id, req.user.role === 'MASTER_ADMIN' ? null : req.user.id]
  );
  await audit(req,'conversation.reply','conversation',conversation.id,{botId:conversation.bot_id});
  res.status(201).json({ item:saved });
}));

app.post('/api/conversations/:conversationId/assign', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({ userId:z.string().min(1).nullable() }).parse(req.body);
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  if (input.userId) {
    const { rows:[target] } = await pool.query('SELECT id,workspace_id,parent_user_id FROM users WHERE id=$1 AND status=\'active\'', [input.userId]);
    if (!target || String(target.workspace_id) !== String(conversation.workspace_id)) return res.status(400).json({ error:'Assignee is not in this workspace' });
    const { rows:[ba] } = await pool.query('SELECT can_read,can_reply FROM bot_assignments WHERE bot_id=$1 AND user_id=$2', [conversation.bot_id,target.id]);
    if (!ba?.can_read) return res.status(409).json({ error:'Assign this bot to the selected ID before assigning the conversation' });
    if (req.user.role === 'TEAM_ADMIN' && target.parent_user_id !== req.user.id && target.id !== req.user.id) return res.status(403).json({ error:'Team admin can assign only within own branch' });
  }
  await pool.query(`UPDATE conversations SET assigned_user_id=$2,status=CASE WHEN $2 IS NULL THEN 'waiting' ELSE 'in_progress' END,updated_at=now() WHERE id=$1`, [conversation.id,input.userId]);
  await audit(req,'conversation.assign','conversation',conversation.id,{userId:input.userId});
  res.json({ ok:true });
}));

app.post('/api/conversations/:conversationId/resolve', auth, asyncRoute(async (req,res) => {
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  await pool.query(`UPDATE conversations SET status='resolved',unread_count=0,updated_at=now() WHERE id=$1`, [conversation.id]);
  await audit(req,'conversation.resolve','conversation',conversation.id,{});
  res.json({ ok:true });
}));

app.get('/api/customers', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws) return res.json({items:[]});
  const { rows } = await pool.query(`SELECT id,workspace_id,platform,external_user_id,display_name,tags,metadata,updated_at,created_at FROM customers WHERE workspace_id=$1 ORDER BY updated_at DESC LIMIT 500`, [ws]);
  res.json({items:rows});
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
  if (rows[0]) return;
  const email = process.env.MASTER_ADMIN_EMAIL;
  const password = process.env.MASTER_ADMIN_PASSWORD;
  const name = process.env.MASTER_ADMIN_NAME || 'Master Admin';
  if (!email || !password) throw new Error('No Master Admin exists. Set MASTER_ADMIN_EMAIL and MASTER_ADMIN_PASSWORD.');
  if (password.length < 12) throw new Error('MASTER_ADMIN_PASSWORD must be at least 12 characters');
  const hash = await bcrypt.hash(password, 12);
  await pool.query(
    `INSERT INTO users(id,workspace_id,parent_user_id,role,name,email,username,password_hash)
     VALUES($1,NULL,NULL,'MASTER_ADMIN',$2,$3,$4,$5)
     ON CONFLICT (id) DO NOTHING`,
    [MASTER_ADMIN_ID,name,email,MASTER_ADMIN_ID,hash]
  );
}

app.get('*', (req,res) => res.redirect(302, '/index.html'));

app.use((err,req,res,next) => {
  console.error(err);
  if (err instanceof z.ZodError) return res.status(400).json({ error:'Invalid request', issues:err.issues });
  if (err.code === '23505') return res.status(409).json({ error:'A unique value already exists' });
  if (err.code === 'TELEGRAM_API_ERROR') return res.status(502).json({ error:err.message });
  res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message });
});

module.exports = app;
if (!process.env.VERCEL && require.main === module) {
  ensureReady()
    .then(() => app.listen(PORT, () => console.log(`OrbitDesk running on :${PORT}`)))
    .catch(err => { console.error('Startup failed:', err.message); process.exitCode = 1; });
}
