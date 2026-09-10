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
app.use(express.json({ limit: '4mb' }));
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
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
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

async function telegramMultipart(token, method, fields, fileField, buffer, filename, mimeType) {
  const form = new FormData();
  for (const [k,v] of Object.entries(fields || {})) {
    if (v !== undefined && v !== null) form.append(k, String(v));
  }
  form.append(fileField, new Blob([buffer], { type:mimeType || 'application/octet-stream' }), filename || 'upload.bin');
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method:'POST', body:form, signal:AbortSignal.timeout(25_000)
  });
  const data = await response.json().catch(() => null);
  if (!response.ok || !data?.ok) {
    const err = new Error(data?.description || `Telegram ${method} failed (${response.status})`);
    err.code = 'TELEGRAM_API_ERROR';
    throw err;
  }
  return data.result;
}
function decodeBase64Upload(dataBase64, maxBytes=2_500_000) {
  const raw = String(dataBase64 || '').replace(/^data:[^;]+;base64,/, '');
  if (!raw || raw.length > Math.ceil(maxBytes * 4 / 3) + 16) throw Object.assign(new Error('Upload is too large. Keep each file under 2.5 MB after image compression.'), { code:'UPLOAD_TOO_LARGE' });
  const buffer = Buffer.from(raw, 'base64');
  if (!buffer.length || buffer.length > maxBytes) throw Object.assign(new Error('Upload is too large. Keep each file under 2.5 MB after image compression.'), { code:'UPLOAD_TOO_LARGE' });
  return buffer;
}
async function saveOutboundTelegramMedia(conversation, reqUserId, buffer, filename, mimeType, kind, source={}) {
  const chatId = conversation.customer_metadata?.telegram_chat_id;
  if (!chatId) throw new Error('Telegram chat ID is missing for this customer');
  const token = decryptToken(conversation);
  const isImage = kind === 'image' || String(mimeType || '').startsWith('image/');
  const sent = isImage
    ? await telegramMultipart(token, 'sendPhoto', { chat_id:chatId }, 'photo', buffer, filename, mimeType)
    : await telegramMultipart(token, 'sendDocument', { chat_id:chatId }, 'document', buffer, filename, mimeType);
  const externalMessageId = `${chatId}:${sent.message_id}`;
  const body = isImage ? `[Image: ${filename}]` : `[File: ${filename}]`;
  const media = { kind:isImage?'image':'file', filename, mimeType, size:buffer.length, ...source };
  const { rows:[saved] } = await pool.query(
    `INSERT INTO messages(conversation_id,sender_type,sender_user_id,body,external_message_id,media,created_at)
     VALUES($1,'agent',$2,$3,$4,$5::jsonb,to_timestamp($6)) RETURNING *`,
    [conversation.id,reqUserId,body,externalMessageId,JSON.stringify(media),Number(sent.date || Math.floor(Date.now()/1000))]
  );
  await pool.query(`UPDATE conversations SET unread_count=0,last_message_at=now(),updated_at=now() WHERE id=$1`, [conversation.id]);
  return saved;
}
async function sendAutomationMessage(conversation, triggerType, actorUserId=null, assigneeUserId=null) {
  const { rows:[rule] } = await pool.query(
    `SELECT enabled,body FROM automation_messages WHERE workspace_id=$1 AND trigger_type=$2`,
    [conversation.workspace_id,triggerType]
  );
  if (!rule?.enabled || !String(rule.body || '').trim()) return null;
  const chatId = conversation.customer_metadata?.telegram_chat_id;
  if (!chatId) return null;
  const token = decryptToken(conversation);
  let agentName = '';
  if (assigneeUserId) { const { rows:[u] } = await pool.query('SELECT name FROM users WHERE id=$1',[assigneeUserId]); agentName = u?.name || ''; }
  const { rows:[ws] } = await pool.query('SELECT name FROM workspaces WHERE id=$1',[conversation.workspace_id]);
  const text = String(rule.body).trim()
    .replace(/\{customer\}/g, String(conversation.display_name || ''))
    .replace(/\{agent\}/g, agentName)
    .replace(/\{workspace\}/g, String(ws?.name || ''));
  const sent = await telegramApi(token,'sendMessage',{ chat_id:chatId, text });
  const externalMessageId = `${chatId}:${sent.message_id}`;
  const { rows:[saved] } = await pool.query(
    `INSERT INTO messages(conversation_id,sender_type,sender_user_id,body,external_message_id,media,created_at)
     VALUES($1,'bot',$2,$3,$4,$5::jsonb,to_timestamp($6)) RETURNING *`,
    [conversation.id,actorUserId,text,externalMessageId,JSON.stringify({ automation:triggerType }),Number(sent.date || Math.floor(Date.now()/1000))]
  );
  await pool.query(`UPDATE conversations SET last_message_at=GREATEST(COALESCE(last_message_at,now()),to_timestamp($2)),updated_at=now() WHERE id=$1`, [conversation.id,Number(sent.date || Math.floor(Date.now()/1000))]);
  return saved;
}

async function translateText(text, targetLanguage) {
  const key = String(process.env.GOOGLE_TRANSLATE_API_KEY || '').trim();
  if (!key) {
    const err = new Error('Translation is not configured. Add GOOGLE_TRANSLATE_API_KEY in Vercel Environment Variables.');
    err.code = 'TRANSLATION_NOT_CONFIGURED';
    throw err;
  }
  const url = new URL('https://translation.googleapis.com/language/translate/v2');
  url.searchParams.set('key', key);
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ q: text, target: targetLanguage, format: 'text' }),
    signal: AbortSignal.timeout(15_000)
  });
  const data = await response.json().catch(() => null);
  if (!response.ok || !data?.data?.translations?.[0]) {
    const err = new Error(data?.error?.message || `Translation failed (${response.status})`);
    err.code = 'TRANSLATION_API_ERROR';
    throw err;
  }
  const item = data.data.translations[0];
  return {
    text: String(item.translatedText || ''),
    detectedSourceLanguage: item.detectedSourceLanguage || null,
    provider: 'google'
  };
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

async function branchUserIds(req, workspaceId) {
  if (!workspaceId) return [];
  if (req.user.role === 'TEAM_ADMIN') {
    const { rows } = await pool.query(
      `SELECT id FROM users WHERE workspace_id=$1 AND status='active' AND (id=$2 OR parent_user_id=$2)`,
      [workspaceId, req.user.id]
    );
    return rows.map(r => r.id);
  }
  if (['AGENT','VIEWER'].includes(req.user.role)) return [req.user.id];
  return [];
}
function dashboardPeriodStart(period) {
  const now = new Date();
  if (period === 'today') {
    const d = new Date(now);
    d.setUTCHours(0,0,0,0);
    return d;
  }
  const days = period === 'month' ? 30 : 7;
  return new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
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
    res.json({ ok: true, service: 'dlxn17-customer-support', database: 'ready', telegram: 'webhook-enabled', runtime: process.env.VERCEL ? 'vercel' : 'node' });
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
  let rows = [];
  if (req.user.role === 'MASTER_ADMIN') {
    const params = [];
    let where = '';
    if (ws) { params.push(ws); where = 'WHERE workspace_id=$1'; }
    ({ rows } = await pool.query(`SELECT id,workspace_id,parent_user_id,role,name,email,username,status,last_login_at,created_at FROM users ${where} ORDER BY created_at`, params));
  } else if (req.user.role === 'WORKSPACE_ADMIN') {
    ({ rows } = await pool.query(`SELECT id,workspace_id,parent_user_id,role,name,email,username,status,last_login_at,created_at FROM users WHERE workspace_id=$1 ORDER BY created_at`, [req.user.workspace_id]));
  } else if (req.user.role === 'TEAM_ADMIN') {
    ({ rows } = await pool.query(`SELECT id,workspace_id,parent_user_id,role,name,email,username,status,last_login_at,created_at FROM users WHERE workspace_id=$1 AND (id=$2 OR parent_user_id=$2) ORDER BY created_at`, [req.user.workspace_id, req.user.id]));
  } else {
    ({ rows } = await pool.query(`SELECT id,workspace_id,parent_user_id,role,name,email,username,status,last_login_at,created_at FROM users WHERE id=$1`, [req.user.id]));
  }
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

async function getBotForUser(req, botId, needManage=false) {
  const { rows:[bot] } = await pool.query('SELECT * FROM bots WHERE id=$1', [botId]);
  if (!bot) return null;
  if (req.user.role === 'MASTER_ADMIN') return bot;
  if (String(req.user.workspace_id) !== String(bot.workspace_id)) return null;
  if (req.user.role === 'WORKSPACE_ADMIN') return bot;
  const { rows:[permission] } = await pool.query('SELECT can_read,can_reply,can_manage FROM bot_assignments WHERE bot_id=$1 AND user_id=$2', [bot.id, req.user.id]);
  if (!permission?.can_read) return null;
  if (needManage && !permission.can_manage) return null;
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

app.put('/api/bots/:botId/assignments', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({ userIds: z.array(z.string().min(1)).max(500) }).parse(req.body);
  const bot = await getBotForUser(req, req.params.botId, req.user.role === 'TEAM_ADMIN');
  if (!bot) return res.status(404).json({ error:'Bot not found or you do not have management permission' });
  const uniqueIds = [...new Set(input.userIds)];
  let allowedRows = [];
  if (uniqueIds.length) {
    const { rows } = await pool.query(
      `SELECT id,workspace_id,parent_user_id,role FROM users WHERE id = ANY($1::varchar[]) AND status='active'`,
      [uniqueIds]
    );
    allowedRows = rows;
    if (rows.length !== uniqueIds.length) return res.status(400).json({ error:'One or more selected IDs do not exist or are inactive' });
    if (rows.some(u => String(u.workspace_id) !== String(bot.workspace_id))) return res.status(400).json({ error:'All assigned IDs must belong to the bot workspace' });
    if (req.user.role === 'TEAM_ADMIN' && rows.some(u => u.id !== req.user.id && u.parent_user_id !== req.user.id)) {
      return res.status(403).json({ error:'Team Admin can assign only itself and IDs in its own branch' });
    }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (req.user.role === 'TEAM_ADMIN') {
      const { rows:branch } = await client.query(`SELECT id FROM users WHERE workspace_id=$1 AND (id=$2 OR parent_user_id=$2)`, [bot.workspace_id, req.user.id]);
      const branchIds = branch.map(x=>x.id);
      if (branchIds.length) await client.query(`DELETE FROM bot_assignments WHERE bot_id=$1 AND user_id = ANY($2::varchar[])`, [bot.id, branchIds]);
    } else {
      await client.query('DELETE FROM bot_assignments WHERE bot_id=$1', [bot.id]);
    }
    for (const u of allowedRows) {
      const canManage = u.role === 'TEAM_ADMIN';
      await client.query(
        `INSERT INTO bot_assignments(bot_id,user_id,can_read,can_reply,can_manage,assigned_by)
         VALUES($1,$2,true,true,$3,$4)
         ON CONFLICT(bot_id,user_id) DO UPDATE SET can_read=true,can_reply=true,can_manage=excluded.can_manage,assigned_by=excluded.assigned_by,assigned_at=now()`,
        [bot.id,u.id,canManage,req.user.id]
      );
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
  await audit(req,'bot.assign.bulk','bot',bot.id,{userIds:uniqueIds});
  res.json({ ok:true, assigned:uniqueIds.length });
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

app.get('/api/bots/:botId/telegram-status', auth, asyncRoute(async (req,res) => {
  const bot = await getBotForUser(req, req.params.botId, false);
  if (!bot) return res.status(404).json({ error:'Bot not found in your scope' });
  const token = decryptToken(bot);
  const info = await telegramApi(token, 'getWebhookInfo');
  const expectedUrl = `${requestBaseUrl(req)}/api/telegram/webhook/${bot.id}`;
  const active = Boolean(info.url) && info.url === expectedUrl && !info.last_error_message;
  await pool.query(
    `UPDATE bots SET webhook_status=$2,last_webhook_error=$3,webhook_url=$4,updated_at=now() WHERE id=$1`,
    [bot.id, active ? 'ACTIVE' : (info.last_error_message ? 'ERROR' : 'PENDING'), info.last_error_message || null, info.url || expectedUrl]
  );
  res.json({
    ok:true,
    active,
    expectedUrl,
    telegramUrl:info.url || '',
    pendingUpdateCount:Number(info.pending_update_count || 0),
    lastErrorMessage:info.last_error_message || null,
    lastErrorDate:info.last_error_date ? new Date(info.last_error_date*1000).toISOString() : null,
    ipAddress:info.ip_address || null,
    allowedUpdates:info.allowed_updates || []
  });
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
  const { rows:[bot] } = await pool.query('SELECT id,workspace_id,webhook_secret,token_ciphertext,token_iv,token_tag FROM bots WHERE id=$1', [req.params.botId]);
  if (!bot || !bot.webhook_secret) return res.status(404).json({ ok:false });
  const supplied = String(req.get('x-telegram-bot-api-secret-token') || '');
  const expected = String(bot.webhook_secret);
  const valid = supplied.length === expected.length && crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
  if (!valid) return res.status(403).json({ ok:false });

  await pool.query(`UPDATE bots SET webhook_status='ACTIVE',last_webhook_error=NULL,updated_at=now() WHERE id=$1`, [bot.id]).catch(()=>{});
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

  const metadataJson = JSON.stringify({ telegram_chat_id:chatId, telegram_username:username, chat_type:message.chat.type });
  const insertedCustomer = await pool.query(
    `INSERT INTO customers(workspace_id,platform,external_user_id,display_name,metadata)
     VALUES($1,'telegram',$2,$3,$4::jsonb)
     ON CONFLICT(workspace_id,platform,external_user_id) DO NOTHING
     RETURNING *`,
    [bot.workspace_id,externalUserId,displayName,metadataJson]
  );
  const isNewCustomer = insertedCustomer.rowCount > 0;
  let customer = insertedCustomer.rows[0];
  if (!customer) {
    const updatedCustomer = await pool.query(
      `UPDATE customers SET display_name=$3,metadata=metadata || $4::jsonb,updated_at=now()
        WHERE workspace_id=$1 AND platform='telegram' AND external_user_id=$2 RETURNING *`,
      [bot.workspace_id,externalUserId,displayName,metadataJson]
    );
    customer = updatedCustomer.rows[0];
  }

  let { rows:[conversation] } = await pool.query(
    `SELECT * FROM conversations
      WHERE workspace_id=$1 AND bot_id=$2 AND customer_id=$3
      ORDER BY created_at ASC LIMIT 1`,
    [bot.workspace_id,bot.id,customer.id]
  );
  if (!conversation) {
    try {
      const created = await pool.query(
        `INSERT INTO conversations(workspace_id,bot_id,customer_id,status,unread_count,last_message_at,waiting_since)
         VALUES($1,$2,$3,'waiting',0,now(),now()) RETURNING *`,
        [bot.workspace_id,bot.id,customer.id]
      );
      conversation = created.rows[0];
    } catch (err) {
      if (err.code !== '23505') throw err;
      const existing = await pool.query(
        `SELECT * FROM conversations WHERE workspace_id=$1 AND bot_id=$2 AND customer_id=$3 ORDER BY created_at ASC LIMIT 1`,
        [bot.workspace_id,bot.id,customer.id]
      );
      conversation = existing.rows[0];
    }
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
      `UPDATE conversations
          SET status=CASE WHEN status IN ('resolved','deleted') THEN 'waiting' ELSE status END,
              assigned_user_id=CASE WHEN status IN ('resolved','deleted') THEN NULL ELSE assigned_user_id END,
              assigned_at=CASE WHEN status IN ('resolved','deleted') THEN NULL ELSE assigned_at END,
              resolved_at=CASE WHEN status IN ('resolved','deleted') THEN NULL ELSE resolved_at END,
              deleted_at=CASE WHEN status IN ('resolved','deleted') THEN NULL ELSE deleted_at END,
              deleted_by=CASE WHEN status IN ('resolved','deleted') THEN NULL ELSE deleted_by END,
              waiting_since=CASE WHEN status IN ('resolved','deleted') THEN to_timestamp($2) WHEN status='waiting' THEN COALESCE(waiting_since,created_at) ELSE waiting_since END,
              unread_count=unread_count+1,
              last_message_at=to_timestamp($2),updated_at=now()
        WHERE id=$1`,
      [conversation.id,Number(message.date || Math.floor(Date.now()/1000))]
    );
    const isReopenedChat = ['resolved','deleted'].includes(conversation.status);
    if (isNewCustomer || isReopenedChat) {
      const automationConversation = {
        ...conversation,
        workspace_id:bot.workspace_id,
        token_ciphertext:bot.token_ciphertext,
        token_iv:bot.token_iv,
        token_tag:bot.token_tag,
        customer_metadata:{ telegram_chat_id:chatId },
        display_name:displayName
      };
      try { await sendAutomationMessage(automationConversation,'new_customer',null); }
      catch (err) { console.warn('new customer auto message failed:', err.message); }
    }
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
  if (req.user.role === 'AGENT') {
    if (c.status === 'waiting' && !c.assigned_user_id) return c;
    return c.assigned_user_id === req.user.id ? c : null;
  }
  if (req.user.role === 'TEAM_ADMIN') {
    if (c.status === 'waiting' && !c.assigned_user_id) return c;
    const ids = await branchUserIds(req, c.workspace_id);
    return c.assigned_user_id && ids.includes(c.assigned_user_id) ? c : null;
  }
  if (req.user.role === 'VIEWER') return c.assigned_user_id === req.user.id ? c : null;
  return c;
}

app.get('/api/conversations', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws) return res.json({ items:[] });
  const status = String(req.query.status || 'active').trim();
  if (!['active','waiting','in_progress','history','resolved','deleted'].includes(status)) return res.status(400).json({ error:'Invalid conversation status' });
  const params = [ws];
  let permissionJoin = '';
  let roleSql = '';
  if (!['MASTER_ADMIN','WORKSPACE_ADMIN'].includes(req.user.role)) {
    params.push(req.user.id);
    permissionJoin = `JOIN bot_assignments p ON p.bot_id=c.bot_id AND p.user_id=$2 AND p.can_read=true`;
    if (req.user.role === 'TEAM_ADMIN') {
      const ids = await branchUserIds(req, ws);
      params.push(ids);
      roleSql = `AND ((c.status='waiting' AND c.assigned_user_id IS NULL) OR c.assigned_user_id = ANY($${params.length}::varchar[]))`;
    } else if (req.user.role === 'AGENT') {
      roleSql = `AND ((c.status='waiting' AND c.assigned_user_id IS NULL) OR c.assigned_user_id=$2)`;
    } else if (req.user.role === 'VIEWER') {
      roleSql = `AND c.assigned_user_id=$2`;
    }
  }
  let statusSql = '';
  if (status === 'active') statusSql = `AND c.status IN ('waiting','in_progress')`;
  else if (status === 'history') statusSql = `AND c.status IN ('resolved','deleted')`;
  else { params.push(status); statusSql = `AND c.status=$${params.length}`; }
  const tag = String(req.query.tag || '').trim();
  if (tag) params.push(tag);
  const tagSql = tag ? `AND $${params.length}=ANY(cu.tags)` : '';
  const { rows } = await pool.query(
    `SELECT c.id,c.workspace_id,c.bot_id,c.customer_id,c.assigned_user_id,c.status,c.priority,c.unread_count,c.last_message_at,c.created_at,
            c.remark,c.remark_updated_at,c.assigned_at,c.resolved_at,c.deleted_at,c.deleted_by,
            cu.display_name,cu.external_user_id,cu.tags,cu.metadata AS customer_metadata,
            b.name AS bot_name,b.external_bot_username,
            au.name AS assigned_name,
            lm.body AS last_message
       FROM conversations c
       ${permissionJoin}
       JOIN customers cu ON cu.id=c.customer_id
       JOIN bots b ON b.id=c.bot_id
       LEFT JOIN users au ON au.id=c.assigned_user_id
       LEFT JOIN LATERAL (SELECT body FROM messages m WHERE m.conversation_id=c.id AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT 1) lm ON true
      WHERE c.workspace_id=$1 ${statusSql} ${roleSql} ${tagSql}
      ORDER BY c.last_message_at DESC NULLS LAST, c.created_at DESC
      LIMIT 300`, params
  );
  res.json({ items:rows });
}));

app.get('/api/inbox/counts', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws && req.user.role !== 'MASTER_ADMIN') return res.json({ waiting:0,inProgress:0,history:0,resolved:0,deleted:0,unread:0 });
  const params=[ws];
  let permissionJoin='', roleSql='';
  if (!['MASTER_ADMIN','WORKSPACE_ADMIN'].includes(req.user.role)) {
    params.push(req.user.id);
    permissionJoin=`JOIN bot_assignments p ON p.bot_id=c.bot_id AND p.user_id=$2 AND p.can_read=true`;
    if (req.user.role==='TEAM_ADMIN') {
      const ids=await branchUserIds(req,ws); params.push(ids);
      roleSql=`AND ((c.status='waiting' AND c.assigned_user_id IS NULL) OR c.assigned_user_id = ANY($${params.length}::varchar[]))`;
    } else if (req.user.role==='AGENT') roleSql=`AND ((c.status='waiting' AND c.assigned_user_id IS NULL) OR c.assigned_user_id=$2)`;
    else roleSql=`AND c.assigned_user_id=$2`;
  }
  const {rows:[r]}=await pool.query(
    `SELECT
       count(*) FILTER (WHERE c.status='waiting')::int AS waiting,
       count(*) FILTER (WHERE c.status='in_progress')::int AS in_progress,
       count(*) FILTER (WHERE c.status='resolved')::int AS resolved,
       count(*) FILTER (WHERE c.status='deleted')::int AS deleted,
       count(*) FILTER (WHERE c.status IN ('resolved','deleted'))::int AS history,
       COALESCE(sum(c.unread_count) FILTER (WHERE c.status IN ('waiting','in_progress')),0)::int AS unread
     FROM conversations c ${permissionJoin}
     WHERE ($1::uuid IS NULL OR c.workspace_id=$1) ${roleSql}`, params
  );
  res.json({waiting:r.waiting||0,inProgress:r.in_progress||0,resolved:r.resolved||0,deleted:r.deleted||0,history:r.history||0,unread:r.unread||0});
}));

app.get('/api/dashboard', auth, asyncRoute(async (req,res) => {
  const requestedWs = String(req.query.workspaceId || '').trim() || null;
  const ws = req.user.role === 'MASTER_ADMIN' ? requestedWs : req.user.workspace_id;
  if (req.user.role !== 'MASTER_ADMIN' && requestedWs && String(requestedWs)!==String(req.user.workspace_id)) {
    return res.status(403).json({error:'Cross-workspace dashboard access denied'});
  }

  const period = ['today','week','month'].includes(String(req.query.period)) ? String(req.query.period) : 'today';
  const start = dashboardPeriodStart(period);
  const unrestricted = ['MASTER_ADMIN','WORKSPACE_ADMIN'].includes(req.user.role);
  const scopeIds = unrestricted ? [] : await branchUserIds(req, req.user.workspace_id);
  const ids = scopeIds.length ? scopeIds : [req.user.id];

  // Keep dashboard analytics deliberately dependent only on the long-lived core tables.
  // This makes the dashboard survive incremental schema upgrades on serverless deployments.
  // More precise lifecycle/event analytics can still be added later without making the whole
  // dashboard fail when one optional analytics table/column is unavailable.
  const params = [ws, start, ids];
  const wsSql = `($1::uuid IS NULL OR c.workspace_id=$1)`;
  const ownedSql = unrestricted ? '' : `AND c.assigned_user_id = ANY($3::varchar[])`;

  const safeOne = async (sql, p=params, fallback={}) => {
    try {
      const {rows:[row]} = await pool.query(sql,p);
      return row || fallback;
    } catch (err) {
      console.error('Dashboard metric query failed:', err.message);
      return fallback;
    }
  };

  const received = await safeOne(
    `SELECT count(DISTINCT c.customer_id)::int AS customers
       FROM conversations c
      WHERE ${wsSql} ${ownedSql}
        AND EXISTS (
          SELECT 1 FROM messages m
           WHERE m.conversation_id=c.id
             AND m.sender_type='customer'
             AND m.created_at >= $2
        )`,
    params,{customers:0}
  );

  const assigned = await safeOne(
    `SELECT count(DISTINCT c.id)::int AS n
       FROM conversations c
      WHERE ${wsSql}
        AND c.assigned_user_id IS NOT NULL
        ${unrestricted ? '' : `AND c.assigned_user_id = ANY($3::varchar[])`}
        AND c.updated_at >= $2`,
    params,{n:0}
  );

  const deleted = await safeOne(
    `SELECT count(DISTINCT c.id)::int AS n
       FROM conversations c
      WHERE ${wsSql}
        AND c.status='deleted'
        ${ownedSql}
        AND c.updated_at >= $2`,
    params,{n:0}
  );

  const resolved = await safeOne(
    `SELECT count(DISTINCT c.id)::int AS n
       FROM conversations c
      WHERE ${wsSql}
        AND c.status='resolved'
        ${ownedSql}
        AND c.updated_at >= $2`,
    params,{n:0}
  );

  const active = await safeOne(
    `SELECT count(*)::int AS n
       FROM conversations c
      WHERE ${wsSql}
        AND c.status='in_progress'
        ${ownedSql}`,
    params,{n:0}
  );

  let totalCustomers;
  if (unrestricted) {
    totalCustomers = await safeOne(
      `SELECT count(*)::int AS n FROM customers cu WHERE ($1::uuid IS NULL OR cu.workspace_id=$1)`,
      [ws],{n:0}
    );
  } else {
    totalCustomers = await safeOne(
      `SELECT count(DISTINCT c.customer_id)::int AS n
         FROM conversations c
        WHERE ${wsSql} AND c.assigned_user_id = ANY($3::varchar[])`,
      params,{n:0}
    );
  }

  let waiting;
  if (unrestricted) {
    waiting = await safeOne(
      `SELECT count(*)::int AS n,
              COALESCE(EXTRACT(EPOCH FROM (now()-min(c.created_at)))::int,0) AS oldest_seconds
         FROM conversations c
        WHERE c.status='waiting' AND ${wsSql}`,
      params,{n:0,oldest_seconds:0}
    );
  } else {
    waiting = await safeOne(
      `SELECT count(DISTINCT c.id)::int AS n,
              COALESCE(EXTRACT(EPOCH FROM (now()-min(c.created_at)))::int,0) AS oldest_seconds
         FROM conversations c
        WHERE c.status='waiting'
          AND c.assigned_user_id IS NULL
          AND ${wsSql}
          AND EXISTS (
            SELECT 1 FROM bot_assignments ba
             WHERE ba.bot_id=c.bot_id
               AND ba.user_id = ANY($3::varchar[])
               AND ba.can_read=true
          )`,
      params,{n:0,oldest_seconds:0}
    );
  }

  const avgResponse = await safeOne(
    `WITH scoped AS (
       SELECT c.id
         FROM conversations c
        WHERE ${wsSql} ${ownedSql}
     ), firsts AS (
       SELECT s.id,
              (SELECT min(m.created_at) FROM messages m WHERE m.conversation_id=s.id AND m.sender_type='customer' AND m.created_at >= $2) AS first_customer,
              (SELECT min(m.created_at) FROM messages m WHERE m.conversation_id=s.id AND m.sender_type IN ('agent','bot') AND m.created_at >= $2) AS first_reply
         FROM scoped s
     )
     SELECT COALESCE(avg(EXTRACT(EPOCH FROM (first_reply-first_customer)))
              FILTER (WHERE first_customer IS NOT NULL AND first_reply>=first_customer),0)::int AS seconds
       FROM firsts`,
    params,{seconds:0}
  );

  let team=[];
  try {
    const userParams=[];
    const where=[`u.status='active'`,`u.role IN ('WORKSPACE_ADMIN','TEAM_ADMIN','AGENT')`];
    if (ws) { userParams.push(ws); where.push(`u.workspace_id=$${userParams.length}`); }
    if (!unrestricted) { userParams.push(ids); where.push(`u.id = ANY($${userParams.length}::varchar[])`); }
    userParams.push(start); const sp=userParams.length;
    const {rows}=await pool.query(
      `SELECT u.id,u.name,u.role,
              (SELECT count(*)::int FROM conversations c WHERE c.assigned_user_id=u.id AND c.status='in_progress') AS active_now,
              (SELECT count(*)::int FROM conversations c WHERE c.assigned_user_id=u.id AND c.updated_at >= $${sp}) AS assigned_period,
              (SELECT count(*)::int FROM conversations c WHERE c.assigned_user_id=u.id AND c.status='deleted' AND c.updated_at >= $${sp}) AS deleted_period,
              (SELECT count(*)::int FROM messages m WHERE m.sender_user_id=u.id AND m.sender_type='agent' AND m.created_at >= $${sp} AND m.deleted_at IS NULL) AS replies_period
         FROM users u
        WHERE ${where.join(' AND ')}
        ORDER BY CASE u.role WHEN 'WORKSPACE_ADMIN' THEN 1 WHEN 'TEAM_ADMIN' THEN 2 ELSE 3 END,u.name
        LIMIT 100`, userParams
    );
    team=rows;
  } catch (err) {
    console.error('Dashboard team query failed:', err.message);
    // Compatibility fallback for databases that predate message soft-delete columns.
    try {
      const userParams=[];
      const where=[`u.status='active'`,`u.role IN ('WORKSPACE_ADMIN','TEAM_ADMIN','AGENT')`];
      if (ws) { userParams.push(ws); where.push(`u.workspace_id=$${userParams.length}`); }
      if (!unrestricted) { userParams.push(ids); where.push(`u.id = ANY($${userParams.length}::varchar[])`); }
      userParams.push(start); const sp=userParams.length;
      const {rows}=await pool.query(
        `SELECT u.id,u.name,u.role,
                (SELECT count(*)::int FROM conversations c WHERE c.assigned_user_id=u.id AND c.status='in_progress') AS active_now,
                (SELECT count(*)::int FROM conversations c WHERE c.assigned_user_id=u.id AND c.updated_at >= $${sp}) AS assigned_period,
                (SELECT count(*)::int FROM conversations c WHERE c.assigned_user_id=u.id AND c.status='deleted' AND c.updated_at >= $${sp}) AS deleted_period,
                (SELECT count(*)::int FROM messages m WHERE m.sender_user_id=u.id AND m.sender_type='agent' AND m.created_at >= $${sp}) AS replies_period
           FROM users u
          WHERE ${where.join(' AND ')}
          ORDER BY CASE u.role WHEN 'WORKSPACE_ADMIN' THEN 1 WHEN 'TEAM_ADMIN' THEN 2 ELSE 3 END,u.name
          LIMIT 100`, userParams
      );
      team=rows;
    } catch (fallbackErr) {
      console.error('Dashboard team fallback failed:', fallbackErr.message);
      team=[];
    }
  }

  res.json({
    period,
    periodStart:start.toISOString(),
    scope:req.user.role==='MASTER_ADMIN'?(ws?'workspace':'all_workspaces'):req.user.role==='WORKSPACE_ADMIN'?'workspace':req.user.role==='TEAM_ADMIN'?'team':'self',
    metrics:{
      received:Number(received.customers||0),
      assigned:Number(assigned.n||0),
      deleted:Number(deleted.n||0),
      resolved:Number(resolved.n||0),
      inProgress:Number(active.n||0),
      waiting:Number(waiting.n||0),
      totalCustomers:Number(totalCustomers.n||0),
      avgFirstResponseSeconds:Number(avgResponse.seconds||0),
      oldestWaitingSeconds:Number(waiting.oldest_seconds||0)
    },
    team
  });
}));

app.get('/api/conversations/:conversationId/messages', auth, asyncRoute(async (req,res) => {
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  const { rows } = await pool.query(
    `SELECT id,sender_type,sender_user_id,body,media,external_message_id,created_at,deleted_at,deleted_by,telegram_deleted
       FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC LIMIT 1000`, [conversation.id]
  );
  await pool.query('UPDATE conversations SET unread_count=0 WHERE id=$1', [conversation.id]);
  res.json({ conversation, items:rows });
}));

app.post('/api/conversations/:conversationId/messages', auth, asyncRoute(async (req,res) => {
  const input = z.object({ text:z.string().min(1).max(4096) }).parse(req.body);
  const conversation = await getConversationForUser(req, req.params.conversationId, true);
  if (!conversation) return res.status(403).json({ error:'You do not have reply permission for this conversation' });
  if (['resolved','deleted'].includes(conversation.status)) return res.status(409).json({ error:'This conversation is in History. Wait for a new customer message to reopen it.' });
  if (conversation.status === 'waiting' || !conversation.assigned_user_id) return res.status(409).json({ error:'Assign the waiting conversation before replying.' });
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
  await pool.query(`UPDATE conversations SET unread_count=0,last_message_at=now(),updated_at=now() WHERE id=$1`, [conversation.id]);
  await audit(req,'conversation.reply','conversation',conversation.id,{botId:conversation.bot_id});
  res.status(201).json({ item:saved });
}));

app.post('/api/conversations/:conversationId/claim', auth, allow('WORKSPACE_ADMIN','TEAM_ADMIN','AGENT'), asyncRoute(async (req,res) => {
  const conversation = await getConversationForUser(req, req.params.conversationId, true);
  if (!conversation) return res.status(403).json({ error:'You do not have reply permission for this conversation' });
  if (conversation.status !== 'waiting') return res.status(409).json({ error:'Only waiting conversations can be assigned' });
  if (conversation.assigned_user_id && conversation.assigned_user_id !== req.user.id) return res.status(409).json({ error:'Conversation is already assigned to another account' });
  await pool.query(`UPDATE conversations SET assigned_user_id=$2,status='in_progress',assigned_at=now(),resolved_at=NULL,deleted_at=NULL,deleted_by=NULL,waiting_since=NULL,updated_at=now() WHERE id=$1`, [conversation.id, req.user.id]);
  await pool.query(`INSERT INTO conversation_assignment_events(workspace_id,conversation_id,assigned_user_id,assigned_by) VALUES($1,$2,$3,$4)`, [conversation.workspace_id,conversation.id,req.user.id,req.user.id]);
  await audit(req,'conversation.claim','conversation',conversation.id,{userId:req.user.id});
  try { await sendAutomationMessage(conversation,'assigned',req.user.id,req.user.id); }
  catch (err) { console.warn('assigned auto message failed:', err.message); }
  res.json({ ok:true, assignedUserId:req.user.id, status:'in_progress' });
}));

app.post('/api/conversations/:conversationId/assign', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({ userId:z.string().min(1).nullable() }).parse(req.body);
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  if (['resolved','deleted'].includes(conversation.status) && input.userId) return res.status(409).json({ error:'History conversations cannot be assigned until a new customer message reopens them' });
  if (input.userId) {
    const { rows:[target] } = await pool.query(`SELECT id,workspace_id,parent_user_id,role FROM users WHERE id=$1 AND status='active'`, [input.userId]);
    if (!target || String(target.workspace_id) !== String(conversation.workspace_id)) return res.status(400).json({ error:'Assignee is not in this workspace' });
    if (!['WORKSPACE_ADMIN','TEAM_ADMIN','AGENT'].includes(target.role)) return res.status(400).json({ error:'Only Admin or Agent accounts can own conversations' });
    const { rows:[ba] } = await pool.query('SELECT can_read,can_reply FROM bot_assignments WHERE bot_id=$1 AND user_id=$2', [conversation.bot_id,target.id]);
    if (!ba?.can_read || !ba?.can_reply) return res.status(409).json({ error:'Assign this bot with read/reply permission to the selected ID before assigning the conversation' });
    if (req.user.role === 'TEAM_ADMIN' && target.parent_user_id !== req.user.id && target.id !== req.user.id) return res.status(403).json({ error:'Team admin can assign only within own branch' });
  }
  await pool.query(
    `UPDATE conversations SET assigned_user_id=$2,status=CASE WHEN $2 IS NULL THEN 'waiting' ELSE 'in_progress' END,
       assigned_at=CASE WHEN $2 IS NULL THEN NULL ELSE now() END,resolved_at=NULL,deleted_at=NULL,deleted_by=NULL,
       waiting_since=CASE WHEN $2 IS NULL THEN now() ELSE NULL END,updated_at=now() WHERE id=$1`,
    [conversation.id,input.userId]
  );
  await pool.query(`INSERT INTO conversation_assignment_events(workspace_id,conversation_id,assigned_user_id,assigned_by) VALUES($1,$2,$3,$4)`, [conversation.workspace_id,conversation.id,input.userId,req.user.id]);
  await audit(req,'conversation.assign','conversation',conversation.id,{userId:input.userId});
  if (input.userId) {
    try { await sendAutomationMessage(conversation,'assigned',req.user.id,input.userId); }
    catch (err) { console.warn('assigned auto message failed:', err.message); }
  }
  res.json({ ok:true, assignedUserId:input.userId, status:input.userId?'in_progress':'waiting' });
}));

app.post('/api/conversations/:conversationId/resolve', auth, asyncRoute(async (req,res) => {
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  if (conversation.status === 'deleted') return res.status(409).json({ error:'Deleted conversation is already in History' });
  await pool.query(`UPDATE conversations SET status='resolved',unread_count=0,resolved_at=now(),deleted_at=NULL,deleted_by=NULL,waiting_since=NULL,updated_at=now() WHERE id=$1`, [conversation.id]);
  await audit(req,'conversation.resolve','conversation',conversation.id,{});
  res.json({ ok:true, status:'resolved' });
}));

app.delete('/api/conversations/:conversationId', auth, asyncRoute(async (req,res) => {
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  if (req.user.role === 'VIEWER') return res.status(403).json({ error:'Viewer cannot delete conversations' });
  if (req.user.role === 'AGENT' && conversation.assigned_user_id !== req.user.id) return res.status(403).json({ error:'Agents can delete only conversations assigned to themselves' });
  if (conversation.status === 'deleted') return res.json({ ok:true, alreadyDeleted:true, status:'deleted' });
  await pool.query(`UPDATE conversations SET status='deleted',unread_count=0,deleted_at=now(),deleted_by=$2,resolved_at=NULL,waiting_since=NULL,updated_at=now() WHERE id=$1`, [conversation.id,req.user.id]);
  await audit(req,'conversation.delete','conversation',conversation.id,{assignedUserId:conversation.assigned_user_id});
  res.json({ ok:true, status:'deleted' });
}));


app.get('/api/tags', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws) return res.json({ items:[] });
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id) !== String(ws)) return res.status(403).json({ error:'Cross-workspace tag access denied' });
  const { rows } = await pool.query(
    `SELECT wt.id,wt.workspace_id,wt.name,wt.created_at,
            COALESCE((SELECT count(*)::int FROM customers c WHERE c.workspace_id=wt.workspace_id AND wt.name=ANY(c.tags)),0) AS usage_count
       FROM workspace_tags wt
      WHERE wt.workspace_id=$1
      ORDER BY lower(wt.name)`, [ws]
  );
  res.json({ items:rows });
}));

app.post('/api/tags', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN','AGENT'), asyncRoute(async (req,res) => {
  const input = z.object({ workspaceId:z.string().uuid().optional(), name:z.string().trim().min(1).max(40) }).parse(req.body);
  const ws = workspaceScope(req, input.workspaceId);
  if (!ws) return res.status(400).json({ error:'workspaceId is required' });
  const inserted = await pool.query(
    `INSERT INTO workspace_tags(workspace_id,name,created_by)
     VALUES($1,$2,$3)
     ON CONFLICT DO NOTHING
     RETURNING id,workspace_id,name,created_at`,
    [ws,input.name,req.user.id]
  );
  const item = inserted.rows[0] || (await pool.query(
    `SELECT id,workspace_id,name,created_at FROM workspace_tags WHERE workspace_id=$1 AND lower(name)=lower($2) LIMIT 1`,
    [ws,input.name]
  )).rows[0];
  await audit(req,'tag.create','tag',item.id,{name:item.name});
  res.status(inserted.rows[0] ? 201 : 200).json({ item });
}));

app.delete('/api/tags/:tagId', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN'), asyncRoute(async (req,res) => {
  const { rows:[tag] } = await pool.query('SELECT * FROM workspace_tags WHERE id=$1', [req.params.tagId]);
  if (!tag) return res.status(404).json({ error:'Tag not found' });
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id) !== String(tag.workspace_id)) return res.status(403).json({ error:'Cross-workspace tag access denied' });
  await pool.query(`UPDATE customers SET tags=array_remove(tags,$2),updated_at=now() WHERE workspace_id=$1`, [tag.workspace_id,tag.name]);
  await pool.query('DELETE FROM workspace_tags WHERE id=$1', [tag.id]);
  await audit(req,'tag.delete','tag',tag.id,{name:tag.name});
  res.json({ ok:true });
}));

app.put('/api/conversations/:conversationId/tags', auth, asyncRoute(async (req,res) => {
  const input = z.object({ tags:z.array(z.string().trim().min(1).max(40)).max(30) }).parse(req.body);
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  if (req.user.role === 'VIEWER') return res.status(403).json({ error:'Viewer cannot edit tags' });
  const unique = [...new Set(input.tags.map(x=>x.trim()).filter(Boolean))];
  if (unique.length) {
    const { rows } = await pool.query(`SELECT name FROM workspace_tags WHERE workspace_id=$1 AND name = ANY($2::text[])`, [conversation.workspace_id,unique]);
    if (rows.length !== unique.length) return res.status(400).json({ error:'One or more tags are not defined in this workspace' });
  }
  await pool.query(`UPDATE customers SET tags=$2::text[],updated_at=now() WHERE id=$1`, [conversation.customer_id,unique]);
  await audit(req,'conversation.tags','conversation',conversation.id,{tags:unique});
  res.json({ ok:true, tags:unique });
}));

app.put('/api/conversations/:conversationId/remark', auth, asyncRoute(async (req,res) => {
  const input = z.object({ remark:z.string().max(2000) }).parse(req.body);
  const conversation = await getConversationForUser(req, req.params.conversationId, false);
  if (!conversation) return res.status(404).json({ error:'Conversation not found in your scope' });
  if (req.user.role === 'VIEWER') return res.status(403).json({ error:'Viewer cannot edit remarks' });
  await pool.query(`UPDATE conversations SET remark=$2,remark_updated_by=$3,remark_updated_at=now(),updated_at=now() WHERE id=$1`, [conversation.id,input.remark.trim(),req.user.id]);
  await audit(req,'conversation.remark','conversation',conversation.id,{length:input.remark.trim().length});
  res.json({ ok:true, remark:input.remark.trim() });
}));

app.post('/api/messages/:messageId/translate', auth, asyncRoute(async (req,res) => {
  const input = z.object({ targetLanguage:z.enum(['en','zh-CN']) }).parse(req.body);
  const { rows:[message] } = await pool.query(
    `SELECT m.id,m.conversation_id,m.body,m.deleted_at
       FROM messages m WHERE m.id=$1`, [req.params.messageId]
  );
  if (!message) return res.status(404).json({ error:'Message not found' });
  const conversation = await getConversationForUser(req, message.conversation_id, false);
  if (!conversation) return res.status(404).json({ error:'Message is outside your conversation scope' });
  if (message.deleted_at || !message.body) return res.status(409).json({ error:'Deleted or empty messages cannot be translated' });
  const { rows:[cached] } = await pool.query(`SELECT translated_text,detected_source_language,provider FROM message_translations WHERE message_id=$1 AND target_language=$2`, [message.id,input.targetLanguage]);
  if (cached) return res.json({ ok:true, cached:true, translatedText:cached.translated_text, detectedSourceLanguage:cached.detected_source_language, provider:cached.provider });
  const translated = await translateText(message.body,input.targetLanguage);
  await pool.query(
    `INSERT INTO message_translations(message_id,target_language,translated_text,detected_source_language,provider)
     VALUES($1,$2,$3,$4,$5)
     ON CONFLICT(message_id,target_language) DO UPDATE SET translated_text=excluded.translated_text,detected_source_language=excluded.detected_source_language,provider=excluded.provider,created_at=now()`,
    [message.id,input.targetLanguage,translated.text,translated.detectedSourceLanguage,translated.provider]
  );
  res.json({ ok:true, cached:false, translatedText:translated.text, detectedSourceLanguage:translated.detectedSourceLanguage, provider:translated.provider });
}));

app.delete('/api/messages/:messageId', auth, asyncRoute(async (req,res) => {
  const { rows:[message] } = await pool.query(
    `SELECT m.*,c.bot_id,c.workspace_id,c.customer_id,b.token_ciphertext,b.token_iv,b.token_tag,cu.metadata AS customer_metadata
       FROM messages m
       JOIN conversations c ON c.id=m.conversation_id
       JOIN bots b ON b.id=c.bot_id
       JOIN customers cu ON cu.id=c.customer_id
      WHERE m.id=$1`, [req.params.messageId]
  );
  if (!message) return res.status(404).json({ error:'Message not found' });
  const conversation = await getConversationForUser(req, message.conversation_id, true);
  if (!conversation) return res.status(403).json({ error:'You do not have permission to delete this message' });
  if (message.deleted_at) return res.json({ ok:true, alreadyDeleted:true, remoteDeleted:Boolean(message.telegram_deleted) });
  const supervisor = ['MASTER_ADMIN','WORKSPACE_ADMIN'].includes(req.user.role);
  const ownOutbound = message.sender_type !== 'customer' && message.sender_user_id === req.user.id;
  if (!supervisor && !ownOutbound) return res.status(403).json({ error:'Agents can delete only messages they sent. Workspace/Master Admin can delete any message in scope.' });

  let remoteDeleted=false, remoteError=null;
  const external = String(message.external_message_id || '');
  const split = external.lastIndexOf(':');
  if (split > 0) {
    const chatId = external.slice(0,split);
    const messageId = Number(external.slice(split+1));
    if (chatId && Number.isInteger(messageId)) {
      try {
        const bot = { token_ciphertext:message.token_ciphertext, token_iv:message.token_iv, token_tag:message.token_tag };
        const botToken = decryptToken(bot);
        remoteDeleted = Boolean(await telegramApi(botToken,'deleteMessage',{chat_id:chatId,message_id:messageId}));
      } catch (err) {
        remoteError = err.message;
      }
    }
  }
  await pool.query(`UPDATE messages SET body=NULL,media=NULL,deleted_at=now(),deleted_by=$2,telegram_deleted=$3 WHERE id=$1`, [message.id,req.user.id,remoteDeleted]);
  await pool.query('DELETE FROM message_translations WHERE message_id=$1', [message.id]);
  await pool.query(`UPDATE conversations SET last_message_at=(SELECT max(created_at) FROM messages WHERE conversation_id=$1 AND deleted_at IS NULL),updated_at=now() WHERE id=$1`, [message.conversation_id]);
  await audit(req,'message.delete','message',message.id,{conversationId:message.conversation_id,remoteDeleted,remoteError});
  res.json({ ok:true, remoteDeleted, remoteError });
}));

app.get('/api/customers', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws) return res.json({items:[]});
  let rows=[];
  if (['MASTER_ADMIN','WORKSPACE_ADMIN'].includes(req.user.role)) {
    ({ rows } = await pool.query(`SELECT id,workspace_id,platform,external_user_id,display_name,tags,metadata,updated_at,created_at FROM customers WHERE workspace_id=$1 ORDER BY updated_at DESC LIMIT 500`, [ws]));
  } else {
    ({ rows } = await pool.query(
      `SELECT DISTINCT cu.id,cu.workspace_id,cu.platform,cu.external_user_id,cu.display_name,cu.tags,cu.metadata,cu.updated_at,cu.created_at
         FROM customers cu
         JOIN conversations c ON c.customer_id=cu.id
         JOIN bot_assignments ba ON ba.bot_id=c.bot_id AND ba.user_id=$2 AND ba.can_read=true
        WHERE cu.workspace_id=$1 ORDER BY cu.updated_at DESC LIMIT 500`, [ws, req.user.id]
    ));
  }
  res.json({items:rows});
}));


// ---- DLXN17 V4 Remake: chat uploads -------------------------------------------------
app.post('/api/conversations/:conversationId/media', auth, asyncRoute(async (req,res) => {
  const input = z.object({
    filename:z.string().trim().min(1).max(255),
    mimeType:z.string().trim().min(1).max(120),
    kind:z.enum(['image','file']),
    dataBase64:z.string().min(8)
  }).parse(req.body);
  const conversation = await getConversationForUser(req, req.params.conversationId, true);
  if (!conversation) return res.status(403).json({ error:'You do not have reply permission for this conversation' });
  if (['resolved','deleted'].includes(conversation.status)) return res.status(409).json({ error:'This conversation is in History. Wait for a new customer message to reopen it.' });
  if (conversation.status === 'waiting' || !conversation.assigned_user_id) return res.status(409).json({ error:'Assign the waiting conversation before sending files.' });
  const buffer = decodeBase64Upload(input.dataBase64);
  const saved = await saveOutboundTelegramMedia(conversation,req.user.id,buffer,input.filename,input.mimeType,input.kind,{ source:'chat_upload' });
  await audit(req,'conversation.media.send','conversation',conversation.id,{filename:input.filename,mimeType:input.mimeType,size:buffer.length});
  res.status(201).json({ item:saved });
}));

// ---- Media Database ------------------------------------------------------------------
app.get('/api/media/categories', auth, asyncRoute(async (req,res) => {
  const ws = workspaceScope(req, req.query.workspaceId);
  if (!ws) return res.json({ items:[] });
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id) !== String(ws)) return res.status(403).json({ error:'Cross-workspace media access denied' });
  const { rows } = await pool.query(
    `SELECT mc.id,mc.workspace_id,mc.name,mc.description,mc.created_at,mc.updated_at,
            count(ma.id)::int AS asset_count,
            COALESCE(sum(ma.byte_size),0)::bigint AS total_bytes
       FROM media_categories mc
       LEFT JOIN media_assets ma ON ma.category_id=mc.id
      WHERE mc.workspace_id=$1
      GROUP BY mc.id
      ORDER BY lower(mc.name)`, [ws]
  );
  res.json({ items:rows });
}));

app.post('/api/media/categories', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({ workspaceId:z.string().uuid().optional(), name:z.string().trim().min(1).max(100), description:z.string().max(1000).optional().default('') }).parse(req.body);
  const ws = workspaceScope(req,input.workspaceId);
  if (!ws) return res.status(400).json({ error:'workspaceId is required' });
  const { rows:[item] } = await pool.query(
    `INSERT INTO media_categories(workspace_id,name,description,created_by) VALUES($1,$2,$3,$4) RETURNING *`,
    [ws,input.name,input.description||null,req.user.id]
  );
  await audit(req,'media.category.create','media_category',item.id,{workspaceId:ws,name:item.name});
  res.status(201).json({ item });
}));

app.delete('/api/media/categories/:categoryId', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const { rows:[category] } = await pool.query('SELECT * FROM media_categories WHERE id=$1',[req.params.categoryId]);
  if (!category) return res.status(404).json({ error:'Media category not found' });
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id)!==String(category.workspace_id)) return res.status(403).json({ error:'Cross-workspace media access denied' });
  await pool.query('DELETE FROM media_categories WHERE id=$1',[category.id]);
  await audit(req,'media.category.delete','media_category',category.id,{name:category.name});
  res.json({ok:true});
}));

app.get('/api/media/categories/:categoryId/assets', auth, asyncRoute(async (req,res) => {
  const { rows:[category] } = await pool.query('SELECT * FROM media_categories WHERE id=$1',[req.params.categoryId]);
  if (!category) return res.status(404).json({ error:'Media category not found' });
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id)!==String(category.workspace_id)) return res.status(403).json({ error:'Cross-workspace media access denied' });
  const { rows } = await pool.query(
    `SELECT id,workspace_id,category_id,filename,mime_type,byte_size,created_at FROM media_assets WHERE category_id=$1 ORDER BY created_at ASC,id ASC`,
    [category.id]
  );
  res.json({ category:{id:category.id,name:category.name,description:category.description}, items:rows });
}));

app.post('/api/media/categories/:categoryId/assets', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input = z.object({ filename:z.string().trim().min(1).max(255), mimeType:z.string().trim().min(1).max(120), dataBase64:z.string().min(8) }).parse(req.body);
  const { rows:[category] } = await pool.query('SELECT * FROM media_categories WHERE id=$1',[req.params.categoryId]);
  if (!category) return res.status(404).json({ error:'Media category not found' });
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id)!==String(category.workspace_id)) return res.status(403).json({ error:'Cross-workspace media access denied' });
  if (!input.mimeType.startsWith('image/')) return res.status(400).json({ error:'Media Database categories currently accept images only' });
  const buffer=decodeBase64Upload(input.dataBase64);
  const { rows:[item] }=await pool.query(
    `INSERT INTO media_assets(workspace_id,category_id,filename,mime_type,byte_size,file_data,created_by)
     VALUES($1,$2,$3,$4,$5,$6,$7)
     RETURNING id,workspace_id,category_id,filename,mime_type,byte_size,created_at`,
    [category.workspace_id,category.id,input.filename,input.mimeType,buffer.length,buffer,req.user.id]
  );
  await audit(req,'media.asset.upload','media_asset',item.id,{categoryId:category.id,filename:item.filename,size:item.byte_size});
  res.status(201).json({item});
}));

app.delete('/api/media/assets/:assetId', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const { rows:[asset] }=await pool.query('SELECT id,workspace_id,category_id,filename FROM media_assets WHERE id=$1',[req.params.assetId]);
  if (!asset) return res.status(404).json({error:'Media asset not found'});
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id)!==String(asset.workspace_id)) return res.status(403).json({ error:'Cross-workspace media access denied' });
  await pool.query('DELETE FROM media_assets WHERE id=$1',[asset.id]);
  await audit(req,'media.asset.delete','media_asset',asset.id,{filename:asset.filename,categoryId:asset.category_id});
  res.json({ok:true});
}));

app.post('/api/conversations/:conversationId/media-assets/:assetId/send', auth, asyncRoute(async (req,res) => {
  const conversation=await getConversationForUser(req,req.params.conversationId,true);
  if (!conversation) return res.status(403).json({error:'You do not have reply permission for this conversation'});
  if (conversation.status==='waiting'||!conversation.assigned_user_id) return res.status(409).json({error:'Assign the waiting conversation before sending media'});
  if (['resolved','deleted'].includes(conversation.status)) return res.status(409).json({error:'History conversations are read-only'});
  const { rows:[asset] }=await pool.query('SELECT * FROM media_assets WHERE id=$1',[req.params.assetId]);
  if (!asset || String(asset.workspace_id)!==String(conversation.workspace_id)) return res.status(404).json({error:'Media asset not found in this workspace'});
  const saved=await saveOutboundTelegramMedia(conversation,req.user.id,asset.file_data,asset.filename,asset.mime_type,'image',{source:'media_database',assetId:asset.id,categoryId:asset.category_id});
  await audit(req,'media.asset.send','conversation',conversation.id,{assetId:asset.id,categoryId:asset.category_id,filename:asset.filename});
  res.status(201).json({item:saved});
}));

// ---- Quick replies and automatic messages --------------------------------------------
app.get('/api/quick-messages', auth, asyncRoute(async (req,res) => {
  const ws=workspaceScope(req,req.query.workspaceId);
  if (!ws) return res.json({quickReplies:[],automations:[]});
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id)!==String(ws)) return res.status(403).json({error:'Cross-workspace quick message access denied'});
  const { rows:quickReplies }=await pool.query(`SELECT id,workspace_id,title,body,sort_order,enabled,created_at,updated_at FROM quick_replies WHERE workspace_id=$1 ORDER BY sort_order,created_at`,[ws]);
  const { rows:autoRows }=await pool.query(`SELECT workspace_id,trigger_type,enabled,body,updated_at FROM automation_messages WHERE workspace_id=$1`,[ws]);
  const byType=Object.fromEntries(autoRows.map(x=>[x.trigger_type,x]));
  const automations=['new_customer','assigned'].map(triggerType=>byType[triggerType]||{workspace_id:ws,trigger_type:triggerType,enabled:false,body:triggerType==='new_customer'?'Hello! Thanks for contacting us. An agent will assist you shortly.':'Your chat has been assigned. I will assist you from here.'});
  res.json({quickReplies,automations});
}));

app.put('/api/automation-messages/:triggerType', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const triggerType=String(req.params.triggerType);
  if (!['new_customer','assigned'].includes(triggerType)) return res.status(400).json({error:'Invalid automation trigger'});
  const input=z.object({workspaceId:z.string().uuid().optional(),enabled:z.boolean(),body:z.string().max(4096)}).parse(req.body);
  const ws=workspaceScope(req,input.workspaceId);
  if (!ws) return res.status(400).json({error:'workspaceId is required'});
  const { rows:[item] }=await pool.query(
    `INSERT INTO automation_messages(workspace_id,trigger_type,enabled,body,updated_by)
     VALUES($1,$2,$3,$4,$5)
     ON CONFLICT(workspace_id,trigger_type) DO UPDATE SET enabled=excluded.enabled,body=excluded.body,updated_by=excluded.updated_by,updated_at=now()
     RETURNING workspace_id,trigger_type,enabled,body,updated_at`,
    [ws,triggerType,input.enabled,input.body.trim(),req.user.id]
  );
  await audit(req,'automation_message.update','automation_message',triggerType,{workspaceId:ws,enabled:input.enabled});
  res.json({item});
}));

app.post('/api/quick-replies', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input=z.object({workspaceId:z.string().uuid().optional(),title:z.string().trim().min(1).max(80),body:z.string().trim().min(1).max(4096)}).parse(req.body);
  const ws=workspaceScope(req,input.workspaceId);
  if (!ws) return res.status(400).json({error:'workspaceId is required'});
  const { rows:[item] }=await pool.query(`INSERT INTO quick_replies(workspace_id,title,body,created_by) VALUES($1,$2,$3,$4) RETURNING *`,[ws,input.title,input.body,req.user.id]);
  await audit(req,'quick_reply.create','quick_reply',item.id,{workspaceId:ws,title:item.title});
  res.status(201).json({item});
}));

app.put('/api/quick-replies/:replyId', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const input=z.object({title:z.string().trim().min(1).max(80),body:z.string().trim().min(1).max(4096),enabled:z.boolean().optional().default(true)}).parse(req.body);
  const { rows:[existing] }=await pool.query('SELECT * FROM quick_replies WHERE id=$1',[req.params.replyId]);
  if (!existing) return res.status(404).json({error:'Quick reply not found'});
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id)!==String(existing.workspace_id)) return res.status(403).json({error:'Cross-workspace quick message access denied'});
  const { rows:[item] }=await pool.query(`UPDATE quick_replies SET title=$2,body=$3,enabled=$4,updated_at=now() WHERE id=$1 RETURNING *`,[existing.id,input.title,input.body,input.enabled]);
  await audit(req,'quick_reply.update','quick_reply',item.id,{title:item.title,enabled:item.enabled});
  res.json({item});
}));

app.delete('/api/quick-replies/:replyId', auth, allow('MASTER_ADMIN','WORKSPACE_ADMIN','TEAM_ADMIN'), asyncRoute(async (req,res) => {
  const { rows:[existing] }=await pool.query('SELECT * FROM quick_replies WHERE id=$1',[req.params.replyId]);
  if (!existing) return res.status(404).json({error:'Quick reply not found'});
  if (req.user.role !== 'MASTER_ADMIN' && String(req.user.workspace_id)!==String(existing.workspace_id)) return res.status(403).json({error:'Cross-workspace quick message access denied'});
  await pool.query('DELETE FROM quick_replies WHERE id=$1',[existing.id]);
  await audit(req,'quick_reply.delete','quick_reply',existing.id,{title:existing.title});
  res.json({ok:true});
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

async function runDataMigrations() {
  const migrationKey = 'v3-one-thread-per-bot-customer';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [migrationKey]);
    const { rows:[done] } = await client.query('SELECT migration_key FROM system_migrations WHERE migration_key=$1', [migrationKey]);
    if (!done) {
      const { rows:groups } = await client.query(
        `SELECT bot_id,customer_id,count(*)::int AS n
           FROM conversations
          WHERE bot_id IS NOT NULL
          GROUP BY bot_id,customer_id
         HAVING count(*) > 1`
      );
      for (const group of groups) {
        const { rows:items } = await client.query(
          `SELECT id,status,assigned_user_id,unread_count,last_message_at,created_at,remark,remark_updated_at
             FROM conversations
            WHERE bot_id=$1 AND customer_id=$2
            ORDER BY created_at ASC FOR UPDATE`,
          [group.bot_id,group.customer_id]
        );
        if (items.length < 2) continue;
        const canonical = items[0];
        const latest = items[items.length-1];
        const duplicates = items.slice(1);
        let unread = items.reduce((n,x)=>n+Number(x.unread_count||0),0);
        let lastMessage = items.map(x=>x.last_message_at).filter(Boolean).sort().at(-1) || latest.last_message_at || canonical.last_message_at;
        const remarkItem = [...items].reverse().find(x=>x.remark);
        for (const dup of duplicates) {
          await client.query(
            `DELETE FROM messages d
              USING messages k
             WHERE d.conversation_id=$1 AND k.conversation_id=$2
               AND d.external_message_id IS NOT NULL
               AND d.external_message_id=k.external_message_id`,
            [dup.id,canonical.id]
          );
          await client.query('UPDATE messages SET conversation_id=$1 WHERE conversation_id=$2', [canonical.id,dup.id]);
          await client.query('DELETE FROM conversations WHERE id=$1', [dup.id]);
        }
        await client.query(
          `UPDATE conversations
              SET status=$2,assigned_user_id=$3,unread_count=$4,last_message_at=$5,
                  remark=COALESCE($6,remark),remark_updated_at=COALESCE($7,remark_updated_at),updated_at=now()
            WHERE id=$1`,
          [canonical.id,latest.status,latest.assigned_user_id,unread,lastMessage,remarkItem?.remark||null,remarkItem?.remark_updated_at||null]
        );
      }
      await client.query(
        `INSERT INTO workspace_tags(workspace_id,name)
         SELECT DISTINCT c.workspace_id,t.tag
           FROM customers c CROSS JOIN LATERAL unnest(c.tags) AS t(tag)
          WHERE trim(t.tag)<>''
         ON CONFLICT DO NOTHING`
      );
      await client.query('INSERT INTO system_migrations(migration_key) VALUES($1) ON CONFLICT DO NOTHING', [migrationKey]);
    }
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_conversations_bot_customer ON conversations(bot_id,customer_id) WHERE bot_id IS NOT NULL`);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function runV4DataMigrations() {
  const migrationKey = 'v4-queue-dashboard-lifecycle';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [migrationKey]);
    const { rows:[done] } = await client.query('SELECT migration_key FROM system_migrations WHERE migration_key=$1', [migrationKey]);
    if (!done) {
      await client.query(`UPDATE conversations SET assigned_at=COALESCE(assigned_at,updated_at,created_at) WHERE assigned_user_id IS NOT NULL AND assigned_at IS NULL`);
      await client.query(`UPDATE conversations SET resolved_at=COALESCE(resolved_at,updated_at) WHERE status='resolved' AND resolved_at IS NULL`);
      await client.query(`UPDATE conversations SET waiting_since=COALESCE(waiting_since,created_at) WHERE status='waiting' AND waiting_since IS NULL`);
      await client.query(
        `INSERT INTO conversation_assignment_events(workspace_id,conversation_id,assigned_user_id,assigned_by,created_at)
         SELECT c.workspace_id,c.id,c.assigned_user_id,c.assigned_user_id,COALESCE(c.assigned_at,c.updated_at,c.created_at)
           FROM conversations c
          WHERE c.assigned_user_id IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM conversation_assignment_events ae WHERE ae.conversation_id=c.id)
         ON CONFLICT DO NOTHING`
      );
      await client.query('INSERT INTO system_migrations(migration_key) VALUES($1) ON CONFLICT DO NOTHING', [migrationKey]);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally { client.release(); }
}

async function initializeDatabase() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');
  const schemaPath = path.join(__dirname, 'sql', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(schema);
  await runDataMigrations();
  await runV4DataMigrations();
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
  if (err.code === 'UPLOAD_TOO_LARGE') return res.status(413).json({ error:err.message });
  if (err.code === 'TRANSLATION_NOT_CONFIGURED') return res.status(503).json({ error:err.message, code:err.code });
  if (err.code === 'TRANSLATION_API_ERROR') return res.status(502).json({ error:err.message, code:err.code });
  res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message });
});

module.exports = app;
if (!process.env.VERCEL && require.main === module) {
  ensureReady()
    .then(() => app.listen(PORT, () => console.log(`DLXN17 Customer Support running on :${PORT}`)))
    .catch(err => { console.error('Startup failed:', err.message); process.exitCode = 1; });
}
