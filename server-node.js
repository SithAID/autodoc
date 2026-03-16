const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');

const { webcrypto } = require('crypto');
const crypto = webcrypto;

const ROOT    = __dirname;
const PORT    = parseInt(process.env.PORT || '8788');
const VARS    = loadDevVars();
const DB_FILE = path.join(ROOT, '.wrangler', 'state', 'localdb.json');

function loadDevVars() {
  const vars = {};
  const file = path.join(__dirname, '.dev.vars');
  if (!fs.existsSync(file)) return vars;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) vars[m[1]] = m[2].trim();
  }
  return vars;
}

const env = {
  JWT_SECRET:     VARS.JWT_SECRET     || 'local-dev-secret-change-this-in-production-min32',
  GEMINI_API_KEY: VARS.GEMINI_API_KEY || '',
  OPENAI_API_KEY: VARS.OPENAI_API_KEY || '',
  GROK_API_KEY:   VARS.GROK_API_KEY   || '',
  CLAUDE_API_KEY: VARS.CLAUDE_API_KEY || '',
};

const kvStore = new Map();
let kvDirty = false;

function loadKV() {
  try {
    if (!fs.existsSync(DB_FILE)) return;
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    for (const [k, v] of Object.entries(data)) kvStore.set(k, v);
  } catch {}
}

function saveKV() {
  if (!kvDirty) return;
  try {
    fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    const obj = {};
    for (const [k, v] of kvStore) obj[k] = v;
    fs.writeFileSync(DB_FILE, JSON.stringify(obj));
    kvDirty = false;
  } catch {}
}

setInterval(saveKV, 3000);
process.on('exit', saveKV);
process.on('SIGINT',  () => { saveKV(); process.exit(0); });
process.on('SIGTERM', () => { saveKV(); process.exit(0); });

loadKV();

const kv = {
  get:    async (key)        => kvStore.get(key) ?? null,
  put:    async (key, value) => { kvStore.set(key, value); kvDirty = true; },
  delete: async (key)        => { kvStore.delete(key); kvDirty = true; },
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff2':'font/woff2',
};

async function serveFile(filePath, res) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      const idx = path.join(filePath, 'index.html');
      if (fs.existsSync(idx)) return serveFile(idx, res);
      res.writeHead(404); res.end('Not found'); return;
    }
    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': mime,
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
    });
    fs.createReadStream(filePath).pipe(res);
  } catch {
    res.writeHead(404); res.end('Not found');
  }
}

function jsonRes(res, data, status = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  });
  res.end(body);
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 20480) reject(new Error('Body too large')); });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

async function fetchJSON(url, opts) {
  return new Promise((resolve, reject) => {
    const u   = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, { method: opts.method || 'GET', headers: opts.headers || {} }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json: () => JSON.parse(data) }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

global.fetch = async (url, opts = {}) => {
  const r = await fetchJSON(url, { ...opts, body: typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body) });
  return { ok: r.ok, status: r.status, json: async () => r.json() };
};

async function deriveEncKey(secret, context) {
  const enc    = new TextEncoder();
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(context), info: new Uint8Array() },
    keyMat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function aesEncrypt(plaintext, key) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  const buf = new Uint8Array(12 + enc.byteLength);
  buf.set(iv); buf.set(new Uint8Array(enc), 12);
  return Buffer.from(buf).toString('base64');
}

async function aesDecrypt(b64, key) {
  const buf = Buffer.from(b64, 'base64');
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
  return new TextDecoder().decode(dec);
}

async function hashPassword(password) {
  const salt   = crypto.getRandomValues(new Uint8Array(16));
  const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash   = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMat, 256);
  return Buffer.from(salt).toString('hex') + ':' + Buffer.from(hash).toString('hex');
}

async function verifyPassword(password, stored) {
  try {
    const [saltHex, hashHex] = stored.split(':');
    const salt   = Buffer.from(saltHex, 'hex');
    const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const hash   = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMat, 256);
    return Buffer.from(hash).toString('hex') === hashHex;
  } catch { return false; }
}

function b64url(str) { return Buffer.from(str).toString('base64url'); }
function b64urlDec(str) { return Buffer.from(str, 'base64url').toString('utf8'); }

async function signJWT(payload, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = b64url(JSON.stringify({ ...payload, iss: 'autodoc', iat: Math.floor(Date.now() / 1000) }));
  const data   = `${header}.${body}`;
  const key    = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${Buffer.from(sig).toString('base64url')}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const key   = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sig   = Buffer.from(parts[2], 'base64url');
  const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error('Invalid signature');
  const payload = JSON.parse(b64urlDec(parts[1]));
  if (payload.exp && Date.now() / 1000 > payload.exp) throw new Error('Token expired');
  if (payload.iss !== 'autodoc') throw new Error('Invalid issuer');
  return payload;
}

const rateLimits = new Map();
function rateLimit(key, max, windowMs, lockMs) {
  const now   = Date.now();
  let   entry = rateLimits.get(key) || { count: 0, firstAt: now, lockedUntil: 0 };
  if (entry.lockedUntil && now < entry.lockedUntil) return { blocked: true, retryAfter: Math.ceil((entry.lockedUntil - now) / 1000) };
  if (now - entry.firstAt > windowMs) entry = { count: 0, firstAt: now, lockedUntil: 0 };
  entry.count++;
  if (entry.count > max) { entry.lockedUntil = now + lockMs; rateLimits.set(key, entry); return { blocked: true, retryAfter: Math.ceil(lockMs / 1000) }; }
  rateLimits.set(key, entry);
  return { blocked: false };
}

function sanitize(str, maxLen = 200) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>"'`]/g, '');
}

async function getUser(email, dbKey) {
  const enc = await kv.get(`user:${email}`);
  if (!enc) return null;
  return JSON.parse(await aesDecrypt(enc, dbKey));
}

async function putUser(email, user, dbKey) {
  await kv.put(`user:${email}`, await aesEncrypt(JSON.stringify(user), dbKey));
}

async function getAuthUser(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) throw new Error('Authentication required.');
  return verifyJWT(auth.slice(7), env.JWT_SECRET);
}

async function handleSignup(req, res) {
  const ip = req.socket?.remoteAddress || 'unknown';
  const rl = rateLimit(`signup:${ip}`, 5, 15 * 60 * 1000, 30 * 60 * 1000);
  if (rl.blocked) return jsonRes(res, { error: `Too many attempts. Retry in ${rl.retryAfter}s.` }, 429);
  const body     = await readBody(req);
  const name     = sanitize(body.name || '', 80);
  const email    = sanitize(body.email || '', 120).toLowerCase();
  const password = body.password;
  if (!name)  return jsonRes(res, { error: 'Name is required.' }, 400);
  if (!email) return jsonRes(res, { error: 'Email is required.' }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonRes(res, { error: 'Enter a valid email address.' }, 400);
  if (!password || typeof password !== 'string') return jsonRes(res, { error: 'Password is required.' }, 400);
  if (password.length < 6)   return jsonRes(res, { error: 'Password must be at least 6 characters.' }, 400);
  if (password.length > 128) return jsonRes(res, { error: 'Password too long.' }, 400);
  const dbKey    = await deriveEncKey(env.JWT_SECRET, 'autodoc-db-v3');
  const existing = await getUser(email, dbKey);
  if (existing)  return jsonRes(res, { error: 'Email already registered.' }, 409);
  const hash  = await hashPassword(password);
  await putUser(email, { name, email, hash, createdAt: new Date().toISOString(), loginCount: 0, apiKeys: null }, dbKey);
  const token = await signJWT({ email, name, exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 }, env.JWT_SECRET);
  jsonRes(res, { token, user: { name, email } });
}

async function handleLogin(req, res) {
  const ip = req.socket?.remoteAddress || 'unknown';
  const rl = rateLimit(`login:${ip}`, 10, 15 * 60 * 1000, 15 * 60 * 1000);
  if (rl.blocked) return jsonRes(res, { error: `Too many attempts. Retry in ${rl.retryAfter}s.` }, 429);
  const body     = await readBody(req);
  const email    = sanitize(body.email || '', 120).toLowerCase();
  const password = body.password;
  if (!email || !password) return jsonRes(res, { error: 'Email and password are required.' }, 400);
  const dbKey = await deriveEncKey(env.JWT_SECRET, 'autodoc-db-v3');
  const user  = await getUser(email, dbKey);
  if (user) {
    const ar = rateLimit(`acct:${email}`, 8, 10 * 60 * 1000, 10 * 60 * 1000);
    if (ar.blocked) return jsonRes(res, { error: `Account locked. Retry in ${ar.retryAfter}s.` }, 429);
  }
  const dummy = 'a'.repeat(32) + ':' + 'b'.repeat(64);
  const valid = user ? await verifyPassword(password, user.hash) : await verifyPassword(password, dummy);
  if (!user || !valid) return jsonRes(res, { error: 'Invalid email or password.' }, 401);
  user.loginCount = (user.loginCount || 0) + 1;
  user.lastLogin  = new Date().toISOString();
  await putUser(email, user, dbKey);
  const token = await signJWT({ email: user.email, name: user.name, exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 }, env.JWT_SECRET);
  jsonRes(res, { token, user: { name: user.name, email: user.email } });
}

async function handleVerify(req, res) {
  const body = await readBody(req);
  if (!body.token) return jsonRes(res, { error: 'Token required.' }, 400);
  try {
    const p = await verifyJWT(body.token, env.JWT_SECRET);
    jsonRes(res, { user: { name: p.name, email: p.email } });
  } catch { jsonRes(res, { error: 'Invalid or expired token.' }, 401); }
}

async function handleSaveApiKeys(req, res) {
  const authUser    = await getAuthUser(req);
  const body        = await readBody(req);
  const plain       = JSON.stringify({ openai: sanitize(body.openai || '', 200), gemini: sanitize(body.gemini || '', 200), grok: sanitize(body.grok || '', 200), claude: sanitize(body.claude || '', 200) });
  const apiKeyEncKey = await deriveEncKey(env.JWT_SECRET, 'autodoc-apikeys-v3');
  const encrypted    = await aesEncrypt(plain, apiKeyEncKey);
  const dbKey        = await deriveEncKey(env.JWT_SECRET, 'autodoc-db-v3');
  const user         = await getUser(authUser.email, dbKey);
  if (!user) return jsonRes(res, { error: 'User not found.' }, 404);
  user.apiKeys = encrypted;
  await putUser(authUser.email, user, dbKey);
  jsonRes(res, { ok: true });
}

async function handleGetApiKeys(req, res) {
  const authUser     = await getAuthUser(req);
  const dbKey        = await deriveEncKey(env.JWT_SECRET, 'autodoc-db-v3');
  const user         = await getUser(authUser.email, dbKey);
  if (!user) return jsonRes(res, { error: 'User not found.' }, 404);
  if (!user.apiKeys) return jsonRes(res, { keys: { openai: '', gemini: '', grok: '', claude: '' } });
  const apiKeyEncKey = await deriveEncKey(env.JWT_SECRET, 'autodoc-apikeys-v3');
  const plain        = await aesDecrypt(user.apiKeys, apiKeyEncKey);
  jsonRes(res, { keys: JSON.parse(plain) });
}

const SYSTEM_PROMPTS = {
  en: 'You are AutoDoc — a highly knowledgeable, practical, and professional AI automotive diagnostics and troubleshooting assistant. Deep expertise in car mechanics, electronics, OBD-II fault codes, and repair procedures for all makes and models. Help users identify symptoms, diagnose problems, explain steps clearly, suggest causes by probability, recommend professional help when needed. SAFETY FIRST: Immediate safety risks warn to stop driving immediately. Cover all vehicle types: petrol, diesel, hybrid, electric. Keep responses structured, clear, and actionable.',
  es: 'Eres AutoDoc, asistente IA experto en diagnóstico automotriz. Expertise en mecánica, electrónica, OBD-II. SEGURIDAD PRIMERO: Riesgo inmediato avisa dejar de conducir.',
  fr: 'Vous êtes AutoDoc, expert IA en diagnostic automobile. SÉCURITÉ: Risque immédiat cessez de conduire.',
  si: 'ඔබ AutoDoc — AI වාහන රෝග විනිශ්චය සහාය. OBD-II, යාන්ත්‍රික, ඉලෙක්ට්‍රොනික විශේෂඥ. ක්ෂණික අවදානමේදී වාහනය වහාම නවත්වන්න.',
};

async function callGemini(msg, lang, hist, key) {
  const k = key || env.GEMINI_API_KEY;
  if (!k) throw new Error('Gemini key not configured');
  const fh     = hist.slice(-10).map(m => ({ parts: [{ text: m.content }], role: m.role === 'assistant' ? 'model' : 'user' }));
  const models = ['gemini-2.0-flash-exp', 'gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-1.5-flash-latest', 'gemini-1.5-flash'];
  let lastError = null;
  for (let i = 0; i < models.length; i++) {
    try {
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${models[i]}:generateContent?key=${k}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: SYSTEM_PROMPTS[lang] }], role: 'user' }, ...fh, { parts: [{ text: msg }], role: 'user' }], generationConfig: { temperature: 0.7, maxOutputTokens: 700 } }),
      });
      if (r.ok) return (await r.json()).candidates[0].content.parts[0].text;
      const e  = await r.json();
      const ec = e.error?.code, es = e.error?.status || '', em = e.error?.message || '';
      if (ec === 429 || es === 'RESOURCE_EXHAUSTED' || em.includes('quota')) { lastError = new Error(`${models[i]}: quota exceeded`); continue; }
      if (ec === 404 || es === 'NOT_FOUND' || em.includes('not found') || em.includes('not supported')) { lastError = new Error(`${models[i]}: not available`); continue; }
      throw new Error(em || 'Gemini error');
    } catch(fe) { lastError = fe; if (i < models.length - 1) continue; }
  }
  throw lastError || new Error('All Gemini models quota exceeded');
}

async function callChatGPT(msg, lang, hist, key) {
  const k = key || env.OPENAI_API_KEY;
  if (!k) throw new Error('OpenAI key not configured');
  const msgs   = [{ role: 'system', content: SYSTEM_PROMPTS[lang] }, ...hist.slice(-10), { role: 'user', content: msg }];
  const models = ['gpt-4o-mini', 'gpt-3.5-turbo'];
  for (let i = 0; i < models.length; i++) {
    const r = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${k}` }, body: JSON.stringify({ model: models[i], messages: msgs, temperature: 0.7, max_tokens: 700 }) });
    if (r.ok) return (await r.json()).choices[0].message.content;
    const e = await r.json();
    if (e.error?.type === 'insufficient_quota' || e.error?.code === 'rate_limit_exceeded') { if (i === models.length - 1) throw new Error('All ChatGPT quotas exceeded'); continue; }
    throw new Error(e.error?.message || 'ChatGPT error');
  }
}

async function callGrok(msg, lang, hist, key) {
  const k = key || env.GROK_API_KEY;
  if (!k) throw new Error('Grok key not configured');
  const msgs = [{ role: 'system', content: SYSTEM_PROMPTS[lang] }, ...hist.slice(-10), { role: 'user', content: msg }];
  const r    = await fetch('https://api.x.ai/v1/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${k}` }, body: JSON.stringify({ model: 'grok-3', messages: msgs, temperature: 0.7, max_tokens: 700 }) });
  if (!r.ok) { const e = await r.json(); throw new Error(e.error?.message || 'Grok error'); }
  return (await r.json()).choices[0].message.content;
}

async function callClaude(msg, lang, hist, key) {
  const k    = key || env.CLAUDE_API_KEY;
  if (!k) throw new Error('Claude key not configured');
  const msgs = [...hist.slice(-10).map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content })), { role: 'user', content: msg }];
  const r    = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': k, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 700, system: SYSTEM_PROMPTS[lang], messages: msgs }) });
  if (!r.ok) { const e = await r.json(); throw new Error(e.error?.message || 'Claude error'); }
  return (await r.json()).content[0].text;
}

async function handleChat(req, res) {
  const ip = req.socket?.remoteAddress || 'unknown';
  const rl = rateLimit(`chat:${ip}`, 40, 60 * 1000, 60 * 1000);
  if (rl.blocked) return jsonRes(res, { error: `Rate limit reached. Retry in ${rl.retryAfter}s.` }, 429);
  const { model, message, language = 'en', history = [], userOpenAiKey, userGeminiKey, userGrokKey, userClaudeKey } = await readBody(req);
  const cleanMsg = sanitize(message, 2000);
  if (!cleanMsg) return jsonRes(res, { error: 'Message is required.' }, 400);
  if (!SYSTEM_PROMPTS[language]) return jsonRes(res, { error: `Unsupported language: ${language}` }, 400);
  try {
    let response;
    if (model === 'chatgpt') response = await callChatGPT(cleanMsg, language, history, userOpenAiKey);
    else if (model === 'gemini') response = await callGemini(cleanMsg, language, history, userGeminiKey);
    else if (model === 'grok')   response = await callGrok(cleanMsg, language, history, userGrokKey);
    else if (model === 'claude') response = await callClaude(cleanMsg, language, history, userClaudeKey);
    else return jsonRes(res, { error: `Invalid model` }, 400);
    jsonRes(res, { response });
  } catch(e) {
    const msg = e.message || '';
    let userMsg = msg;
    if (msg.includes('not configured')) {
      const m = msg.includes('OpenAI') ? 'OpenAI' : msg.includes('Gemini') ? 'Gemini' : msg.includes('Grok') ? 'Grok' : 'Claude';
      userMsg = `No ${m} API key found. Go to Settings → API Keys and add your key, or switch to a different model.`;
    } else if (msg.includes('quota exceeded') || msg.includes('All Gemini')) {
      userMsg = 'Gemini free quota exceeded for today. Switch model in Settings, add your own Gemini key, or wait until tomorrow.';
    } else if (msg.includes('All ChatGPT')) {
      userMsg = 'ChatGPT quota exceeded. Switch model in Settings or add your own OpenAI key.';
    }
    jsonRes(res, { error: userMsg }, 500);
  }
}

function resolveFile(urlPath) {
  const clean = urlPath.split('?')[0].replace(/\.\./g, '');
  const full  = path.join(ROOT, clean);
  if (fs.existsSync(full)) {
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      const idx = path.join(full, 'index.html');
      if (fs.existsSync(idx)) return idx;
    } else return full;
  }
  return null;
}

const server = http.createServer(async (req, res) => {
  const url    = req.url || '/';
  const method = req.method || 'GET';

  if (method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type,Authorization', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' });
    res.end(); return;
  }

  try {
    if (url.startsWith('/api/')) {
      const p = url.split('?')[0];
      if (p === '/api/auth/signup'  && method === 'POST') return await handleSignup(req, res);
      if (p === '/api/auth/login'   && method === 'POST') return await handleLogin(req, res);
      if (p === '/api/auth/verify'  && method === 'POST') return await handleVerify(req, res);
      if (p === '/api/auth/apikeys' && method === 'POST') return await handleSaveApiKeys(req, res);
      if (p === '/api/auth/apikeys' && method === 'GET')  return await handleGetApiKeys(req, res);
      if (p === '/api/chat'         && method === 'POST') return await handleChat(req, res);
      if (p === '/api/health') return jsonRes(res, { status: 'ok', version: '3.0.0', runtime: 'Node.js' });
      return jsonRes(res, { error: 'Not found' }, 404);
    }

    const file = resolveFile(url);
    if (file) return serveFile(file, res);

    const withSlash = url.endsWith('/') ? url : url + '/';
    const idxFile   = resolveFile(withSlash);
    if (idxFile) return serveFile(idxFile, res);

    res.writeHead(404); res.end('Not found');
  } catch(e) {
    try { jsonRes(res, { error: e.message || 'Server error' }, 500); } catch {}
  }
});

function getLocalIP() {
  try {
    for (const ifaces of Object.values(os.networkInterfaces())) {
      for (const iface of ifaces) {
        if (iface.family === 'IPv4' && !iface.internal) return iface.address;
      }
    }
  } catch {}
  return null;
}

server.listen(PORT, '0.0.0.0', () => {
  const ip = getLocalIP();
  console.log('');
  console.log('  ┌─────────────────────────────────────────┐');
  console.log('  │      AutoDoc — Node.js Local Server     │');
  console.log('  ├─────────────────────────────────────────┤');
  console.log(`  │  Local:   http://127.0.0.1:${PORT}          │`);
  if (ip) console.log(`  │  Network: http://${ip.padEnd(15)}:${PORT}   │`);
  console.log('  │  Press Ctrl+C to stop                   │');
  console.log('  └─────────────────────────────────────────┘');
  console.log('');
});

server.on('error', e => {
  if (e.code === 'EADDRINUSE') {
    console.error(`  Port ${PORT} is already in use. Set PORT= to use a different port.`);
    process.exit(1);
  }
  throw e;
});
