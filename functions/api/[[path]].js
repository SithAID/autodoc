function getHeaders(request) {
  return {
    'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Type': 'application/json',
  };
}

async function deriveEncKey(secret, context) {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(context), info: new Uint8Array() },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function aesEncrypt(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  const buf = new Uint8Array(12 + enc.byteLength);
  buf.set(iv);
  buf.set(new Uint8Array(enc), 12);
  return btoa(String.fromCharCode(...buf));
}

async function aesDecrypt(b64, key) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
  return new TextDecoder().decode(dec);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMat, 256);
  const saltHex = [...salt].map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  try {
    const [saltHex, hashHex] = stored.split(':');
    const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
    const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMat, 256);
    const newHex = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
    return newHex === hashHex;
  } catch { return false; }
}

function b64url(str) {
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(str) {
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
}

async function signJWT(payload, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = b64url(JSON.stringify({ ...payload, iss: 'autodoc', iat: Math.floor(Date.now() / 1000) }));
  const data   = `${header}.${body}`;
  const key    = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${b64url(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const key   = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sig   = Uint8Array.from(b64urlDecode(parts[2]), c => c.charCodeAt(0));
  const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error('Invalid signature');
  const payload = JSON.parse(b64urlDecode(parts[1]));
  if (payload.exp && Date.now() / 1000 > payload.exp) throw new Error('Token expired');
  if (payload.iss !== 'autodoc') throw new Error('Invalid issuer');
  return payload;
}

async function rateLimit(kv, key, max, windowMs, lockMs) {
  const now = Date.now();
  let entry;
  try { entry = await kv.get(`rl:${key}`, 'json'); } catch { entry = null; }
  entry = entry || { count: 0, firstAt: now, lockedUntil: 0 };
  if (entry.lockedUntil && now < entry.lockedUntil) {
    return { blocked: true, retryAfter: Math.ceil((entry.lockedUntil - now) / 1000) };
  }
  if (now - entry.firstAt > windowMs) entry = { count: 0, firstAt: now, lockedUntil: 0 };
  entry.count++;
  if (entry.count > max) {
    entry.lockedUntil = now + lockMs;
    await kv.put(`rl:${key}`, JSON.stringify(entry), { expirationTtl: Math.ceil(lockMs / 1000) + 120 });
    return { blocked: true, retryAfter: Math.ceil(lockMs / 1000) };
  }
  await kv.put(`rl:${key}`, JSON.stringify(entry), { expirationTtl: Math.ceil(windowMs / 1000) + 120 });
  return { blocked: false };
}

function sanitize(str, maxLen = 200) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>"'`]/g, '');
}

async function getUser(kv, email, dbKey) {
  const enc = await kv.get(`user:${email}`);
  if (!enc) return null;
  const plain = await aesDecrypt(enc, dbKey);
  return JSON.parse(plain);
}

async function putUser(kv, email, user, dbKey) {
  const enc = await aesEncrypt(JSON.stringify(user), dbKey);
  await kv.put(`user:${email}`, enc);
}

async function getAuthUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) throw new Error('Authentication required.');
  return verifyJWT(auth.slice(7), env.JWT_SECRET);
}

async function handleSignup(request, env, headers) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rl = await rateLimit(env.USERS_KV, `signup:${ip}`, 5, 15 * 60 * 1000, 30 * 60 * 1000);
  if (rl.blocked) return Response.json({ error: `Too many attempts. Retry in ${rl.retryAfter}s.` }, { status: 429, headers });

  const body     = await request.json();
  const name     = sanitize(body.name || '', 80);
  const email    = sanitize(body.email || '', 120).toLowerCase();
  const password = body.password;

  if (!name) return Response.json({ error: 'Name is required.' }, { status: 400, headers });
  if (!email) return Response.json({ error: 'Email is required.' }, { status: 400, headers });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return Response.json({ error: 'Enter a valid email address.' }, { status: 400, headers });
  if (!password || typeof password !== 'string') return Response.json({ error: 'Password is required.' }, { status: 400, headers });
  if (password.length < 6) return Response.json({ error: 'Password must be at least 6 characters.' }, { status: 400, headers });
  if (password.length > 128) return Response.json({ error: 'Password too long.' }, { status: 400, headers });

  const dbKey   = await deriveEncKey(env.JWT_SECRET, 'autodoc-db-v3');
  const existing = await getUser(env.USERS_KV, email, dbKey);
  if (existing) return Response.json({ error: 'Email already registered.' }, { status: 409, headers });

  const hash = await hashPassword(password);
  await putUser(env.USERS_KV, email, { name, email, hash, createdAt: new Date().toISOString(), loginCount: 0, apiKeys: null }, dbKey);

  const token = await signJWT({ email, name, exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 }, env.JWT_SECRET);
  return Response.json({ token, user: { name, email } }, { headers });
}

async function handleLogin(request, env, headers) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rl = await rateLimit(env.USERS_KV, `login:${ip}`, 10, 15 * 60 * 1000, 15 * 60 * 1000);
  if (rl.blocked) return Response.json({ error: `Too many attempts. Retry in ${rl.retryAfter}s.` }, { status: 429, headers });

  const body     = await request.json();
  const email    = sanitize(body.email || '', 120).toLowerCase();
  const password = body.password;
  if (!email || !password) return Response.json({ error: 'Email and password are required.' }, { status: 400, headers });

  const dbKey = await deriveEncKey(env.JWT_SECRET, 'autodoc-db-v3');
  const user  = await getUser(env.USERS_KV, email, dbKey);

  if (user) {
    const acctRl = await rateLimit(env.USERS_KV, `acct:${email}`, 8, 10 * 60 * 1000, 10 * 60 * 1000);
    if (acctRl.blocked) return Response.json({ error: `Account locked. Retry in ${acctRl.retryAfter}s.` }, { status: 429, headers });
  }

  const dummyStored = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const valid = user ? await verifyPassword(password, user.hash) : await verifyPassword(password, dummyStored);
  if (!user || !valid) return Response.json({ error: 'Invalid email or password.' }, { status: 401, headers });

  user.loginCount = (user.loginCount || 0) + 1;
  user.lastLogin  = new Date().toISOString();
  await putUser(env.USERS_KV, email, user, dbKey);

  const token = await signJWT({ email: user.email, name: user.name, exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 }, env.JWT_SECRET);
  return Response.json({ token, user: { name: user.name, email: user.email } }, { headers });
}

async function handleVerify(request, env, headers) {
  const body = await request.json();
  if (!body.token || typeof body.token !== 'string') return Response.json({ error: 'Token required.' }, { status: 400, headers });
  try {
    const p = await verifyJWT(body.token, env.JWT_SECRET);
    return Response.json({ user: { name: p.name, email: p.email } }, { headers });
  } catch(e) {
    return Response.json({ error: 'Invalid or expired token.' }, { status: 401, headers });
  }
}

async function handleSaveApiKeys(request, env, headers) {
  const authUser = await getAuthUser(request, env);
  const body = await request.json();
  const plain = JSON.stringify({
    openai: sanitize(body.openai || '', 200),
    gemini: sanitize(body.gemini || '', 200),
    grok:   sanitize(body.grok   || '', 200),
    claude: sanitize(body.claude || '', 200),
  });
  const apiKeyEncKey = await deriveEncKey(env.JWT_SECRET, 'autodoc-apikeys-v3');
  const encrypted    = await aesEncrypt(plain, apiKeyEncKey);
  const dbKey        = await deriveEncKey(env.JWT_SECRET, 'autodoc-db-v3');
  const user         = await getUser(env.USERS_KV, authUser.email, dbKey);
  if (!user) return Response.json({ error: 'User not found.' }, { status: 404, headers });
  user.apiKeys = encrypted;
  await putUser(env.USERS_KV, authUser.email, user, dbKey);
  return Response.json({ ok: true }, { headers });
}

async function handleGetApiKeys(request, env, headers) {
  const authUser     = await getAuthUser(request, env);
  const dbKey        = await deriveEncKey(env.JWT_SECRET, 'autodoc-db-v3');
  const user         = await getUser(env.USERS_KV, authUser.email, dbKey);
  if (!user) return Response.json({ error: 'User not found.' }, { status: 404, headers });
  if (!user.apiKeys) return Response.json({ keys: { openai: '', gemini: '', grok: '', claude: '' } }, { headers });
  const apiKeyEncKey = await deriveEncKey(env.JWT_SECRET, 'autodoc-apikeys-v3');
  const plain        = await aesDecrypt(user.apiKeys, apiKeyEncKey);
  return Response.json({ keys: JSON.parse(plain) }, { headers });
}

const SYSTEM_PROMPTS = {
  en: `You are AutoDoc — a highly knowledgeable, practical, and professional AI automotive diagnostics and troubleshooting assistant. Deep expertise in car mechanics, electronics, OBD-II fault codes, and repair procedures for all makes and models. Help users identify symptoms, diagnose problems, explain steps clearly, suggest causes by probability, recommend professional help when needed. SAFETY FIRST: Immediate safety risks warn to stop driving immediately. Cover all vehicle types: petrol, diesel, hybrid, electric. Keep responses structured, clear, and actionable.`,
  es: `Eres AutoDoc, asistente IA experto en diagnóstico automotriz. Expertise en mecánica, electrónica, OBD-II. SEGURIDAD PRIMERO: Riesgo inmediato avisa dejar de conducir.`,
  fr: `Vous êtes AutoDoc, expert IA en diagnostic automobile. SÉCURITÉ: Risque immédiat cessez de conduire.`,
  si: `ඔබ AutoDoc — AI වාහන රෝග විනිශ්චය සහාය. OBD-II, යාන්ත්‍රික, ඉලෙක්ට්‍රොනික විශේෂඥ. ක්ෂණික අවදානමේදී වාහනය වහාම නවත්වන්න.`,
};

async function callChatGPT(msg, lang, hist, key, env) {
  const k = key || env.OPENAI_API_KEY;
  if (!k) throw new Error('OpenAI key not configured');
  const msgs   = [{ role: 'system', content: SYSTEM_PROMPTS[lang] }, ...hist.slice(-10), { role: 'user', content: msg }];
  const models = ['gpt-4o-mini', 'gpt-3.5-turbo'];
  for (let i = 0; i < models.length; i++) {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${k}` },
      body: JSON.stringify({ model: models[i], messages: msgs, temperature: 0.7, max_tokens: 700 }),
    });
    if (r.ok) return (await r.json()).choices[0].message.content;
    const e = await r.json();
    if (e.error?.type === 'insufficient_quota' || e.error?.code === 'rate_limit_exceeded') {
      if (i === models.length - 1) throw new Error('All ChatGPT quotas exceeded');
      continue;
    }
    throw new Error(e.error?.message || 'ChatGPT error');
  }
}

async function callGemini(msg, lang, hist, key, env) {
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
        body: JSON.stringify({
          contents: [{ parts: [{ text: SYSTEM_PROMPTS[lang] }], role: 'user' }, ...fh, { parts: [{ text: msg }], role: 'user' }],
          generationConfig: { temperature: 0.7, maxOutputTokens: 700 },
        }),
      });
      if (r.ok) return (await r.json()).candidates[0].content.parts[0].text;
      const e  = await r.json();
      const ec = e.error?.code;
      const es = e.error?.status || '';
      const em = e.error?.message || '';
      if (ec === 429 || es === 'RESOURCE_EXHAUSTED' || em.includes('quota')) { lastError = new Error(`${models[i]}: quota exceeded`); continue; }
      if (ec === 404 || es === 'NOT_FOUND' || em.includes('not found') || em.includes('not supported')) { lastError = new Error(`${models[i]}: not available`); continue; }
      throw new Error(em || 'Gemini error');
    } catch(fe) { lastError = fe; if (i < models.length - 1) continue; }
  }
  throw lastError || new Error('All Gemini models quota exceeded');
}

async function callGrok(msg, lang, hist, key, env) {
  const k = key || env.GROK_API_KEY;
  if (!k) throw new Error('Grok key not configured');
  const msgs = [{ role: 'system', content: SYSTEM_PROMPTS[lang] }, ...hist.slice(-10), { role: 'user', content: msg }];
  const r    = await fetch('https://api.x.ai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${k}` },
    body: JSON.stringify({ model: 'grok-3', messages: msgs, temperature: 0.7, max_tokens: 700 }),
  });
  if (!r.ok) { const e = await r.json(); throw new Error(e.error?.message || 'Grok error'); }
  return (await r.json()).choices[0].message.content;
}

async function callClaude(msg, lang, hist, key, env) {
  const k    = key || env.CLAUDE_API_KEY;
  if (!k) throw new Error('Claude key not configured');
  const msgs = [...hist.slice(-10).map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content })), { role: 'user', content: msg }];
  const r    = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': k, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 700, system: SYSTEM_PROMPTS[lang], messages: msgs }),
  });
  if (!r.ok) { const e = await r.json(); throw new Error(e.error?.message || 'Claude error'); }
  return (await r.json()).content[0].text;
}

async function handleChat(request, env, headers) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rl = await rateLimit(env.USERS_KV, `chat:${ip}`, 40, 60 * 1000, 60 * 1000);
  if (rl.blocked) return Response.json({ error: `Rate limit reached. Retry in ${rl.retryAfter}s.` }, { status: 429, headers });

  const { model, message, language = 'en', history = [], userOpenAiKey, userGeminiKey, userGrokKey, userClaudeKey } = await request.json();
  const cleanMsg = sanitize(message, 2000);
  if (!cleanMsg) return Response.json({ error: 'Message is required.' }, { status: 400, headers });
  if (!SYSTEM_PROMPTS[language]) return Response.json({ error: `Unsupported language: ${language}` }, { status: 400, headers });

  try {
    let response;
    if (model === 'chatgpt') response = await callChatGPT(cleanMsg, language, history, userOpenAiKey, env);
    else if (model === 'gemini') response = await callGemini(cleanMsg, language, history, userGeminiKey, env);
    else if (model === 'grok') response = await callGrok(cleanMsg, language, history, userGrokKey, env);
    else if (model === 'claude') response = await callClaude(cleanMsg, language, history, userClaudeKey, env);
    else return Response.json({ error: `Invalid model "${sanitize(model)}"` }, { status: 400, headers });
    return Response.json({ response }, { headers });
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
    return Response.json({ error: userMsg }, { status: 500, headers });
  }
}

export async function onRequest(context) {
  const { request, env } = context;
  const path   = new URL(request.url).pathname;
  const headers = getHeaders(request);

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });

  try {
    if (path === '/api/auth/signup'  && request.method === 'POST') return handleSignup(request, env, headers);
    if (path === '/api/auth/login'   && request.method === 'POST') return handleLogin(request, env, headers);
    if (path === '/api/auth/verify'  && request.method === 'POST') return handleVerify(request, env, headers);
    if (path === '/api/auth/apikeys' && request.method === 'POST') return handleSaveApiKeys(request, env, headers);
    if (path === '/api/auth/apikeys' && request.method === 'GET')  return handleGetApiKeys(request, env, headers);
    if (path === '/api/chat'         && request.method === 'POST') return handleChat(request, env, headers);
    if (path === '/api/health')  return Response.json({ status: 'ok', version: '3.0.0', runtime: 'Cloudflare Workers' }, { headers });
    return Response.json({ error: 'Not found' }, { status: 404, headers });
  } catch(e) {
    return Response.json({ error: e.message || 'Server error' }, { status: 500, headers });
  }
}
