'use strict';
/* TechPulse Innovations: complete backend. No dependencies, no install: run `node server.js`.
   One link serves everything:  /  = website (login, signup, dashboard)   /admin = admin dashboard (admins only).
   Data is stored in ./data (set DATA_DIR to move it onto a persistent disk). */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS = path.join(DATA_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@techpulse.dev').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@123';
const MAX_UPLOAD = 15 * 1024 * 1024;
const SESSION_MS = 14 * 24 * 3600 * 1000;
const STATUSES = ['Request sent', 'Planning', 'In design', 'In development', 'Testing', 'Completed'];

fs.mkdirSync(UPLOADS, { recursive: true });

/* ---------- tiny JSON database ---------- */
let db = { users: [], sessions: {}, messages: [], projects: [], files: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch (e) { /* first run */ }
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
const uid = () => crypto.randomBytes(8).toString('hex');

/* ---------- passwords + sessions ---------- */
const hashPw = (pw, salt) => new Promise((res, rej) => {
  salt = salt || crypto.randomBytes(16).toString('hex');
  crypto.scrypt(pw, salt, 64, (e, k) => e ? rej(e) : res({ salt, hash: k.toString('hex') }));
});
async function checkPw(pw, u) {
  const { hash } = await hashPw(pw, u.salt);
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(u.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
function newSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(token)] = { uid: userId, exp: Date.now() + SESSION_MS };
  return token;
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
function currentUser(req) {
  const t = cookies(req).tp_sid; if (!t) return null;
  const s = db.sessions[sha(t)]; if (!s) return null;
  if (s.exp < Date.now()) { delete db.sessions[sha(t)]; return null; }
  const u = db.users.find(x => x.id === s.uid);
  return u && u.status !== 'suspended' ? u : null;
}
const pub = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, status: u.status, createdAt: u.createdAt, lastLogin: u.lastLogin });

/* ---------- seed the admin account ---------- */
async function initAdmin() {
  let a = db.users.find(u => u.role === 'admin');
  const h = await hashPw(ADMIN_PASSWORD);
  if (!a) {
    db.users.push({
      id: uid(),
      name: 'TechPulse Admin',
      email: ADMIN_EMAIL,
      salt: h.salt,
      hash: h.hash,
      role: 'admin',
      status: 'active',
      createdAt: Date.now(),
      lastLogin: null
    });
    save();
  } else if (process.env.ADMIN_PASSWORD) {
    /* Setting ADMIN_PASSWORD is an explicit recovery/reset mechanism. */
    a.salt = h.salt;
    a.hash = h.hash;
    a.email = ADMIN_EMAIL;
    a.status = 'active';
    save();
  }
}

/* ---------- helpers ---------- */
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(), r = hits.get(key);
  if (!r || now - r.t > windowMs) { hits.set(key, { n: 1, t: now }); return false; }
  r.n++; return r.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (now - v.t > 3600e3) hits.delete(k); for (const k in db.sessions) if (db.sessions[k].exp < now) delete db.sessions[k]; }, 600e3).unref();
const emailOk = v => typeof v === 'string' && v.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const clean = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, max);
function send(res, code, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {}));
  res.end(body);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0, over = false;
    req.on('data', c => {
      n += c.length;
      if (n > limit) { over = true; chunks.length = 0; if (n > limit * 2) req.destroy(); } // keep draining so the client can read our error reply
      else if (!over) chunks.push(c);
    });
    req.on('end', () => over ? reject(Object.assign(new Error('too big'), { code: 413 })) : resolve(Buffer.concat(chunks)));
    req.on('error', reject);
    req.on('close', () => { if (!req.complete) reject(Object.assign(new Error('Upload interrupted.'), { code: 400 })); });
  });
}
async function readJson(req) {
  const b = await readBody(req, 100 * 1024);
  if (!b.length) return {};
  try { const j = JSON.parse(b.toString('utf8')); return j && typeof j === 'object' ? j : {}; } catch (e) { throw Object.assign(new Error('Invalid request.'), { code: 400 }); }
}
const fail = (code, msg) => Object.assign(new Error(msg), { code });
const ip = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
function setCookie(req, token, maxAge) {
  const secure = (req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted) ? '; Secure' : '';
  return 'tp_sid=' + token + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + maxAge + secure;
}
const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN', 'Referrer-Policy': 'strict-origin-when-cross-origin' };

/* ---------- API ---------- */
async function api(req, res, pathname, query) {
  const m = req.method, parts = pathname.split('/').filter(Boolean).slice(1); // after "api"
  const me = currentUser(req);

  if (m !== 'GET' && m !== 'HEAD') { // CSRF guard: custom header + same-origin
    if (req.headers['x-requested-with'] !== 'tp') throw fail(403, 'Blocked request.');
    const o = req.headers.origin;
    if (o) { let h = ''; try { h = new URL(o).host; } catch (e) {} if (h !== req.headers.host) throw fail(403, 'Blocked request.'); }
  }
  const needUser = () => { if (!me) throw fail(401, 'Please log in.'); return me; };
  const needAdmin = () => { if (!me) throw fail(401, 'Please log in.'); if (me.role !== 'admin') throw fail(403, 'Admins only.'); return me; };
  const route = parts.join('/');

  /* ----- auth ----- */
  if (m === 'POST' && route === 'signup') {
    if (limited('su|' + ip(req), 20, 3600e3)) throw fail(429, 'Too many sign-ups. Try again later.');
    const b = await readJson(req), email = clean(b.email, 120).toLowerCase(), name = clean(b.name, 40), pw = String(b.password || '');
    if (!emailOk(email)) throw fail(400, 'Enter a valid email address.');
    if (name.length < 2) throw fail(400, 'Name must be at least 2 characters.');
    if (pw.length < 8 || pw.length > 200) throw fail(400, 'Use at least 8 characters for the password.');
    if (db.users.some(u => u.email === email)) throw fail(409, 'An account with this email already exists. Try logging in.');
    const h = await hashPw(pw);
    const u = { id: uid(), name, email, salt: h.salt, hash: h.hash, role: 'client', status: 'active', createdAt: Date.now(), lastLogin: Date.now() };
    db.users.push(u);
    const token = newSession(u.id); save();
    return send(res, 200, { user: pub(u) }, { 'Set-Cookie': setCookie(req, token, SESSION_MS / 1000) });
  }
  if (m === 'POST' && route === 'login') {
    const b = await readJson(req), email = clean(b.email, 120).toLowerCase(), pw = String(b.password || '');
    const key = 'li|' + ip(req) + '|' + email;
    if ((hits.get(key) || { n: 0 }).n >= 8 && Date.now() - hits.get(key).t < 15 * 60e3) throw fail(429, 'Too many attempts. Please wait 15 minutes and try again.');
    const u = db.users.find(x => x.email === email);
    const ok = u && pw.length <= 200 && await checkPw(pw, u);
    if (!ok) { const r = hits.get(key); hits.set(key, { n: r && Date.now() - r.t < 15 * 60e3 ? r.n + 1 : 1, t: r && Date.now() - r.t < 15 * 60e3 ? r.t : Date.now() }); throw fail(401, 'Email or password is incorrect.'); }
    if (u.status === 'suspended') throw fail(403, 'This account is suspended. Contact an administrator.');
    hits.delete(key);
    u.lastLogin = Date.now();
    const token = newSession(u.id); save();
    return send(res, 200, { user: pub(u) }, { 'Set-Cookie': setCookie(req, token, SESSION_MS / 1000) });
  }
  if (m === 'POST' && route === 'logout') {
    const t = cookies(req).tp_sid; if (t) { delete db.sessions[sha(t)]; save(); }
    return send(res, 200, { ok: true }, { 'Set-Cookie': setCookie(req, '', 0) });
  }
  if (m === 'POST' && route === 'forgot') { // no email service: the admin is notified and sets a new password
    if (limited('fg|' + ip(req), 10, 3600e3)) throw fail(429, 'Too many requests. Try again later.');
    const b = await readJson(req), email = clean(b.email, 120).toLowerCase();
    if (!emailOk(email)) throw fail(400, 'Enter a valid email address.');
    const u = db.users.find(x => x.email === email && x.role !== 'admin');
    if (u && !db.messages.some(x => x.topic === 'Password reset request' && x.email === email && !x.read)) {
      db.messages.push({ id: uid(), name: u.name, email, topic: 'Password reset request', text: u.name + ' asked for a password reset. Open Users and press Reset next to their name to set a new password, then send it to them privately.', t: Date.now(), read: false, userId: u.id });
      save();
    }
    return send(res, 200, { ok: true });
  }

  /* ----- me ----- */
  if (m === 'GET' && route === 'me') { needUser(); return send(res, 200, { user: pub(me) }); }
  if (m === 'PATCH' && route === 'me') {
    needUser(); const b = await readJson(req), name = clean(b.name, 40);
    if (name.length < 2) throw fail(400, 'Name must be at least 2 characters.');
    me.name = name; save(); return send(res, 200, { user: pub(me) });
  }
  if (m === 'POST' && route === 'me/password') {
    needUser(); const b = await readJson(req), next = String(b.next || '');
    if (!(await checkPw(String(b.current || ''), me))) throw fail(400, 'Current password is incorrect.');
    if (next.length < 8 || next.length > 200) throw fail(400, 'Use at least 8 characters for the new password.');
    const h = await hashPw(next); me.salt = h.salt; me.hash = h.hash;
    const keep = sha(cookies(req).tp_sid || ''); for (const k in db.sessions) if (db.sessions[k].uid === me.id && k !== keep) delete db.sessions[k];
    save(); return send(res, 200, { ok: true });
  }

  /* ----- contact + projects + files (signed-in user) ----- */
  if (m === 'POST' && route === 'contact') {
    if (limited('ct|' + ip(req), 20, 3600e3)) throw fail(429, 'Too many messages. Try again later.');
    const b = await readJson(req), name = clean(b.name, 80), email = clean(b.email, 120), topic = clean(b.topic, 100) || 'General question', text = clean(b.message, 3000);
    if (name.length < 2) throw fail(400, 'Enter your name.');
    if (!emailOk(email)) throw fail(400, 'Enter a valid email address.');
    if (text.length < 10) throw fail(400, 'Message must be at least 10 characters.');
    db.messages.push({ id: uid(), name, email, topic, text, t: Date.now(), read: false, userId: me ? me.id : null });
    let project = false;
    if (me && b.request === true) { db.projects.push({ id: uid(), userId: me.id, name: topic, status: 'Request sent', pct: 0, createdAt: Date.now() }); project = true; }
    save(); return send(res, 200, { ok: true, project });
  }
  if (m === 'GET' && route === 'projects') { needUser(); return send(res, 200, { projects: db.projects.filter(p => p.userId === me.id).map(p => ({ id: p.id, name: p.name, status: p.status, pct: p.pct })) }); }
  if (m === 'GET' && route === 'files') { needUser(); return send(res, 200, { files: db.files.filter(f => f.userId === me.id).map(f => ({ id: f.id, name: f.name, size: f.size, t: f.t })) }); }
  if (m === 'POST' && route === 'files') {
    needUser(); if (limited('up|' + me.id, 60, 3600e3)) throw fail(429, 'Too many uploads. Try again later.');
    if (db.files.filter(f => f.userId === me.id).length >= 100) throw fail(400, 'File limit reached (100 files).');
    const name = path.basename(clean(query.get('name'), 120)).replace(/[\\/:*?"<>|]/g, '_') || 'file';
    const body = await readBody(req, MAX_UPLOAD).catch(e => { throw e.code === 413 ? fail(413, 'File is too large (15 MB maximum).') : e; });
    if (!body.length) throw fail(400, 'That file is empty.');
    const f = { id: uid(), userId: me.id, name, size: body.length, t: Date.now() };
    fs.writeFileSync(path.join(UPLOADS, f.id), body); db.files.push(f); save();
    return send(res, 200, { file: { id: f.id, name: f.name, size: f.size, t: f.t } });
  }
  if (parts[0] === 'files' && parts[1]) {
    needUser(); const f = db.files.find(x => x.id === parts[1]);
    if (!f || (f.userId !== me.id && me.role !== 'admin')) throw fail(404, 'File not found.');
    if (m === 'GET') {
      let data; try { data = fs.readFileSync(path.join(UPLOADS, f.id)); } catch (e) { throw fail(404, 'File not found.'); }
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': data.length, 'Content-Disposition': 'attachment; filename*=UTF-8\'\'' + encodeURIComponent(f.name), 'Cache-Control': 'no-store' });
      return res.end(data);
    }
    if (m === 'DELETE' && f.userId === me.id) { try { fs.unlinkSync(path.join(UPLOADS, f.id)); } catch (e) {} db.files = db.files.filter(x => x !== f); save(); return send(res, 200, { ok: true }); }
  }

  /* ----- admin ----- */
  if (parts[0] === 'admin') {
    needAdmin(); const id = parts[2];
    if (m === 'GET' && route === 'admin/users') {
      return send(res, 200, { users: db.users.filter(u => u.role !== 'admin').map(u => Object.assign(pub(u), { files: db.files.filter(f => f.userId === u.id).length })) });
    }
    if (parts[1] === 'users' && id) {
      const u = db.users.find(x => x.id === id && x.role !== 'admin'); if (!u) throw fail(404, 'User not found.');
      if (m === 'PATCH') {
        const b = await readJson(req);
        if (b.status === 'active' || b.status === 'suspended') { u.status = b.status; if (u.status === 'suspended') for (const k in db.sessions) if (db.sessions[k].uid === u.id) delete db.sessions[k]; }
        save(); return send(res, 200, { user: pub(u) });
      }
      if (m === 'POST' && parts[3] === 'password') {
        const b = await readJson(req), pw = String(b.password || '');
        if (pw.length < 8 || pw.length > 200) throw fail(400, 'Use at least 8 characters.');
        const h = await hashPw(pw); u.salt = h.salt; u.hash = h.hash;
        for (const k in db.sessions) if (db.sessions[k].uid === u.id) delete db.sessions[k];
        save(); return send(res, 200, { ok: true });
      }
      if (m === 'GET' && parts[3] === 'files') return send(res, 200, { files: db.files.filter(f => f.userId === u.id).map(f => ({ id: f.id, name: f.name, size: f.size, t: f.t })) });
      if (m === 'DELETE' && !parts[3]) {
        db.files.filter(f => f.userId === u.id).forEach(f => { try { fs.unlinkSync(path.join(UPLOADS, f.id)); } catch (e) {} });
        db.files = db.files.filter(f => f.userId !== u.id); db.projects = db.projects.filter(p => p.userId !== u.id);
        for (const k in db.sessions) if (db.sessions[k].uid === u.id) delete db.sessions[k];
        db.users = db.users.filter(x => x !== u); save(); return send(res, 200, { ok: true });
      }
    }
    if (m === 'GET' && route === 'admin/messages') return send(res, 200, { messages: db.messages.slice().sort((a, b) => b.t - a.t) });
    if (parts[1] === 'messages' && id) {
      const x = db.messages.find(q => q.id === id); if (!x) throw fail(404, 'Message not found.');
      if (m === 'PATCH') { const b = await readJson(req); if (typeof b.read === 'boolean') x.read = b.read; save(); return send(res, 200, { ok: true }); }
      if (m === 'DELETE') { db.messages = db.messages.filter(q => q !== x); save(); return send(res, 200, { ok: true }); }
    }
    if (m === 'GET' && route === 'admin/projects') {
      return send(res, 200, { statuses: STATUSES, projects: db.projects.slice().sort((a, b) => b.createdAt - a.createdAt).map(p => { const u = db.users.find(x => x.id === p.userId) || {}; return { id: p.id, name: p.name, status: p.status, pct: p.pct, userName: u.name || 'Deleted user', userEmail: u.email || '' }; }) });
    }
    if (parts[1] === 'projects' && id) {
      const p = db.projects.find(q => q.id === id); if (!p) throw fail(404, 'Project not found.');
      if (m === 'PATCH') {
        const b = await readJson(req);
        if (STATUSES.includes(b.status)) p.status = b.status;
        const n = Math.round(Number(b.pct)); if (Number.isFinite(n)) p.pct = Math.min(100, Math.max(0, n));
        if (p.status === 'Completed') p.pct = 100;
        save(); return send(res, 200, { ok: true });
      }
      if (m === 'DELETE') { db.projects = db.projects.filter(q => q !== p); save(); return send(res, 200, { ok: true }); }
    }
  }
  throw fail(404, 'Not found.');
}

/* ---------- server ---------- */
const page = f => fs.readFileSync(path.join(__dirname, f));
const server = http.createServer(async (req, res) => {
  Object.keys(SEC).forEach(k => res.setHeader(k, SEC[k]));
  let u; try { u = new URL(req.url, 'http://x'); } catch (e) { res.writeHead(400); return res.end(); }
  const p = u.pathname.replace(/\/+$/, '') || '/';
  try {
    if (p === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify({ ok: true, service: 'techpulse', uptime: Math.round(process.uptime()) }));
    }
    if (p.startsWith('/api/') || p === '/api') return await api(req, res, p, u.searchParams);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    if (p === '/' || p === '/index.html') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' }); return res.end(page('index.html')); }
    if (p === '/admin' || p === '/admin.html') {
      const me = currentUser(req);
      if (!me || me.role !== 'admin') { res.writeHead(302, { Location: '/#/login', 'Cache-Control': 'no-store' }); return res.end(); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(page('admin.html'));
    }
    res.writeHead(302, { Location: '/' }); res.end();
  } catch (e) {
    const code = e.code && Number.isInteger(e.code) ? e.code : 500;
    if (code === 500) console.error(e);
    if (!res.headersSent) send(res, code, { error: code === 500 ? 'Something went wrong on the server.' : e.message });
  }
});
async function start() {
  await initAdmin();
  server.listen(PORT, () => {
    console.log('\nTechPulse is running on port ' + PORT + '  ->  http://localhost:' + PORT);
    console.log('Health check: http://localhost:' + PORT + '/health');
    console.log('Admin login: ' + ADMIN_EMAIL + (process.env.ADMIN_PASSWORD
      ? '  (password from ADMIN_PASSWORD)'
      : '  /  Admin@123   (change it after logging in)') + '\n');
  });
}
function shutdown() {
  try { save(); } catch (e) { console.error('Could not save data during shutdown:', e); }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
start().catch(e => { console.error(e); process.exit(1); });
