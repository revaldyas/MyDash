require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// ── DATABASE ──────────────────────────────────────────────────────────────────
const db = new Database(path.join(DATA_DIR, 'dashboard.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS categories (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    color      TEXT NOT NULL DEFAULT 'blue',
    sort_order INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS bookmarks (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    url        TEXT NOT NULL,
    cat        TEXT NOT NULL,
    emoji      TEXT DEFAULT '🌐',
    color      TEXT DEFAULT 'blue',
    sort_order INTEGER DEFAULT 0
  );
`);

// Persist session secret across restarts
let sessionSecret = db.prepare("SELECT value FROM config WHERE key='session_secret'").get()?.value;
if (!sessionSecret) {
  sessionSecret = crypto.randomBytes(32).toString('hex');
  db.prepare("INSERT INTO config (key, value) VALUES ('session_secret', ?)").run(sessionSecret);
}

// ── APP ───────────────────────────────────────────────────────────────────────
const app = express();

app.use(express.json());
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ── SETUP ─────────────────────────────────────────────────────────────────────
app.get('/api/setup/status', (_req, res) => {
  const row = db.prepare("SELECT value FROM config WHERE key='pin_hash'").get();
  res.json({ configured: !!row });
});

app.post('/api/setup', async (req, res) => {
  const existing = db.prepare("SELECT value FROM config WHERE key='pin_hash'").get();
  if (existing) return res.status(400).json({ error: 'Already configured' });

  const { pin } = req.body;
  if (!pin || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'Invalid PIN' });

  const hash = await bcrypt.hash(pin, 10);
  db.prepare("INSERT INTO config (key, value) VALUES ('pin_hash', ?)").run(hash);

  // Seed default data
  const insertCat = db.prepare('INSERT OR IGNORE INTO categories (id, name, color) VALUES (?, ?, ?)');
  [
    ['dev',    'Development',          'blue'],
    ['client', 'Client Projects',      'purple'],
    ['tools',  'Tools & Productivity', 'green'],
    ['infra',  'Infrastructure',       'orange'],
  ].forEach(([id, name, color]) => insertCat.run(id, name, color));

  const insertBm = db.prepare('INSERT OR IGNORE INTO bookmarks (id, name, url, cat, emoji, color) VALUES (?, ?, ?, ?, ?, ?)');
  [
    ['b1',  'GitHub',          'https://github.com',       'dev',    '🐙', 'blue'],
    ['b2',  'Claude',          'https://claude.ai',        'tools',  '🤖', 'purple'],
    ['b3',  'Notion',          'https://notion.so',        'tools',  '📝', 'indigo'],
    ['b4',  'Linear',          'https://linear.app',       'tools',  '🎯', 'green'],
    ['b5',  'Figma',           'https://figma.com',        'tools',  '🎨', 'pink'],
    ['b6',  'Supabase',        'https://supabase.com',     'infra',  '⚡', 'green'],
    ['b7',  'Netlify',         'https://app.netlify.com',  'infra',  '☁️', 'teal'],
    ['b8',  'Gmail',           'https://mail.google.com',  'tools',  '📧', 'red'],
    ['b9',  'Accurate Online', 'https://accurate.id',      'client', '💰', 'orange'],
    ['b10', 'Bale Software',   'https://balesoftware.id',  'client', '🏠', 'blue'],
  ].forEach(([id, name, url, cat, emoji, color]) => insertBm.run(id, name, url, cat, emoji, color));

  req.session.authenticated = true;
  res.json({ ok: true });
});

app.post('/api/setup/reset', async (req, res) => {
  const row = db.prepare("SELECT value FROM config WHERE key='pin_hash'").get();
  if (row) {
    const ok = await bcrypt.compare(req.body.pin || '', row.value);
    if (!ok) return res.status(401).json({ error: 'Wrong PIN' });
  }
  db.exec("DELETE FROM bookmarks; DELETE FROM categories; DELETE FROM config WHERE key='pin_hash';");
  req.session.destroy(() => res.json({ ok: true }));
});

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.get('/api/auth/status', (req, res) => {
  res.json({ authenticated: !!req.session.authenticated });
});

app.post('/api/auth/login', async (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ error: 'PIN required' });

  const row = db.prepare("SELECT value FROM config WHERE key='pin_hash'").get();
  if (!row) return res.status(400).json({ error: 'Not configured' });

  const ok = await bcrypt.compare(pin, row.value);
  if (!ok) return res.status(401).json({ error: 'Wrong PIN' });

  req.session.authenticated = true;
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.put('/api/auth/pin', requireAuth, async (req, res) => {
  const { newPin } = req.body;
  if (!newPin || !/^\d{4}$/.test(newPin)) return res.status(400).json({ error: 'Invalid PIN' });
  const hash = await bcrypt.hash(newPin, 10);
  db.prepare("UPDATE config SET value=? WHERE key='pin_hash'").run(hash);
  res.json({ ok: true });
});

// ── DATA ──────────────────────────────────────────────────────────────────────
app.get('/api/data', requireAuth, (_req, res) => {
  const categories = db.prepare('SELECT * FROM categories ORDER BY sort_order, rowid').all();
  const bookmarks  = db.prepare('SELECT * FROM bookmarks  ORDER BY sort_order, rowid').all();
  res.json({ categories, bookmarks });
});

// Bookmarks
app.post('/api/bookmarks', requireAuth, (req, res) => {
  const { id, name, url, cat, emoji, color } = req.body;
  db.prepare('INSERT INTO bookmarks (id, name, url, cat, emoji, color) VALUES (?, ?, ?, ?, ?, ?)').run(id, name, url, cat, emoji, color);
  res.json({ ok: true });
});

app.put('/api/bookmarks/:id', requireAuth, (req, res) => {
  const { name, url, cat, emoji, color } = req.body;
  db.prepare('UPDATE bookmarks SET name=?, url=?, cat=?, emoji=?, color=? WHERE id=?').run(name, url, cat, emoji, color, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/bookmarks/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM bookmarks WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// Categories
app.post('/api/categories', requireAuth, (req, res) => {
  const { id, name, color } = req.body;
  db.prepare('INSERT INTO categories (id, name, color) VALUES (?, ?, ?)').run(id, name, color);
  res.json({ ok: true });
});

app.delete('/api/categories/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM bookmarks WHERE cat=?').run(req.params.id);
  db.prepare('DELETE FROM categories WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── AI ────────────────────────────────────────────────────────────────────────
app.post('/api/ai/categorize', requireAuth, async (req, res) => {
  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(503).json({ error: 'AI not configured — set DEEPSEEK_API_KEY' });
  }

  const { name, url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });

  const categories = db.prepare('SELECT id, name FROM categories ORDER BY rowid').all();

  const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`,
    },
    body: JSON.stringify({
      model: 'deepseek-chat',
      max_tokens: 150,
      messages: [{
        role: 'user',
        content: `Categorize this bookmark for a personal developer dashboard.

Bookmark: "${name || ''}" — ${url}

Available categories:
${categories.map(c => `• ${c.id}: ${c.name}`).join('\n')}

Pick the best fit. If none match well, suggest a new one.
Reply with JSON only (no markdown):
Existing → {"action":"use","id":"<id>"}
New      → {"action":"create","name":"<name>","color":"blue|green|purple|orange|teal|red|pink|yellow|indigo|cyan"}`,
      }],
    }),
  });

  const json = await response.json();
  const text = json.choices?.[0]?.message?.content?.trim();

  try {
    const result = JSON.parse(text.replace(/^```json\s*|\s*```$/g, ''));

    if (result.action === 'create') {
      const id = 'cat_' + Date.now();
      const color = result.color || 'blue';
      db.prepare('INSERT INTO categories (id, name, color) VALUES (?, ?, ?)').run(id, result.name, color);
      return res.json({ action: 'create', category: { id, name: result.name, color } });
    }

    const valid = categories.find(c => c.id === result.id);
    res.json({ action: 'use', id: valid ? result.id : categories[0]?.id });
  } catch {
    res.status(500).json({ error: 'AI response parse error' });
  }
});

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Bale Dashboard running on http://localhost:${PORT}`));
