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
    pinned     INTEGER DEFAULT 0,
    sort_order INTEGER DEFAULT 0
  );
`);
// migrate existing DB
try { db.exec('ALTER TABLE bookmarks ADD COLUMN pinned INTEGER DEFAULT 0'); } catch {}

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

app.patch('/api/bookmarks/:id/pin', requireAuth, (req, res) => {
  const row = db.prepare('SELECT pinned FROM bookmarks WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  const pinned = row.pinned ? 0 : 1;
  db.prepare('UPDATE bookmarks SET pinned=? WHERE id=?').run(pinned, req.params.id);
  res.json({ pinned: !!pinned });
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

// ── AI CHAT ──────────────────────────────────────────────────────────────────
const AI_TOOLS = [
  {
    type: 'function',
    function: {
      name: 'add_bookmark',
      description: 'Add a new bookmark to the dashboard',
      parameters: {
        type: 'object',
        properties: {
          name:        { type: 'string', description: 'Display name' },
          url:         { type: 'string', description: 'Full URL including https://' },
          category_id: { type: 'string', description: 'Existing category id' },
          emoji:       { type: 'string', description: 'Single emoji icon' },
          color:       { type: 'string', enum: ['blue','green','red','purple','pink','orange','teal','yellow','indigo','cyan'] },
        },
        required: ['name', 'url', 'category_id'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'create_category',
      description: 'Create a new bookmark category',
      parameters: {
        type: 'object',
        properties: {
          name:  { type: 'string' },
          color: { type: 'string', enum: ['blue','green','red','purple','pink','orange','teal','yellow','indigo','cyan'] },
        },
        required: ['name', 'color'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'move_bookmark',
      description: 'Move a bookmark to a different category',
      parameters: {
        type: 'object',
        properties: {
          bookmark_id:  { type: 'string' },
          category_id:  { type: 'string' },
        },
        required: ['bookmark_id', 'category_id'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'pin_bookmark',
      description: 'Pin or unpin a bookmark',
      parameters: {
        type: 'object',
        properties: {
          bookmark_id: { type: 'string' },
          pinned:      { type: 'boolean' },
        },
        required: ['bookmark_id', 'pinned'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'delete_bookmark',
      description: 'Permanently delete a bookmark',
      parameters: {
        type: 'object',
        properties: {
          bookmark_id: { type: 'string' },
        },
        required: ['bookmark_id'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'update_bookmark',
      description: 'Update name, URL, emoji, or color of an existing bookmark',
      parameters: {
        type: 'object',
        properties: {
          bookmark_id: { type: 'string' },
          name:        { type: 'string' },
          url:         { type: 'string' },
          emoji:       { type: 'string' },
          color:       { type: 'string', enum: ['blue','green','red','purple','pink','orange','teal','yellow','indigo','cyan'] },
        },
        required: ['bookmark_id'],
      },
    },
  },
];

app.post('/api/ai/chat', requireAuth, async (req, res) => {
  if (!process.env.DEEPSEEK_API_KEY) {
    return res.status(503).json({ error: 'AI not configured — set DEEPSEEK_API_KEY' });
  }

  const { messages } = req.body;
  const categories = db.prepare('SELECT * FROM categories ORDER BY rowid').all();
  const bookmarks  = db.prepare('SELECT * FROM bookmarks  ORDER BY rowid').all();

  const system = `You are an AI assistant for Bale Dashboard — a personal bookmark manager for a developer named Reva.

Current categories (${categories.length}):
${categories.map(c => `  [${c.id}] "${c.name}" color:${c.color}`).join('\n')}

Current bookmarks (${bookmarks.length}):
${bookmarks.map(b => `  [${b.id}] "${b.name}" → ${b.url} | cat:${b.cat}${b.pinned ? ' | pinned' : ''}`).join('\n')}

Rules:
- Respond in the same language the user writes in.
- Be concise and friendly.
- Use tools to perform actions immediately when asked — don't just describe what you would do.
- When recommending sites, suggest specific real URLs then offer to add them.
- For bulk operations, use multiple tool calls in one response.`;

  const msgs = [{ role: 'system', content: system }, ...messages.slice(-20)];
  const actions = [];

  for (let round = 0; round < 8; round++) {
    const resp = await fetch('https://api.deepseek.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`,
      },
      body: JSON.stringify({
        model: 'deepseek-chat',
        messages: msgs,
        tools: AI_TOOLS,
        tool_choice: 'auto',
        max_tokens: 1000,
      }),
    });

    const json = await resp.json();
    const choice = json.choices?.[0];
    if (!choice) break;

    msgs.push(choice.message);
    if (choice.finish_reason !== 'tool_calls') break;

    for (const call of (choice.message.tool_calls || [])) {
      const fn   = call.function.name;
      const args = JSON.parse(call.function.arguments);
      let result = {};

      if (fn === 'add_bookmark') {
        const id = 'b' + Date.now() + Math.floor(Math.random() * 999);
        db.prepare('INSERT INTO bookmarks (id, name, url, cat, emoji, color) VALUES (?,?,?,?,?,?)')
          .run(id, args.name, args.url, args.category_id, args.emoji || '🌐', args.color || 'blue');
        result = { success: true, id };
        actions.push({ type: 'add_bookmark', name: args.name });

      } else if (fn === 'create_category') {
        const id = 'cat_' + Date.now();
        db.prepare('INSERT INTO categories (id, name, color) VALUES (?,?,?)').run(id, args.name, args.color);
        result = { success: true, id };
        actions.push({ type: 'create_category', name: args.name });

      } else if (fn === 'move_bookmark') {
        db.prepare('UPDATE bookmarks SET cat=? WHERE id=?').run(args.category_id, args.bookmark_id);
        const bm = db.prepare('SELECT name FROM bookmarks WHERE id=?').get(args.bookmark_id);
        result = { success: true };
        actions.push({ type: 'move_bookmark', name: bm?.name || args.bookmark_id });

      } else if (fn === 'pin_bookmark') {
        db.prepare('UPDATE bookmarks SET pinned=? WHERE id=?').run(args.pinned ? 1 : 0, args.bookmark_id);
        const bm = db.prepare('SELECT name FROM bookmarks WHERE id=?').get(args.bookmark_id);
        result = { success: true };
        actions.push({ type: 'pin_bookmark', name: bm?.name || args.bookmark_id, pinned: args.pinned });

      } else if (fn === 'delete_bookmark') {
        const bm = db.prepare('SELECT name FROM bookmarks WHERE id=?').get(args.bookmark_id);
        db.prepare('DELETE FROM bookmarks WHERE id=?').run(args.bookmark_id);
        result = { success: true };
        actions.push({ type: 'delete_bookmark', name: bm?.name || args.bookmark_id });

      } else if (fn === 'update_bookmark') {
        const bm = db.prepare('SELECT * FROM bookmarks WHERE id=?').get(args.bookmark_id);
        if (bm) {
          db.prepare('UPDATE bookmarks SET name=?, url=?, emoji=?, color=? WHERE id=?')
            .run(args.name ?? bm.name, args.url ?? bm.url, args.emoji ?? bm.emoji, args.color ?? bm.color, args.bookmark_id);
        }
        result = { success: !!bm };
        actions.push({ type: 'update_bookmark', name: args.name || bm?.name });
      }

      msgs.push({ role: 'tool', tool_call_id: call.id, content: JSON.stringify(result) });
    }
  }

  const last = msgs[msgs.length - 1];
  const message = typeof last.content === 'string' ? last.content : 'Done!';
  res.json({ message, actions });
});

// ── AI CATEGORIZE ─────────────────────────────────────────────────────────────
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

// ── CHROME BOOKMARKS IMPORT ───────────────────────────────────────────────────
app.post('/api/import/chrome', requireAuth, (req, res) => {
  const { html } = req.body;
  if (!html) return res.status(400).json({ error: 'html required' });

  // Parse Netscape bookmark HTML format
  const bookmarks = [];
  const linkRe = /<A\s+HREF="([^"]+)"[^>]*>([^<]+)<\/A>/gi;
  let match;
  while ((match = linkRe.exec(html)) !== null) {
    const url  = match[1].trim();
    const name = match[2].trim();
    if (url.startsWith('http') && name) {
      bookmarks.push({ name, url });
    }
  }

  res.json({ bookmarks, count: bookmarks.length });
});

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Bale Dashboard running on http://localhost:${PORT}`));
