// server.js (FULL REPLACEMENT)
// - Seeds DB from data/approved_submissions.csv if DB is empty (one-time on deploy)
// - Raises caps to 4000 for /api/approved, /admin approved list, and /api/admin/state approved list
// - Keeps everything else the same

require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const compression = require('compression');
const basicAuth = require('express-basic-auth');
const Filter = require('bad-words');
const filter = new Filter();
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const fs = require('fs');
const OpenAI = require('openai');

// OpenAI client (v4 SDK)
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Moderation knobs (kept from your version)
const MAX_PER_MINUTE = parseInt(process.env.MAX_PER_MINUTE || '1', 10);
const MAX_PER_DAY = parseInt(process.env.MAX_PER_DAY || '10', 10);
const BLOCK_LINKS = process.env.BLOCK_LINKS === '1';
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

// NEW: character limit (hard limit)
const MAX_CHARS = parseInt(process.env.MAX_CHARS || '300', 10);

// NEW: how many approved items the wall fetch returns
// Change default from 2000 -> 4000
const APPROVED_FEED_LIMIT = parseInt(process.env.APPROVED_FEED_LIMIT || '4000', 10);

// NEW: how many items to show in admin lists
const ADMIN_APPROVED_LIMIT = parseInt(process.env.ADMIN_APPROVED_LIMIT || '4000', 10);
const ADMIN_PENDING_LIMIT = parseInt(process.env.ADMIN_PENDING_LIMIT || '4000', 10);

// Seed CSV location (commit this file to your repo)
const SEED_CSV_PATH = path.join(__dirname, 'data', 'approved_submissions.csv');

// Load banned terms
const bannedPath = path.join(__dirname, 'data', 'banned.txt');
let banned = [];
try {
  banned = fs.readFileSync(bannedPath, 'utf8')
    .split(/\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
} catch (e) {
  banned = [];
}

// -------- Safer banned matching (prevents "ass" in "pass") --------
function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Define "word boundary" for Unicode letters/numbers, not ASCII \b
const WORD_CHARS = `[\\p{L}\\p{N}_]`;
const LEFT_BOUNDARY = `(?<!${WORD_CHARS})`;
const RIGHT_BOUNDARY = `(?!${WORD_CHARS})`;

// Build per-term regex matchers once
const bannedMatchers = banned
  .map((raw) => {
    const term = String(raw || '').trim();
    if (!term) return null;

    const normalized = term.normalize('NFKC').toLowerCase();

    // Treat multi-space as flexible whitespace
    const parts = normalized.split(/\s+/).filter(Boolean);
    const escaped = parts.map(escapeRegex).join('\\s+');

    const needsStrict = parts.join('').length <= 3;

    const pattern = needsStrict
      ? `${LEFT_BOUNDARY}${escaped}${RIGHT_BOUNDARY}`
      : `${LEFT_BOUNDARY}${escaped}${RIGHT_BOUNDARY}`;

    return { term, re: new RegExp(pattern, 'iu') };
  })
  .filter(Boolean);

// Normalize input for matching
function normalizeForMatch(text) {
  return String(text || '')
    .normalize('NFKC')
    .toLowerCase();
}

// Simple URL / link detector
function hasLink(text) {
  const re = /(https?:\/\/|www\.)\S+/i;
  return re.test(text);
}

function containsBanned(text) {
  const t = normalizeForMatch(text);
  for (const m of bannedMatchers) {
    if (m.re.test(t)) return true;
  }
  return false;
}

function excessiveCaps(text) {
  const letters = text.replace(/[^A-Za-z\p{L}]/gu, '');
  if (letters.length < 12) return false;
  const caps = (letters.match(/[A-Z\p{Lu}]/gu) || []).length;
  return caps / letters.length > 0.8;
}

function normalizeInput(s) {
  let v = s.replace(/(.)\1{2,}/g, '$1$1');
  v = v.split(/\n/).slice(0, 12).map(l => l.trimEnd()).join('\n');
  return v.trim();
}

// Turnstile verification
const fetch = (...args) => import('node-fetch')
  .then(({ default: fetch }) => fetch(...args))
  .catch(() => null);

async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY) return true;
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: TURNSTILE_SECRET_KEY,
        response: token || '',
        remoteip: ip || ''
      })
    });
    if (!resp) return false;
    const data = await resp.json();
    return !!data.success;
  } catch (e) {
    return false;
  }
}

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

const PORT = process.env.PORT || 3000;
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

// Database
const db = new Database(path.join(__dirname, 'data', 'wall.db'));
db.pragma('journal_mode = WAL');
db.prepare(`
  CREATE TABLE IF NOT EXISTS submissions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    ip TEXT,
    user_agent TEXT,
    auto_flagged INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0,
    rejected INTEGER DEFAULT 0
  )
`).run();

// -------------------------
// CSV seed (one-time)
// -------------------------

function parseCSV(content) {
  // Minimal CSV parser that supports:
  // - commas
  // - quoted fields
  // - newlines inside quoted fields
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < content.length; i++) {
    const c = content[i];

    if (inQuotes) {
      if (c === '"') {
        const next = content[i + 1];
        if (next === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
      continue;
    }

    if (c === '"') {
      inQuotes = true;
      continue;
    }

    if (c === ',') {
      row.push(field);
      field = '';
      continue;
    }

    if (c === '\n') {
      row.push(field);
      field = '';
      // ignore fully empty trailing line
      if (row.length > 1 || (row.length === 1 && row[0] !== '')) rows.push(row);
      row = [];
      continue;
    }

    if (c === '\r') continue;

    field += c;
  }

  // last field
  row.push(field);
  if (row.length > 1 || (row.length === 1 && row[0] !== '')) rows.push(row);

  return rows;
}

function normalizeHeader(h) {
  return String(h || '').trim().toLowerCase();
}

function toSqliteDatetime(dateStr, timeStr) {
  // Accept:
  // - dateStr like 2026-01-25 or 25/01/2026 etc (best effort)
  // - timeStr like 11:33:12
  // Output: "YYYY-MM-DD HH:MM:SS" (sqlite datetime text)
  const dRaw = String(dateStr || '').trim();
  const tRaw = String(timeStr || '').trim();

  // If the CSV already has a full datetime in one column, allow it.
  if (dRaw && !tRaw) {
    // If already "YYYY-MM-DD HH:MM:SS"
    if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$/.test(dRaw)) return dRaw;
    // If "YYYY-MM-DDTHH:MM:SS"
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(dRaw)) return dRaw.replace('T', ' ').slice(0, 19);
  }

  // Try YYYY-MM-DD
  let Y = null, M = null, D = null;

  if (/^\d{4}-\d{2}-\d{2}$/.test(dRaw)) {
    const parts = dRaw.split('-').map(x => parseInt(x, 10));
    Y = parts[0]; M = parts[1]; D = parts[2];
  } else if (/^\d{2}\/\d{2}\/\d{4}$/.test(dRaw)) {
    // DD/MM/YYYY
    const parts = dRaw.split('/').map(x => parseInt(x, 10));
    D = parts[0]; M = parts[1]; Y = parts[2];
  } else if (/^\d{4}\/\d{2}\/\d{2}$/.test(dRaw)) {
    // YYYY/MM/DD
    const parts = dRaw.split('/').map(x => parseInt(x, 10));
    Y = parts[0]; M = parts[1]; D = parts[2];
  }

  // Default if parsing fails: now
  if (!Y || !M || !D) {
    return db.prepare("SELECT datetime('now') as dt").get().dt;
  }

  const time = /^\d{2}:\d{2}:\d{2}$/.test(tRaw) ? tRaw : '00:00:00';
  const mm = String(M).padStart(2, '0');
  const dd = String(D).padStart(2, '0');
  return `${Y}-${mm}-${dd} ${time}`;
}

function seedFromApprovedCsvIfEmpty() {
  try {
    const row = db.prepare('SELECT COUNT(*) as c FROM submissions').get();
    const count = row && row.c ? row.c : 0;
    if (count > 0) return; // not empty, do nothing

    if (!fs.existsSync(SEED_CSV_PATH)) {
      console.log('[seed] DB empty but seed CSV not found at:', SEED_CSV_PATH);
      return;
    }

    const csv = fs.readFileSync(SEED_CSV_PATH, 'utf8');
    const rows = parseCSV(csv);
    if (!rows.length) {
      console.log('[seed] seed CSV is empty');
      return;
    }

    // Detect header
    const header = rows[0].map(normalizeHeader);

    const idxId =
      header.indexOf('id') >= 0 ? header.indexOf('id') :
      header.indexOf('number') >= 0 ? header.indexOf('number') :
      header.indexOf('#') >= 0 ? header.indexOf('#') : -1;

    const idxText =
      header.indexOf('text') >= 0 ? header.indexOf('text') :
      header.indexOf('submission') >= 0 ? header.indexOf('submission') :
      header.indexOf('message') >= 0 ? header.indexOf('message') : -1;

    const idxCreated =
      header.indexOf('created_at') >= 0 ? header.indexOf('created_at') :
      header.indexOf('created') >= 0 ? header.indexOf('created') :
      header.indexOf('datetime') >= 0 ? header.indexOf('datetime') : -1;

    const idxDate = header.indexOf('date');
    const idxTime = header.indexOf('time');

    const hasHeader = (idxText !== -1) && (idxId !== -1 || idxCreated !== -1 || (idxDate !== -1 && idxTime !== -1));
    const start = hasHeader ? 1 : 0;

    const insert = db.prepare(`
      INSERT INTO submissions
      (id, text, created_at, ip, user_agent, auto_flagged, approved, rejected)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const tx = db.transaction((items) => {
      for (const it of items) {
        insert.run(it.id, it.text, it.created_at, '', 'seed', 0, 1, 0);
      }
    });

    const items = [];
    for (let r = start; r < rows.length; r++) {
      const cols = rows[r];

      const rawId = (idxId >= 0 ? cols[idxId] : cols[0]);
      const id = parseInt(String(rawId || '').trim(), 10);
      if (!Number.isFinite(id) || id <= 0) continue;

      const text = String((idxText >= 0 ? cols[idxText] : cols[cols.length - 1]) || '').replace(/\r/g, '');
      if (!text.trim()) continue;

      let created_at = null;
      if (idxCreated >= 0) {
        created_at = toSqliteDatetime(cols[idxCreated], '');
      } else if (idxDate >= 0 && idxTime >= 0) {
        created_at = toSqliteDatetime(cols[idxDate], cols[idxTime]);
      } else {
        // fallback: second+third columns if they look like date/time
        created_at = toSqliteDatetime(cols[1], cols[2]);
      }

      items.push({ id, text, created_at });
    }

    if (!items.length) {
      console.log('[seed] no rows parsed from seed CSV');
      return;
    }

    tx(items);

    // Ensure AUTOINCREMENT continues from the max seeded id
    const maxRow = db.prepare('SELECT MAX(id) as m FROM submissions').get();
    const maxId = maxRow && maxRow.m ? maxRow.m : 0;
    try {
      db.prepare("UPDATE sqlite_sequence SET seq=? WHERE name='submissions'").run(maxId);
    } catch (e) {
      // ignore if sqlite_sequence not present for any reason
    }

    console.log(`[seed] seeded ${items.length} approved submissions from CSV (max id=${maxId})`);
  } catch (e) {
    console.error('[seed] failed:', e);
  }
}

// Seed immediately on startup (before routes)
seedFromApprovedCsvIfEmpty();

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'", "'unsafe-inline'", "https://challenges.cloudflare.com"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:"],
      "connect-src": ["'self'", "https://challenges.cloudflare.com"],
      "frame-src": ["'self'", "https://challenges.cloudflare.com"]
    }
  }
}));

app.use(compression());
app.use(morgan('tiny'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 30 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(['/submit', '/api/submit'], limiter);

// Views & static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/static', express.static(path.join(__dirname, 'public')));

// Sanitize
function sanitizeText(s) {
  return String(s || '')
    .replace(/\r/g, '')
    .slice(0, MAX_CHARS)
    .trim();
}

// OpenAI moderation
async function isFlaggedByOpenAI(text) {
  if (!openai.apiKey) return false;
  try {
    const response = await openai.moderations.create({
      model: 'omni-moderation-latest',
      input: text
    });
    const result = response.results && response.results[0];
    return !!(result && result.flagged);
  } catch (err) {
    console.error('OpenAI moderation error:', err.message || err);
    return false;
  }
}

// ---------- ROUTES ----------

app.get('/', (req, res) => res.redirect('/submit'));

// 🚫 PUBLIC /submit is now blocked
app.get('/submit', (req, res) => {
  res.render('error', {
    title: 'Access Restricted',
    message: 'Please use the official QR code to submit your message.'
  });
});

// ✅ SECRET QR PATH (YOUR LINK)
app.get('/access-7f3b9kz2m', (req, res) => {
  res.render('submit', {
    title: 'Share your words',
    TURNSTILE_SITE_KEY
  });
});

// Floating wall
app.get('/wall-floating', (req, res) => {
  res.render('wall_floating', { title: 'Floating Quotes' });
});

// ---------- Submit route ----------
app.post('/submit', async (req, res) => {
  const raw = req.body.text || '';

  const normalized = normalizeInput(raw);
  const cleaned = String(normalized || '').replace(/\r/g, '').trim();

  if (!cleaned) {
    return res.status(400).render('error', { message: 'Please enter a few words.' });
  }

  if (cleaned.length > MAX_CHARS) {
    return res.status(400).render('error', { message: `Please keep it under ${MAX_CHARS} characters.` });
  }

  const text = sanitizeText(cleaned);

  const ip = req.ip;
  const ua = req.get('user-agent') || '';

  const turnstileToken = req.body['cf-turnstile-response'];
  const humanOK = await verifyTurnstile(turnstileToken, ip);
  if (!humanOK) {
    return res.status(400).render('error', { message: 'Captcha verification failed.' });
  }

  let auto_flagged = 0;

  if (BLOCK_LINKS && hasLink(text)) auto_flagged = 1;
  if (containsBanned(text)) auto_flagged = 1;
  if (excessiveCaps(text)) auto_flagged = 1;
  if (filter.isProfane(text)) auto_flagged = 1;

  const aiFlagged = await isFlaggedByOpenAI(text);
  if (aiFlagged) auto_flagged = 1;

  const approved = auto_flagged ? 0 : 1;

  const stmt = db.prepare(
    'INSERT INTO submissions (text, ip, user_agent, auto_flagged, approved) VALUES (?, ?, ?, ?, ?)'
  );
  const info = stmt.run(text, ip, ua, auto_flagged, approved);

  if (approved) {
    const item = db.prepare(
      'SELECT id, text, created_at FROM submissions WHERE id=?'
    ).get(info.lastInsertRowid);
    if (item) {
      io.emit('approved_item', item);
    }
  }

  res.render('thanks', { title: 'Thank you!' });
});

// Approved feed (LIMIT now defaults to 4000)
app.get('/api/approved', (req, res) => {
  try {
    res.set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Surrogate-Control': 'no-store'
    });

    const rows = db.prepare(
      `SELECT id, text, created_at
       FROM submissions
       WHERE approved=1 AND rejected=0
       ORDER BY created_at DESC
       LIMIT ?`
    ).all(APPROVED_FEED_LIMIT);

    res.json({ items: rows });
  } catch (err) {
    res.status(500).json({ error: 'failed_to_fetch' });
  }
});

// Wall grid (unchanged)
app.get('/wall', (req, res) => {
  const theme = req.query.theme || 'light';
  const columns = Math.max(1, Math.min(12, parseInt(req.query.columns || '5', 10)));
  const gap = req.query.gap || '1.5vmin';
  const fontsize = req.query.fontsize || '2.6vmin';
  res.render('wall', { title: 'Wall', theme, columns, gap, fontsize });
});

// Admin routes
const adminUser = process.env.ADMIN_USER || 'admin';
const adminPass = process.env.ADMIN_PASS || 'please-change-me';
const adminAuth = basicAuth({
  users: { [adminUser]: adminPass },
  challenge: true,
  realm: 'InteractiveWallAdmin'
});

app.get('/admin', adminAuth, (req, res) => {
  const pending = db.prepare(
    'SELECT * FROM submissions WHERE approved=0 AND rejected=0 ORDER BY id DESC LIMIT ?'
  ).all(ADMIN_PENDING_LIMIT);

  const approved = db.prepare(
    'SELECT * FROM submissions WHERE approved=1 AND rejected=0 ORDER BY id DESC LIMIT ?'
  ).all(ADMIN_APPROVED_LIMIT);

  res.render('admin', { title: 'Moderation', pending, approved });
});

app.get('/api/admin/state', adminAuth, (req, res) => {
  try {
    res.set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Surrogate-Control': 'no-store'
    });

    const pending = db.prepare(
      'SELECT id, text, created_at, auto_flagged FROM submissions WHERE approved=0 AND rejected=0 ORDER BY id DESC LIMIT ?'
    ).all(ADMIN_PENDING_LIMIT);

    const approved = db.prepare(
      'SELECT id, text, created_at FROM submissions WHERE approved=1 AND rejected=0 ORDER BY id DESC LIMIT ?'
    ).all(ADMIN_APPROVED_LIMIT);

    const sig = `p${pending[0] ? pending[0].id : 0}-a${approved[0] ? approved[0].id : 0}-pc${pending.length}-ac${approved.length}`;

    res.json({ sig, pending, approved });
  } catch (e) {
    res.status(500).json({ error: 'failed' });
  }
});

app.post('/admin/approve/:id', adminAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.prepare('UPDATE submissions SET approved=1, rejected=0 WHERE id=?').run(id);

  const item = db.prepare(
    'SELECT id, text, created_at FROM submissions WHERE id=?'
  ).get(id);
  if (item) io.emit('approved_item', item);

  res.redirect('/admin');
});

app.post('/admin/reject/:id', adminAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.prepare('UPDATE submissions SET approved=0, rejected=1 WHERE id=?').run(id);
  res.redirect('/admin');
});

app.post('/admin/remove/:id', adminAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.prepare('UPDATE submissions SET approved=0, rejected=1 WHERE id=?').run(id);
  io.emit('removed_item', { id });
  res.redirect('/admin');
});

app.post('/admin/bulk', adminAuth, (req, res) => {
  const ids = (req.body.ids || '')
    .split(',')
    .map(x => parseInt(x, 10))
    .filter(Boolean);
  const action = req.body.action;

  const approveStmt = db.prepare(
    'UPDATE submissions SET approved=1, rejected=0 WHERE id=?'
  );
  const rejectStmt = db.prepare(
    'UPDATE submissions SET approved=0, rejected=1 WHERE id=?'
  );

  const emitApproved = [];
  ids.forEach(id => {
    if (action === 'approve') {
      approveStmt.run(id);
      const item = db.prepare(
        'SELECT id, text, created_at FROM submissions WHERE id=?'
      ).get(id);
      if (item) emitApproved.push(item);
    } else if (action === 'reject') {
      rejectStmt.run(id);
    }
  });

  emitApproved.forEach(item => io.emit('approved_item', item));
  res.redirect('/admin');
});

io.on('connection', (socket) => {});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { message: 'Something went wrong.' });
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
