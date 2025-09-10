
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
    const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args)).catch(() => null);

    // Moderation knobs
    const MAX_PER_MINUTE = parseInt(process.env.MAX_PER_MINUTE || '1', 10);
    const MAX_PER_DAY = parseInt(process.env.MAX_PER_DAY || '10', 10);
    const BLOCK_LINKS = process.env.BLOCK_LINKS === '1';
    const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '';
    const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

    // Load banned terms
    const bannedPath = path.join(__dirname, 'data', 'banned.txt');
    let banned = [];
    try {
      banned = fs.readFileSync(bannedPath, 'utf8')
        .split(/\\n/)
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
    } catch (e) { banned = []; }

    function hasLink(text){
      const re = /(https?:\\/\\/|www\\.|[\\w-]+\\.(com|net|org|io|co|info|biz|me|ai|gov|edu|uk|de|fr|ae)(\\b|\\/))/i;
      return re.test(text);
    }
    function containsBanned(text){
      const lower = text.toLocaleLowerCase();
      return banned.some(term => lower.includes(term));
    }
    function excessiveCaps(text){
      const letters = text.replace(/[^A-Za-z\\p{L}]/gu, '');
      if (letters.length < 12) return false;
      const caps = (letters.match(/[A-Z\\p{Lu}]/gu) || []).length;
      return caps / letters.length > 0.8;
    }
    function normalizeInput(s){
      // Squash 3+ repeats, trim lines, limit to 12 lines
      let v = s.replace(/(.)\\1{2,}/g, '$1$1');
      v = v.split(/\\n/).slice(0,12).map(l => l.trimEnd()).join('\\n');
      return v.trim();
    }

    async function verifyTurnstile(token, ip){
      if (!TURNSTILE_SECRET_KEY) return true; // disabled
      try {
        const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          method:'POST',
          headers: {'Content-Type':'application/x-www-form-urlencoded'},
          body: new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token || '', remoteip: ip || '' })
        });
        if (!resp) return false;
        const data = await resp.json();
        return !!data.success;
      } catch(e){
        return false;
      }
    }

    function countRecent(ip, seconds){
      const row = db.prepare("SELECT COUNT(*) as c FROM submissions WHERE ip=? AND created_at >= datetime('now', ?)").get(ip, `-${seconds} seconds`);
      return row.c || 0;
    }
    function countToday(ip){
      const row = db.prepare("SELECT COUNT(*) as c FROM submissions WHERE ip=? AND date(created_at) = date('now', 'localtime')").get(ip);
      return row.c || 0;
    }


const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" } // Adjust for stricter origins if needed
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

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:"],
      "connect-src": ["'self'"]
    }
  }
}));
app.use(compression());
app.use(morgan('tiny'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Rate limiting for public endpoints
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

// Helpers
function sanitizeText(s) {
  // Basic cleanups; keep line breaks
  return String(s || '')
    .replace(/\r/g, '')
    .slice(0, 500) // hard cap
    .trim();
}

// Routes
app.get('/', (req, res) => res.redirect('/submit'));

app.get('/submit', (req, res) => {
  res.render('submit', { title: 'Share your words', TURNSTILE_SITE_KEY });
});

app.post('/submit', (req, res) => {
  const text = sanitizeText(req.body.text || '');
  if (!text) return res.status(400).render('error', { message: 'Please enter a few words.' });

  // Simple auto-flag using bad-words
  const auto_flagged = filter.isProfane(text) ? 1 : 0;
  const ip = req.ip;
  const ua = req.get('user-agent') || '';

  const stmt = db.prepare('INSERT INTO submissions (text, ip, user_agent, auto_flagged) VALUES (?, ?, ?, ?)');
  stmt.run(text, ip, ua, auto_flagged);

  res.render('thanks', { title: 'Thank you!' });
});

// JSON feed for approved items
app.get('/api/approved', (req, res) => {
  const rows = db.prepare('SELECT id, text, created_at FROM submissions WHERE approved=1 AND rejected=0 ORDER BY id ASC').all();
  res.json({ items: rows });
});

// Projection wall
app.get('/wall', (req, res) => {
  // Optional URL params: theme, columns, gap, fontsize
  const theme = req.query.theme || 'light'; // 'light' or 'dark'
  const columns = Math.max(1, Math.min(12, parseInt(req.query.columns || '5', 10)));
  const gap = req.query.gap || '1.5vmin';
  const fontsize = req.query.fontsize || '2.6vmin';
  res.render('wall', { title: 'Wall', theme, columns, gap, fontsize });
});

// Admin (basic auth)
const adminUser = process.env.ADMIN_USER || 'admin';
const adminPass = process.env.ADMIN_PASS || 'please-change-me';
const adminAuth = basicAuth({
  users: { [adminUser]: adminPass },
  challenge: true,
  realm: 'InteractiveWallAdmin'
});

app.get('/admin', adminAuth, (req, res) => {
  const pending = db.prepare('SELECT * FROM submissions WHERE approved=0 AND rejected=0 ORDER BY id DESC').all();
  const approved = db.prepare('SELECT * FROM submissions WHERE approved=1 AND rejected=0 ORDER BY id DESC LIMIT 100').all();
  res.render('admin', { title: 'Moderation', pending, approved });
});

app.post('/admin/approve/:id', adminAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.prepare('UPDATE submissions SET approved=1, rejected=0 WHERE id=?').run(id);

  // Emit real-time update
  const item = db.prepare('SELECT id, text, created_at FROM submissions WHERE id=?').get(id);
  io.emit('approved_item', item);

  res.redirect('/admin');
});

app.post('/admin/reject/:id', adminAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  db.prepare('UPDATE submissions SET approved=0, rejected=1 WHERE id=?').run(id);
  res.redirect('/admin');
});

app.post('/admin/bulk', adminAuth, (req, res) => {
  const ids = (req.body.ids || '').split(',').map(x => parseInt(x, 10)).filter(Boolean);
  const action = req.body.action;
  const approveStmt = db.prepare('UPDATE submissions SET approved=1, rejected=0 WHERE id=?');
  const rejectStmt = db.prepare('UPDATE submissions SET approved=0, rejected=1 WHERE id=?');

  const emitApproved = [];
  ids.forEach(id => {
    if (action === 'approve') {
      approveStmt.run(id);
      const item = db.prepare('SELECT id, text, created_at FROM submissions WHERE id=?').get(id);
      if (item) emitApproved.push(item);
    } else if (action === 'reject') {
      rejectStmt.run(id);
    }
  });
  // Emit all approved items after bulk
  emitApproved.forEach(item => io.emit('approved_item', item));
  res.redirect('/admin');
});

// Socket for wall live updates
io.on('connection', (socket) => {
  // No-op now; broadcast happens on approvals
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { message: 'Something went wrong.' });
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
