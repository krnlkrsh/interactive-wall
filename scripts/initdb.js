const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const dbPath = path.join(__dirname, '..', 'data', 'wall.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
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
console.log('Database initialized at', dbPath);
