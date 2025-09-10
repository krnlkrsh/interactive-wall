# Interactive Wall (Art Installation)

Audience scans a QR code → writes a few words → words are moderated → approved words appear on a projection-friendly wall in real time. Each tile is A4 aspect ratio.

## Quick Start

1. **Requirements**: Node.js 18+
2. **Install**:
   ```bash
   npm install
   cp .env.example .env
   # edit ADMIN_USER and ADMIN_PASS in .env
   npm run initdb
   npm start
   ```
3. **Open**:
   - Submit form: http://localhost:3000/submit
   - Wall (projection): http://localhost:3000/wall?theme=dark&columns=5&gap=1.5vmin&fontsize=2.6vmin
   - Admin: http://localhost:3000/admin (basic auth)
   - JSON feed: http://localhost:3000/api/approved

## Moderation Flow

- Auto-flagging uses a basic profanity filter. **Everything still requires manual approval**.
- Admin dashboard lets you approve/reject individually or in bulk.
- On approval, the wall updates instantly via WebSockets (Socket.IO).

## Deployment Notes

- This app uses WebSockets; choose a host that supports them (Render, Fly.io, Railway, Heroku).
- Use `TRUST_PROXY=1` in `.env` if behind a proxy.
- Persistent storage: SQLite database file at `data/wall.db`.
  - For multi-instance scaling, move to Postgres and replace the DB calls.
- HTTPS is recommended in production.

## Projection Tips

- Use `/wall?theme=dark&columns=6&gap=1vmin&fontsize=2.4vmin` to tune density.
- Press browser fullscreen (F11) and hide OS UI.
- If you want landscape A4 tiles, change `aspect-ratio` to `297 / 210` in `public/style.css` or provide a `&landscape=1` feature.

## Customization

- Update styles in `public/style.css`.
- Update copy in `views/*.ejs`.
- Extend moderation (e.g., block URLs, rate-limit more aggressively, add captcha) as needed.

## License

MIT
