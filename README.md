# AutoDoc — AI Car Diagnostics

AI-powered vehicle diagnostics. Runs on Cloudflare Pages, Termux (Android), and Windows.

---

## Quick Start

### Termux (Android)
```
pkg update && pkg install nodejs git
./start.sh
```
Open: `http://127.0.0.1:8788`

### Windows CMD
Double-click `start.bat`
OR run in CMD:
```
start.bat
```
Open: `http://127.0.0.1:8788`

### Cloudflare Pages (Production)
See deployment section below.

---

## First-Time Setup (All Platforms)

### 1. Add Your API Key

Edit the `.dev.vars` file and add at least one AI key:

**Termux / Linux:**
```
nano .dev.vars
```

**Windows:**
```
notepad .dev.vars
```

Add your Gemini key (free at aistudio.google.com):
```
GEMINI_API_KEY=AIza...your-key-here
```

Save and close. Then run start.sh or start.bat.

### 2. First Run

The launcher automatically:
- Checks Node.js version (18+ required)
- Installs wrangler (first run only, ~30 seconds)
- Creates local encrypted database
- Starts server on port 8788

---

## File Structure

```
autodoc_cf/
├── index.html              Landing page
├── autodoc/
│   └── index.html          Main app (login, chat, settings)
├── about/
│   └── index.html          About page
├── blog/
│   └── index.html          Blog page
├── dashboard/
│   └── index.html          Dashboard page
├── functions/
│   └── api/
│       └── [[path]].js     All backend API (Cloudflare Worker)
├── start.sh                Linux / Termux launcher
├── start.bat               Windows CMD launcher
├── start.js                Cross-platform launcher (Node.js)
├── wrangler.toml           Cloudflare config
├── package.json            Dependencies
├── _headers                Security headers
├── _redirects              URL redirects
├── .dev.vars               Local secrets (not committed to git)
└── .dev.vars.example       Template for .dev.vars
```

---

## Platform Requirements

| Platform | Requirement |
|---|---|
| Termux | Node.js 18+ (`pkg install nodejs`) |
| Windows | Node.js 18+ from nodejs.org |
| Cloudflare | Free account at cloudflare.com |

---

## Deploy to Cloudflare Pages

### Step 1 — Install Wrangler
```
npm install
```

### Step 2 — Login to Cloudflare
```
npx wrangler login
```
This opens a browser. Log in with your Cloudflare account.

### Step 3 — Create KV Namespace
```
npx wrangler kv namespace create USERS_KV
```
Copy the `id` from the output.

### Step 4 — Update wrangler.toml
Open `wrangler.toml` and replace both `REPLACE_WITH_KV_ID_FOR_PRODUCTION` with your KV id:
```
id = "paste-your-id-here"
preview_id = "paste-your-id-here"
```

### Step 5 — Push to GitHub
```
git init
git add .
git commit -m "AutoDoc v3"
git remote add origin https://github.com/YOUR_USERNAME/autodoc.git
git push -u origin main
```

### Step 6 — Connect Cloudflare Pages
1. Go to pages.cloudflare.com
2. Create project → Connect to Git → Select your repo
3. Build command: (leave empty)
4. Build output directory: `.`
5. Click Deploy

### Step 7 — Add Secrets in Dashboard
Go to: Pages → your project → Settings → Environment Variables

Add these (mark as Secret):
```
JWT_SECRET      = (run: node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")
GEMINI_API_KEY  = your-key
OPENAI_API_KEY  = your-key (optional)
GROK_API_KEY    = your-key (optional)
CLAUDE_API_KEY  = your-key (optional)
```

### Step 8 — Bind KV Namespace
Go to: Pages → Settings → Functions → KV Namespace Bindings
Add: Variable name = `USERS_KV`, KV namespace = the one you created

### Step 9 — Redeploy
Go to Deployments → click the latest deployment → Retry deployment

Your app is live at `https://autodoc.pages.dev`

---

## Security

- Passwords: PBKDF2 (100,000 iterations, SHA-256)
- User database: AES-256-GCM encrypted in Cloudflare KV
- API keys: AES-256-GCM encrypted per-user
- JWT tokens: HMAC-SHA256, 30-day expiry
- Rate limiting: Per-IP on all auth endpoints
- All crypto: Web Crypto API (built-in, no dependencies)
- Zero Node.js dependencies in production (pure Worker)

---

## Troubleshooting

**"wrangler: not found"**
Run `npm install` first.

**"KV namespace not found"**
Local dev uses `--kv=USERS_KV` flag automatically. No setup needed for local.

**"JWT_SECRET not set"**
Edit `.dev.vars` and add `JWT_SECRET=any-string-at-least-32-chars`

**Port 8788 in use**
Set a different port: `PORT=9000 node start.js`

**Windows: script won't run**
Right-click `start.bat` → Run as administrator. Or open CMD, navigate to folder, type `start.bat`

**Termux: pkg install fails**
Run `pkg update && pkg upgrade` first, then `pkg install nodejs`
