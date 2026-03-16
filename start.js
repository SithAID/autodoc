const { execSync, spawn } = require('child_process');
const fs   = require('fs');
const path = require('path');
const os   = require('os');

const isWindows = os.platform() === 'win32';
const isTermux  = fs.existsSync('/data/data/com.termux');
const isARM     = os.arch() === 'arm64' || os.arch() === 'arm';
const useNode   = isTermux || (isARM && os.platform() === 'linux') || process.env.USE_NODE_SERVER === '1';

const PORT = process.env.PORT || 8788;
const ROOT = __dirname;

function log(msg)  { console.log(`  ${msg}`); }
function ok(msg)   { console.log(`  \u2713  ${msg}`); }
function warn(msg) { console.log(`  \u26a0  ${msg}`); }
function err(msg)  { console.log(`  \u2717  ${msg}`); }
function hr()      { console.log('  ' + '\u2500'.repeat(40)); }

function runCmd(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', stdio: 'pipe' }).trim(); }
  catch { return null; }
}

function checkNode() {
  const ver = runCmd('node -v');
  if (!ver) { err('Node.js not found.'); process.exit(1); }
  const major = parseInt(ver.replace('v', '').split('.')[0]);
  if (major < 18) {
    err(`Node.js 18+ required. You have ${ver}`);
    if (isTermux) log('Run: pkg install nodejs');
    else if (isWindows) log('Download: https://nodejs.org');
    process.exit(1);
  }
  ok(`Node.js ${ver}`);
}

function ensureDevVars() {
  const devVars = path.join(ROOT, '.dev.vars');
  const example = path.join(ROOT, '.dev.vars.example');
  if (!fs.existsSync(devVars)) {
    if (fs.existsSync(example)) {
      fs.copyFileSync(example, devVars);
    } else {
      fs.writeFileSync(devVars,
        'JWT_SECRET=local-dev-secret-change-this-in-production-min32\n' +
        'GEMINI_API_KEY=\nOPENAI_API_KEY=\nGROK_API_KEY=\nCLAUDE_API_KEY=\n'
      );
    }
    warn('.dev.vars created. Add your API keys inside it.');
  }

  const content  = fs.readFileSync(devVars, 'utf8');
  const hasKey   = ['GEMINI_API_KEY', 'OPENAI_API_KEY', 'GROK_API_KEY', 'CLAUDE_API_KEY']
    .some(k => { const m = content.match(new RegExp(`${k}=(.+)`)); return m && m[1].trim().length > 3; });

  if (!hasKey) {
    warn('No AI API keys in .dev.vars');
    log(isWindows ? 'Edit: notepad .dev.vars' : 'Edit: nano .dev.vars');
    log('Add: GEMINI_API_KEY=AIza...');
    log('');
  } else {
    ok('.dev.vars loaded');
  }
}

function installWrangler() {
  const bin = path.join(ROOT, 'node_modules', '.bin', isWindows ? 'wrangler.cmd' : 'wrangler');
  if (!fs.existsSync(bin)) {
    log('Installing wrangler (first run only)...');
    try {
      execSync('npm install', { cwd: ROOT, stdio: 'inherit' });
      ok('Wrangler installed');
    } catch {
      err('npm install failed. Check internet connection.');
      process.exit(1);
    }
  } else {
    ok('Wrangler ready');
  }
}

function getLocalIP() {
  try {
    for (const ifaces of Object.values(os.networkInterfaces())) {
      for (const iface of ifaces) {
        if (iface.family === 'IPv4' && !iface.internal) return iface.address.padEnd(15);
      }
    }
  } catch {}
  return '(unavailable)  ';
}

function startNodeServer() {
  ok('Using built-in Node.js server (no wrangler needed)');
  hr();
  console.log('');
  console.log('  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510');
  console.log('  \u2502      AutoDoc \u2014 Node.js Local Server     \u2502');
  console.log('  \u251c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524');
  console.log(`  \u2502  Local:   http://127.0.0.1:${PORT}          \u2502`);
  console.log(`  \u2502  Network: http://${getLocalIP()}:${PORT}   \u2502`);
  console.log('  \u2502  Press Ctrl+C to stop                   \u2502');
  console.log('  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518');
  console.log('');

  const serverFile = path.join(ROOT, 'server-node.js');
  const child = spawn(process.execPath, [serverFile], {
    cwd: ROOT, stdio: 'inherit',
    env: { ...process.env, PORT: String(PORT) },
  });
  child.on('error', e => { err(`Failed: ${e.message}`); process.exit(1); });
  child.on('exit',  c => process.exit(c || 0));
  process.on('SIGINT',  () => child.kill('SIGINT'));
  process.on('SIGTERM', () => child.kill('SIGTERM'));
}

function startWrangler() {
  installWrangler();
  const wrangler = path.join(ROOT, 'node_modules', '.bin', isWindows ? 'wrangler.cmd' : 'wrangler');
  const stateDir = path.join(ROOT, '.wrangler', 'state');
  const args     = ['pages', 'dev', '.', `--port=${PORT}`, '--compatibility-date=2024-09-23', '--kv=USERS_KV', `--persist-to=${stateDir}`, '--log-level=warn'];
  hr();
  console.log('');
  console.log('  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510');
  console.log('  \u2502      AutoDoc \u2014 Wrangler Dev Server       \u2502');
  console.log('  \u251c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524');
  console.log(`  \u2502  Local:   http://127.0.0.1:${PORT}          \u2502`);
  console.log(`  \u2502  Network: http://${getLocalIP()}:${PORT}   \u2502`);
  console.log('  \u2502  Press Ctrl+C to stop                   \u2502');
  console.log('  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518');
  console.log('');
  const child = spawn(wrangler, args, { cwd: ROOT, stdio: 'inherit', shell: isWindows });
  child.on('error', e => { err(`Failed: ${e.message}`); process.exit(1); });
  child.on('exit',  c => process.exit(c || 0));
  process.on('SIGINT',  () => child.kill('SIGINT'));
  process.on('SIGTERM', () => child.kill('SIGTERM'));
}

console.log('');
console.log('  AutoDoc \u2014 Starting');
hr();
checkNode();
ensureDevVars();

if (useNode) {
  if (isTermux) ok('Platform: Termux (Android)');
  else if (isARM) ok('Platform: ARM Linux');
  else ok('Platform: Node.js mode (USE_NODE_SERVER=1)');
  startNodeServer();
} else {
  if (isWindows) ok('Platform: Windows');
  else ok('Platform: Linux/macOS');
  startWrangler();
}
