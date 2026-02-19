const path = require("path");
const fs = require("fs");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const http = require("http");
const WebSocket = require("ws");
const jwt = require("jsonwebtoken");
const app = express();
// trust proxy bug fix
app.set("trust proxy", true);

// -----------------------
// Config
// -----------------------
function envStr(name, fallback = "") {
  const v = process.env[name];
  if (v === undefined || v === null || String(v).trim() === "") return fallback;
  return String(v);
}

function requireEnv(name) {
  const v = envStr(name);
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const CONFIG = {
  port: parseInt(envStr("PORT", "3000"), 10),
  nodeEnv: envStr("NODE_ENV", "production"),
  authPin: requireEnv("AUTH_PIN"),
  ownerPin: requireEnv("OWNER_PIN"),
  jwtSecret: requireEnv("JWT_SECRET"),
  accessExpiresDays: parseInt(envStr("ACCESS_EXPIRES_DAYS", "7"), 10) || 7,
  dbPath: envStr("DB_PATH", "./data/divine.sqlite"),

  // Env fallback only. Real lockdown state is stored in DB.
  lockdownEnabledEnv: envStr("LOCKDOWN_ENABLED", "0") === "1",

  userPinMaxFails: 3,
  userPinLockSeconds: 300,

  ownerPinMaxFails: 3,
  ownerPinLockSeconds: 24 * 60 * 60,

  usernameCooldownDays: 14,
};

const COOKIE_USER = "divine_access";
const COOKIE_OWNER_ONCE = "dv_owner_once";
const ownerOnceTokens = new Map();

// -----------------------
// Helpers
// -----------------------
function ensureDirForFile(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function nowMs() {
  return Date.now();
}

function getReqIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.trim()) return xf.split(",")[0].trim();
  return req.ip || "";
}

function accessCookieMaxAgeMs() {
  return CONFIG.accessExpiresDays * 24 * 60 * 60 * 1000;
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function createJWT(userId) {
  const expiresIn = `${CONFIG.accessExpiresDays}d`;
  return jwt.sign({ userId: String(userId) }, CONFIG.jwtSecret, { expiresIn });
}

function verifyJWT(token) {
  try {
    const decoded = jwt.verify(token, CONFIG.jwtSecret);
    return decoded.userId || null;
  } catch {
    return null;
  }
}

function setUserCookie(res, token) {
  const isProd = CONFIG.nodeEnv === "production";
  res.cookie(COOKIE_USER, token, {
    httpOnly: false,
    sameSite: "Lax",
    secure: isProd,
    path: "/",
    maxAge: accessCookieMaxAgeMs(),
  });
}

function clearUserCookie(res) {
  const isProd = CONFIG.nodeEnv === "production";
  res.cookie(COOKIE_USER, "", {
    httpOnly: false,
    sameSite: "Lax",
    secure: isProd,
    path: "/",
    maxAge: 0,
  });
}

async function issueUserSession(res, userId) {
  const token = createJWT(userId);
  setUserCookie(res, token);
}

async function revokeUserSessions(userId) {
  // JWT tokens cannot be revoked server-side without a blacklist
  // This function is kept for API compatibility but currently does nothing
  // SECURITY NOTE: JWTs remain valid until expiration even after this is called
  // For security-critical operations (password changes, account compromise):
  //   1. Clear the user's cookie immediately
  //   2. Tokens will remain valid until they expire (default: 7 days)
  //   3. Consider implementing a token blacklist for immediate revocation
}

async function revokeCurrentSession(req) {
  // JWT tokens cannot be revoked server-side without a blacklist
  // This function is kept for API compatibility but currently does nothing
  // SECURITY NOTE: The JWT token will remain valid until expiration
  // The cookie should be cleared on logout, which prevents browser reuse
  // However, if the token was copied elsewhere, it remains valid until expiry
}

function issueOwnerOnceCookie(res) {
  const isProd = CONFIG.nodeEnv === "production";
  const token = randomToken(24);
  ownerOnceTokens.set(token, nowMs() + (5 * 60 * 1000));
  res.cookie(COOKIE_OWNER_ONCE, token, {
    httpOnly: true,
    sameSite: "Lax",
    secure: isProd,
    path: "/owner",
    maxAge: 5 * 60 * 1000,
  });
}

function isValidOwnerOnceToken(tok) {
  if (!tok) return false;
  const exp = ownerOnceTokens.get(String(tok));
  if (!exp) return false;
  if (nowMs() >= exp) {
    ownerOnceTokens.delete(String(tok));
    return false;
  }
  return true;
}

function consumeOwnerOnceCookie(req, res) {
  const tok = req.cookies[COOKIE_OWNER_ONCE];
  if (!isValidOwnerOnceToken(tok)) return false;
  ownerOnceTokens.delete(String(tok));

  const isProd = CONFIG.nodeEnv === "production";
  res.cookie(COOKIE_OWNER_ONCE, "", {
    httpOnly: true,
    sameSite: "Lax",
    secure: isProd,
    path: "/owner",
    maxAge: 0,
  });
  return true;
}

function normalizeUsername(u) {
  return String(u || "").trim();
}

function validUsername(u) {
  if (!u) return false;
  if (u.length < 3 || u.length > 24) return false;
  if (!/^[a-zA-Z0-9._-]+$/.test(u)) return false;
  return true;
}

function randomUserId(len = 16) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < len; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return out;
}

function clampStr(s, maxLen) {
  const x = String(s || "");
  return x.length > maxLen ? x.slice(0, maxLen) : x;
}

function validClientId(cid) {
  if (!cid || typeof cid !== "string") return false;
  if (cid.length < 8 || cid.length > 128) return false;
  // Allow alphanumeric, hyphens, and underscores (typical UUID/GUID format)
  if (!/^[a-zA-Z0-9_-]+$/.test(cid)) return false;
  return true;
}

function fmtTimeSec(ms) {
  try {
    const d = new Date(Number(ms || 0));
    return d.toISOString().replace("T", " ").replace("Z", "");
  } catch {
    return "";
  }
}

// -----------------------
// Lockouts (in-memory, per IP)
// -----------------------
const pinLocks = {
  user: new Map(),
  owner: new Map(),
};

function getLock(map, ip) {
  const v = map.get(ip);
  if (!v) return { fails: 0, untilMs: 0 };
  return v;
}
function clearLock(map, ip) {
  map.delete(ip);
}
function isLocked(map, ip) {
  const v = getLock(map, ip);
  return v.untilMs && nowMs() < v.untilMs;
}
function remainingSeconds(map, ip) {
  const v = getLock(map, ip);
  if (!v.untilMs) return 0;
  const rem = Math.ceil((v.untilMs - nowMs()) / 1000);
  return rem > 0 ? rem : 0;
}
function registerFail(map, ip, maxFails, lockSeconds) {
  const v = getLock(map, ip);
  const fails = (v.fails || 0) + 1;
  let untilMs = v.untilMs || 0;
  if (fails >= maxFails) untilMs = nowMs() + lockSeconds * 1000;
  map.set(ip, { fails, untilMs });
  return { fails, untilMs };
}
function registerSuccess(map, ip) {
  clearLock(map, ip);
}

// -----------------------
// DB (SQLite)
// -----------------------
ensureDirForFile(CONFIG.dbPath);
const db = new sqlite3.Database(CONFIG.dbPath);

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ changes: this.changes, lastID: this.lastID });
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function (err, row) {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function (err, rows) {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

async function initDb() {
  await dbRun(`PRAGMA foreign_keys = ON;`);
  try { await dbRun(`PRAGMA journal_mode = WAL;`); } catch {}

  await dbRun(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  email TEXT NOT NULL,
  bio TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  token_version INTEGER NOT NULL DEFAULT 0,
  last_ip TEXT NOT NULL DEFAULT '',
  banned_until INTEGER NOT NULL DEFAULT 0,
  ban_reason TEXT NOT NULL DEFAULT '',
  username_changed_at INTEGER NOT NULL DEFAULT 0
);`);

  await dbRun(`
CREATE TABLE IF NOT EXISTS user_sessions (
  session_token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);`);

  await dbRun(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);`);

  // Add last_seen_at column if it doesn't exist (migration)
  try {
    await dbRun(`ALTER TABLE users ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0;`);
  } catch {
    // Column already exists
  }
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen_at);`);

  // Owner-controlled state (lockdown + future flags)
  await dbRun(`
CREATE TABLE IF NOT EXISTS owner_state (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);`);

  // Activity logging
  await dbRun(`
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  path TEXT NOT NULL,
  ip TEXT NOT NULL
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_activity_created_at ON activity(created_at);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_activity_user ON activity(user_id);`);

  // Reports (from users)
  await dbRun(`
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  reporter_id TEXT NOT NULL,
  reporter_username TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_ref TEXT NOT NULL,
  target_username TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open'
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);`);

  // Broadcasts
  await dbRun(`
CREATE TABLE IF NOT EXISTS broadcasts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  scope TEXT NOT NULL,
  target_username TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_broadcasts_created_at ON broadcasts(created_at);`);

  // Redirect-on-next-load (one-time)
  await dbRun(`
CREATE TABLE IF NOT EXISTS user_redirects (
  user_id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  created_at INTEGER NOT NULL
);`);

  // DM system tables
  await dbRun(`
CREATE TABLE IF NOT EXISTS dm_bans (
  user_id TEXT PRIMARY KEY,
  banned_until INTEGER NOT NULL,
  ban_reason TEXT NOT NULL,
  created_at INTEGER NOT NULL
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_bans_until ON dm_bans(banned_until);`);

  await dbRun(`
CREATE TABLE IF NOT EXISTS dm_threads (
  id TEXT PRIMARY KEY,
  user_a TEXT NOT NULL,
  user_b TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_message_at INTEGER NOT NULL
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_threads_user_a ON dm_threads(user_a);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_threads_user_b ON dm_threads(user_b);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_threads_last_message ON dm_threads(last_message_at);`);

  await dbRun(`
CREATE TABLE IF NOT EXISTS dm_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user_id TEXT NOT NULL,
  to_user_id TEXT NOT NULL,
  invite_message TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  responded_at INTEGER NOT NULL DEFAULT 0
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_requests_to ON dm_requests(to_user_id, status);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_requests_from ON dm_requests(from_user_id);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_requests_created ON dm_requests(created_at);`);

  await dbRun(`
CREATE TABLE IF NOT EXISTS dm_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id TEXT NOT NULL,
  from_user_id TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_messages_thread ON dm_messages(thread_id, created_at);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_messages_from ON dm_messages(from_user_id);`);

  await dbRun(`
CREATE TABLE IF NOT EXISTS dm_reads (
  thread_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  last_read_message_id INTEGER NOT NULL,
  last_read_at INTEGER NOT NULL,
  PRIMARY KEY (thread_id, user_id)
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_reads_user ON dm_reads(user_id);`);

  await dbRun(`
CREATE TABLE IF NOT EXISTS dm_appeals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  appeal_text TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'open'
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_dm_appeals_status ON dm_appeals(status, created_at);`);

  // Client tracking table for /api/check and /api/hello
  await dbRun(`
CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'verified',
  last_seen_at INTEGER NOT NULL,
  last_ip TEXT,
  device_info TEXT,
  created_at INTEGER NOT NULL
);`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);`);

  // Ensure a default lockdown value exists (env is fallback only)
  const existing = await dbGet(`SELECT v FROM owner_state WHERE k='lockdown_enabled'`);
  if (!existing) {
    const init = CONFIG.lockdownEnabledEnv ? "1" : "0";
    await dbRun(`INSERT INTO owner_state(k,v) VALUES('lockdown_enabled',?)`, [init]);
  }
}

async function isUserBanned(userRow) {
  if (!userRow) return false;
  const until = parseInt(userRow.banned_until || "0", 10);
  return until && nowMs() < until;
}

async function updateLastSeen(userId) {
  await dbRun(`UPDATE users SET last_seen_at=? WHERE id=?`, [nowMs(), String(userId)]);
}

async function updateLastIp(userId, ip) {
  await dbRun(`UPDATE users SET last_ip=? WHERE id=?`, [String(ip || ""), String(userId)]);
}

async function verifyUserFromRequest(req) {
  const tok = req.cookies[COOKIE_USER];
  if (!tok) return null;
  
  const userId = verifyJWT(tok);
  if (!userId) return null;

  const user = await dbGet(`SELECT * FROM users WHERE id=?`, [String(userId)]);
  if (!user) return null;
  return user;
}

function msUntilUsernameChangeAllowed(user) {
  const last = parseInt(user.username_changed_at || "0", 10);
  const cooldownMs = CONFIG.usernameCooldownDays * 24 * 60 * 60 * 1000;
  const nextOk = last + cooldownMs;
  const rem = nextOk - nowMs();
  return rem > 0 ? rem : 0;
}

async function requireUser(req, res) {
  const user = await verifyUserFromRequest(req);
  if (!user) {
    res.status(401).json({ ok: false, error: "Unauthorized" });
    return null;
  }
  try { await updateLastIp(user.id, getReqIp(req)); } catch {}
  if (await isUserBanned(user)) {
    clearUserCookie(res);
    res.status(403).json({ ok: false, error: "Banned" });
    return null;
  }
  return user;
}

// -------- DM ban helpers --------
async function isUserDmBanned(userId) {
  const row = await dbGet(`SELECT banned_until FROM dm_bans WHERE user_id=?`, [String(userId)]);
  if (!row) return false;
  const until = parseInt(row.banned_until || "0", 10);
  return until && nowMs() < until;
}

async function getDmBan(userId) {
  return await dbGet(`SELECT * FROM dm_bans WHERE user_id=?`, [String(userId)]);
}

function generateThreadId(userIdA, userIdB) {
  // Always sort to ensure consistent thread ID for both users
  const sorted = [String(userIdA), String(userIdB)].sort();
  return `${sorted[0]}__${sorted[1]}`;
}

// -------- Client access control helpers --------
async function getOrCreateClient(clientId, ip, deviceInfo = null) {
  const now = nowMs();
  let client = await dbGet(`SELECT * FROM clients WHERE client_id=?`, [clientId]);
  
  if (!client) {
    // New client - default to verified status
    await dbRun(
      `INSERT INTO clients(client_id, status, last_seen_at, last_ip, device_info, created_at) VALUES(?,?,?,?,?,?)`,
      [clientId, "verified", now, ip, deviceInfo, now]
    );
    return { client_id: clientId, status: "verified", last_seen_at: now, last_ip: ip, device_info: deviceInfo, created_at: now };
  }
  
  // Update last seen and device info for existing client
  await dbRun(
    `UPDATE clients SET last_seen_at=?, last_ip=?, device_info=COALESCE(?, device_info) WHERE client_id=?`,
    [now, ip, deviceInfo, clientId]
  );
  
  return client;
}

function safeStringifyDevice(device) {
  try {
    if (!device || typeof device !== "object") return "{}";
    
    // Limit the size and depth to prevent abuse
    const safe = {
      ua: clampStr(String(device.ua || ""), 500),
      platform: clampStr(String(device.platform || ""), 100),
      language: clampStr(String(device.language || ""), 50),
      timezone: clampStr(String(device.timezone || ""), 100),
      screen: clampStr(String(device.screen || ""), 50)
    };
    
    return JSON.stringify(safe);
  } catch {
    return "{}";
  }
}

// -------- Owner auth helper for APIs (must be called after /owner cookie middleware in chain) --------
function requireOwner(req, res) {
  // Owner cookie is consumed in /owner middleware for page loads.
  // For API calls, we require a fresh pin cookie too, but because you wanted "every reload",
  // we keep owner pin in a short 5m cookie, and allow API calls during that window.
  // The UI calls /owner/pin and then proceeds immediately.
  const tok = req.cookies[COOKIE_OWNER_ONCE];
  if (!isValidOwnerOnceToken(tok)) {
    res.status(401).json({ ok: false, error: "Owner auth required" });
    return false;
  }
  return true;
}

// -------- Owner state helpers --------
async function getLockdownEnabled() {
  const row = await dbGet(`SELECT v FROM owner_state WHERE k='lockdown_enabled'`);
  if (!row) return false;
  return String(row.v) === "1";
}

async function setLockdownEnabled(enabled) {
  await dbRun(`INSERT INTO owner_state(k,v) VALUES('lockdown_enabled',?)
               ON CONFLICT(k) DO UPDATE SET v=excluded.v`, [enabled ? "1" : "0"]);
}

// -------- Activity --------
async function logActivity(user, reqPath, reqIp) {
  try {
    await dbRun(
      `INSERT INTO activity(created_at, user_id, username, path, ip) VALUES(?,?,?,?,?)`,
      [nowMs(), String(user.id), String(user.username), clampStr(reqPath, 260), clampStr(reqIp, 80)]
    );
  } catch {}
}

// -------- Redirect-on-next-load --------
async function getAndConsumeRedirect(userId) {
  const row = await dbGet(`SELECT url FROM user_redirects WHERE user_id=?`, [String(userId)]);
  if (!row || !row.url) return "";
  // consume
  await dbRun(`DELETE FROM user_redirects WHERE user_id=?`, [String(userId)]);
  return String(row.url);
}

// -------- Ban duration parsing --------
function parseDurationToMs(input) {
  const s = String(input || "").trim().toLowerCase();
  if (!s) return null;
  if (s === "permanent" || s === "perm" || s === "forever") return Infinity;

  // supports: 10m, 1h, 2d
  const m = s.match(/^(\d+)\s*([mhd])$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = m[2];

  if (!Number.isFinite(n) || n <= 0) return null;

  if (unit === "m") return n * 60 * 1000;
  if (unit === "h") return n * 60 * 60 * 1000;
  if (unit === "d") return n * 24 * 60 * 60 * 1000;
  return null;
}

// -----------------------
// WebSocket infrastructure
// -----------------------
const wsClients = new Map(); // userId -> Set of WebSocket connections

function notifyUser(userId, payload) {
  const clients = wsClients.get(String(userId));
  if (!clients || clients.size === 0) return;
  
  const message = JSON.stringify(payload);
  for (const ws of clients) {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(message);
      } catch (e) {
        console.error("WS send error:", e);
      }
    }
  }
}

function registerWsClient(userId, ws) {
  const uid = String(userId);
  if (!wsClients.has(uid)) {
    wsClients.set(uid, new Set());
  }
  wsClients.get(uid).add(ws);
}

function unregisterWsClient(userId, ws) {
  const uid = String(userId);
  const clients = wsClients.get(uid);
  if (!clients) return;
  clients.delete(ws);
  if (clients.size === 0) {
    wsClients.delete(uid);
  }
}

// -----------------------
// App
// -----------------------
app.disable("x-powered-by");
// IMPORTANT: for most hosts you SHOULD set trust proxy true if behind a proxy
// but leaving your original behavior unchanged.
app.set("trust proxy", false);
// Enable strict routing so /divine and /divine/ are treated as different routes
app.set("strict routing", true);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cookieParser());
app.use(express.json({ limit: "400kb" }));
app.use(express.urlencoded({ extended: false }));

// -----------------------
// Page routes (serve real files)
// -----------------------
const REPO_ROOT = path.join(__dirname, "..");
const sendRepoFile = (res, relPath) => res.sendFile(path.join(REPO_ROOT, relPath));

// Under construction at / (served with/without hidden trigger depending on lockdown)
app.get("/", async (req, res) => {
  try {
    // Check if user has access cookie - if so, redirect to /divine
    // Only verify if cookie exists to avoid unnecessary DB queries
    if (req.cookies[COOKIE_USER]) {
      const user = await verifyUserFromRequest(req);
      if (user) {
        return res.redirect(302, "/divine/");
      }
    }

    const enabled = await getLockdownEnabled();
    if (enabled) {
      const f = path.join(REPO_ROOT, "index.lockdown.html");
      if (fs.existsSync(f)) return res.sendFile(f);
    }
  } catch {}
  return sendRepoFile(res, "index.html");
});

// Activation pages (blocked during lockdown)
app.get("/activate", async (req, res) => {
  try {
    const enabled = await getLockdownEnabled();
    if (enabled) {
      return res.redirect(302, "/");
    }
  } catch {}
  return sendRepoFile(res, "activate/index.html");
});
app.get("/activate/register", async (req, res) => {
  try {
    const enabled = await getLockdownEnabled();
    if (enabled) {
      return res.redirect(302, "/");
    }
  } catch {}
  return sendRepoFile(res, "activate/register/index.html");
});

// Owner page (same file; UI does pin overlay)
app.get("/owner", (req, res) => sendRepoFile(res, "owner/index.html"));

// -----------------------
// Global gate behavior (lockdown + redirect logged-in users away from gate)
// -----------------------
app.use(async (req, res, next) => {
  try {
    const p = req.path || "/";

    // owner paths handled separately (allowed even during lockdown)
    if (p === "/owner" || p.startsWith("/owner/")) return next();

    // Allow root and activate pages always.
    // Lockdown behavior: only / and /owner/* should be accessible.
    // You also wanted Under Construction to remain accessible (it is /).
    const lockdownEnabled = await getLockdownEnabled();
    if (lockdownEnabled) {
      // Allow only:
      // - /
      // - /owner/*
      // Everything else redirects to /
      if (p !== "/") return res.redirect(302, "/");
      return next();
    }

    // logged in -> redirect away from public gate pages
    if (p === "/" || p === "/activate" || p.startsWith("/activate/")) {
      const u = await verifyUserFromRequest(req);
      if (u) return res.redirect(302, "/divine/");
    }

    return next();
  } catch {
    return next();
  }
});

// -----------------------
// APIs
// -----------------------

// User PIN gate with lockout
app.post("/api/activate", (req, res) => {
  const ip = getReqIp(req);

  if (isLocked(pinLocks.user, ip)) {
    const rem = remainingSeconds(pinLocks.user, ip);
    return res.status(429).json({ ok: false, error: `Too many failed attempts. Try again in ${rem}s.` });
  }

  const pinAttempt = String(req.body?.pinAttempt || "").trim();
  if (!pinAttempt) return res.status(400).json({ ok: false, error: "Missing PIN" });

  if (pinAttempt !== CONFIG.authPin) {
    const v = registerFail(pinLocks.user, ip, CONFIG.userPinMaxFails, CONFIG.userPinLockSeconds);
    if (v.fails >= CONFIG.userPinMaxFails) {
      return res.status(429).json({ ok: false, error: `Wrong PIN. Locked for ${CONFIG.userPinLockSeconds}s.` });
    }
    return res.status(403).json({ ok: false, error: "Wrong PIN" });
  }

  registerSuccess(pinLocks.user, ip);
  return res.json({ ok: true });
});

// Register
app.post("/api/register", async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const email = String(req.body?.email || "").trim();
    const password = String(req.body?.password || "").trim();
    const consent = req.body?.consent === true;

    if (!consent) return res.status(400).json({ ok: false, error: "Consent required" });
    if (!validUsername(username)) return res.status(400).json({ ok: false, error: "Invalid username" });
    if (!email || email.length > 120) return res.status(400).json({ ok: false, error: "Invalid email" });
    if (!password || password.length < 6) return res.status(400).json({ ok: false, error: "Password too short" });

    const exists = await dbGet(`SELECT id FROM users WHERE username=?`, [username]);
    if (exists) return res.status(409).json({ ok: false, error: "Username already in use" });

    let id = randomUserId(16);
    for (let i = 0; i < 6; i++) {
      const taken = await dbGet(`SELECT id FROM users WHERE id=?`, [id]);
      if (!taken) break;
      id = randomUserId(16);
    }

    const hash = await bcrypt.hash(password, 10);
    const createdAt = nowMs();

    await dbRun(
      `INSERT INTO users(id, username, password_hash, email, bio, created_at, token_version, last_ip, banned_until, ban_reason, username_changed_at)
       VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
      [id, username, hash, email, "", createdAt, 0, "", 0, "", 0]
    );

    await issueUserSession(res, id);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const password = String(req.body?.password || "").trim();
    if (!username || !password) return res.status(400).json({ ok: false, error: "Missing fields" });

    const user = await dbGet(`SELECT * FROM users WHERE username=?`, [username]);
    if (!user) return res.status(403).json({ ok: false, error: "Invalid credentials" });

    if (await isUserBanned(user)) return res.status(403).json({ ok: false, error: "This account is banned." });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(403).json({ ok: false, error: "Invalid credentials" });

    await issueUserSession(res, user.id);

    try { await updateLastIp(user.id, getReqIp(req)); } catch {}
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Recover by User ID (resets password and revokes tokens)
app.post("/api/recover", async (req, res) => {
  try {
    const userId = String(req.body?.userId || "").trim();
    const newPassword = String(req.body?.newPassword || "").trim();
    if (!userId || !newPassword) return res.status(400).json({ ok: false, error: "Missing fields" });
    if (newPassword.length < 6) return res.status(400).json({ ok: false, error: "Password too short" });

    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [userId]);
    if (!user) return res.status(404).json({ ok: false, error: "User not found" });

    const hash = await bcrypt.hash(newPassword, 10);
    await dbRun(`UPDATE users SET password_hash=?, token_version=token_version+1 WHERE id=?`, [hash, userId]);
    await revokeUserSessions(userId);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/logout", async (req, res) => {
  try { await revokeCurrentSession(req); } catch {}
  clearUserCookie(res);
  return res.json({ ok: true });
});

// Client access control endpoints for clientID-based flow
app.post("/api/check", async (req, res) => {
  try {
    const clientId = String(req.body?.clientID || "").trim();
    if (!clientId) return res.status(400).json({ ok: false, error: "Missing clientID" });
    if (!validClientId(clientId)) return res.status(400).json({ ok: false, error: "Invalid clientID format" });

    const ip = getReqIp(req);
    const client = await getOrCreateClient(clientId, ip);

    const status = String(client.status || "verified");
    const banned = status === "banned";
    const allowed = status === "verified";

    return res.json({ ok: true, status, banned, allowed });
  } catch (err) {
    console.error("Error in /api/check:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/hello", async (req, res) => {
  try {
    const clientId = String(req.body?.clientID || "").trim();
    if (!clientId) return res.status(400).json({ ok: false, error: "Missing clientID" });
    if (!validClientId(clientId)) return res.status(400).json({ ok: false, error: "Invalid clientID format" });

    const device = req.body?.device || {};
    const deviceInfo = safeStringifyDevice(device);
    const ip = getReqIp(req);

    await getOrCreateClient(clientId, ip, deviceInfo);

    return res.json({ ok: true });
  } catch (err) {
    console.error("Error in /api/hello:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Ban info and appeal page
app.get("/banned", (req, res) => sendRepoFile(res, "banned/index.html"));

app.get("/api/ban-info", async (req, res) => {
  try {
    const user = await verifyUserFromRequest(req);
    if (!user) return res.status(401).json({ ok: false, error: "Unauthorized" });
    
    const isBanned = await isUserBanned(user);
    if (!isBanned) return res.json({ ok: true, banned: false });
    
    const remainingMs = parseInt(user.banned_until || "0", 10) - nowMs();
    
    return res.json({
      ok: true,
      banned: true,
      reason: user.ban_reason || "No reason provided",
      remainingMs: Math.max(0, remainingMs),
      bannedUntil: user.banned_until
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/ban-appeal", async (req, res) => {
  try {
    const user = await verifyUserFromRequest(req);
    if (!user) return res.status(401).json({ ok: false, error: "Unauthorized" });
    
    const appealText = String(req.body?.appealText || "").trim();
    if (!appealText) return res.status(400).json({ ok: false, error: "Missing appeal text" });
    if (appealText.length > 1000) return res.status(400).json({ ok: false, error: "Appeal too long (max 1000 chars)" });
    
    if (!await isUserBanned(user)) {
      return res.status(400).json({ ok: false, error: "You are not banned" });
    }
    
    // Check for recent appeal (prevent spam)
    const oneDayAgo = nowMs() - (24 * 60 * 60 * 1000);
    const recentAppeal = await dbGet(
      `SELECT id FROM reports WHERE reporter_id=? AND target_type='ban_appeal' AND created_at > ?`,
      [user.id, oneDayAgo]
    );
    if (recentAppeal) {
      return res.status(429).json({ ok: false, error: "Please wait 24 hours between appeals" });
    }
    
    // Store appeal in reports table with target_type='ban_appeal'
    await dbRun(
      `INSERT INTO reports(created_at, reporter_id, reporter_username, target_type, target_ref, target_username, body, status) VALUES(?,?,?,?,?,?,?,?)`,
      [nowMs(), user.id, user.username, "ban_appeal", user.id, user.username, appealText, "open"]
    );
    
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// User reporting API
app.post("/api/report", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;
    
    const targetType = String(req.body?.targetType || "").trim();
    const targetRef = String(req.body?.targetRef || "").trim();
    const targetUsername = String(req.body?.targetUsername || "").trim();
    const body = String(req.body?.body || "").trim();
    
    if (!targetType) return res.status(400).json({ ok: false, error: "Missing target type" });
    if (!targetRef) return res.status(400).json({ ok: false, error: "Missing target reference" });
    if (!body) return res.status(400).json({ ok: false, error: "Missing report body" });
    if (body.length > 1000) return res.status(400).json({ ok: false, error: "Report too long (max 1000 chars)" });
    
    // Validate target type
    const validTypes = ["profile", "dm_message"];
    if (!validTypes.includes(targetType)) {
      return res.status(400).json({ ok: false, error: "Invalid target type" });
    }
    
    // Prevent spam: one report per target per user per day
    const oneDayAgo = nowMs() - (24 * 60 * 60 * 1000);
    const existingReport = await dbGet(
      `SELECT id FROM reports WHERE reporter_id=? AND target_type=? AND target_ref=? AND created_at > ?`,
      [user.id, targetType, targetRef, oneDayAgo]
    );
    if (existingReport) {
      return res.status(429).json({ ok: false, error: "You already reported this today" });
    }
    
    // Store report
    await dbRun(
      `INSERT INTO reports(created_at, reporter_id, reporter_username, target_type, target_ref, target_username, body, status) VALUES(?,?,?,?,?,?,?,?)`,
      [nowMs(), user.id, user.username, targetType, targetRef, targetUsername, body, "open"]
    );
    
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// User search API
app.get("/api/users/search", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;
    
    const q = String(req.query?.q || "").trim();
    if (!q) return res.json({ ok: true, users: [] });
    if (q.length < 2) return res.status(400).json({ ok: false, error: "Query too short (min 2 chars)" });
    
    const limit = Math.min(20, Math.max(1, parseInt(String(req.query?.limit || "10"), 10)));
    
    // Escape SQL wildcards and backslashes to prevent injection
    const escapedQ = q.replace(/\\/g, '\\\\').replace(/[%_]/g, '\\$&');
    
    // Search by username only (IDs should remain private)
    const rows = await dbAll(
      `SELECT username, bio FROM users 
       WHERE username LIKE ? ESCAPE '\\'
       AND banned_until < ?
       ORDER BY username 
       LIMIT ?`,
      [`%${escapedQ}%`, nowMs(), limit]
    );
    
    return res.json({
      ok: true,
      users: rows.map(r => ({
        username: r.username,
        bio: r.bio || ""
      }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Profile APIs
app.get("/api/me", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    return res.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        bio: user.bio || "",
      },
      usernameChange: {
        cooldownDays: CONFIG.usernameCooldownDays,
        remainingMs: msUntilUsernameChangeAllowed(user),
      }
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/me", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const bio = String(req.body?.bio || "").trim();
    if (bio.length > 240) return res.status(400).json({ ok: false, error: "Bio too long (max 240)" });

    await dbRun(`UPDATE users SET bio=? WHERE id=?`, [bio, user.id]);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Get public user profile by username
app.get("/api/user/:username", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;
    
    const username = String(req.params?.username || "").trim();
    if (!username) return res.status(400).json({ ok: false, error: "Missing username" });
    
    const targetUser = await dbGet(
      `SELECT id, username, bio FROM users WHERE username=? AND banned_until < ?`,
      [username, nowMs()]
    );
    
    if (!targetUser) return res.status(404).json({ ok: false, error: "User not found" });
    
    // Never expose user ID in public profile
    return res.json({
      ok: true,
      user: {
        username: targetUser.username,
        bio: targetUser.bio || ""
      }
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/me/username", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const remMs = msUntilUsernameChangeAllowed(user);
    if (remMs > 0) {
      const remHours = Math.ceil(remMs / (60 * 60 * 1000));
      return res.status(429).json({ ok: false, error: `Username can be changed again in ~${remHours}h.` });
    }

    const newUsername = normalizeUsername(req.body?.username);
    if (!validUsername(newUsername)) return res.status(400).json({ ok: false, error: "Invalid username" });

    const exists = await dbGet(`SELECT id FROM users WHERE username=?`, [newUsername]);
    if (exists && String(exists.id) !== String(user.id)) {
      return res.status(409).json({ ok: false, error: "Username already in use" });
    }

    await dbRun(`UPDATE users SET username=?, username_changed_at=? WHERE id=?`, [newUsername, nowMs(), user.id]);

    return res.json({ ok: true, username: newUsername });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Owner PIN API with lockout; issues short-lived cookie
app.post("/owner/pin", (req, res) => {
  const ip = getReqIp(req);

  if (isLocked(pinLocks.owner, ip)) {
    const rem = remainingSeconds(pinLocks.owner, ip);
    return res.status(429).json({ ok: false, error: `Too many wrong attempts. Try again in ${rem}s.` });
  }

  const pinAttempt = String(req.body?.pinAttempt || "").trim();
  if (!pinAttempt) return res.status(400).json({ ok: false, error: "Missing PIN" });

  if (pinAttempt !== CONFIG.ownerPin) {
    const v = registerFail(pinLocks.owner, ip, CONFIG.ownerPinMaxFails, CONFIG.ownerPinLockSeconds);
    if (v.fails >= CONFIG.ownerPinMaxFails) {
      return res.status(429).json({ ok: false, error: `Wrong PIN. Locked for ${CONFIG.ownerPinLockSeconds}s.` });
    }
    return res.status(403).json({ ok: false, error: "Wrong PIN" });
  }

  registerSuccess(pinLocks.owner, ip);
  issueOwnerOnceCookie(res);
  return res.json({ ok: true });
});

// -----------------------
// Owner APIs (requireOwner)
// -----------------------
app.get("/api/owner/state", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const lockdownEnabled = await getLockdownEnabled();
    
    // Active users = users seen within last 10 minutes
    const tenMinutesAgo = nowMs() - (10 * 60 * 1000);
    const activeUsers = await dbGet(`SELECT COUNT(*) AS c FROM users WHERE last_seen_at > ?`, [tenMinutesAgo]);
    const bannedUsers = await dbGet(`SELECT COUNT(*) AS c FROM users WHERE banned_until>?`, [nowMs()]);

    return res.json({
      ok: true,
      lockdownEnabled,
      activeUsers: Number(activeUsers?.c || 0),
      bannedUsers: Number(bannedUsers?.c || 0),
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/lockdown", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const cur = await getLockdownEnabled();
    const next = !cur;
    await setLockdownEnabled(next);
    return res.json({ ok: true, enabled: next });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/owner/users", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const rows = await dbAll(
      `SELECT id, username, last_ip, banned_until, ban_reason, created_at
       FROM users
       ORDER BY created_at DESC
       LIMIT 500`
    );

    return res.json({
      ok: true,
      users: rows.map(r => ({
        id: r.id,
        username: r.username,
        last_ip: r.last_ip || "",
        banned_until: Number(r.banned_until || 0),
        ban_reason: r.ban_reason || "",
        created_at: Number(r.created_at || 0),
        banned: (Number(r.banned_until || 0) > nowMs()),
      }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/users/revoke", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const username = normalizeUsername(req.body?.username);
    if (!username) return res.status(400).json({ ok: false, error: "Missing username" });

    const u = await dbGet(`SELECT id FROM users WHERE username=?`, [username]);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    await dbRun(`UPDATE users SET token_version=token_version+1 WHERE id=?`, [u.id]);
    await revokeUserSessions(u.id);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/users/redirect", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const username = normalizeUsername(req.body?.username);
    const url = String(req.body?.url || "").trim();
    if (!username || !url) return res.status(400).json({ ok: false, error: "Missing fields" });

    const u = await dbGet(`SELECT id FROM users WHERE username=?`, [username]);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    await dbRun(
      `INSERT INTO user_redirects(user_id, url, created_at) VALUES(?,?,?)
       ON CONFLICT(user_id) DO UPDATE SET url=excluded.url, created_at=excluded.created_at`,
      [u.id, clampStr(url, 900), nowMs()]
    );

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/owner/activity", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const limit = Math.min(500, Math.max(1, parseInt(String(req.query?.limit || "80"), 10) || 80));
    const userQ = String(req.query?.user || "").trim();

    let rows;
    if (userQ) {
      rows = await dbAll(
        `SELECT created_at, username, user_id, path, ip
         FROM activity
         WHERE username=?
         ORDER BY created_at DESC
         LIMIT ?`,
        [userQ, limit]
      );
    } else {
      rows = await dbAll(
        `SELECT created_at, username, user_id, path, ip
         FROM activity
         ORDER BY created_at DESC
         LIMIT ?`,
        [limit]
      );
    }

    return res.json({
      ok: true,
      items: rows.map(r => ({
        time: fmtTimeSec(r.created_at),
        username: r.username,
        userId: r.user_id,
        page: r.path,
        extra: r.ip ? `ip:${r.ip}` : ""
      }))
      });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/broadcast", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const scope = String(req.body?.scope || "global").trim().toLowerCase();
    const message = String(req.body?.message || "").trim();
    const targetUsername = normalizeUsername(req.body?.username || "");

    if (!message) return res.status(400).json({ ok: false, error: "Missing message" });
    if (message.length > 800) return res.status(400).json({ ok: false, error: "Message too long" });

    if (scope !== "global" && scope !== "user") {
      return res.status(400).json({ ok: false, error: "Invalid scope" });
    }

    if (scope === "user") {
      if (!targetUsername) return res.status(400).json({ ok: false, error: "Missing target username" });
      const u = await dbGet(`SELECT id FROM users WHERE username=?`, [targetUsername]);
      if (!u) return res.status(404).json({ ok: false, error: "User not found" });
    }

    await dbRun(
      `INSERT INTO broadcasts(created_at, scope, target_username, message, active)
       VALUES(?,?,?,?,1)`,
      [nowMs(), scope, scope === "user" ? targetUsername : "", message]
    );

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/owner/bans", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const rows = await dbAll(
      `SELECT id, username, last_ip, banned_until, ban_reason
       FROM users
       WHERE banned_until > ?
       ORDER BY banned_until DESC
       LIMIT 500`,
      [nowMs()]
    );

    return res.json({
      ok: true,
      items: rows.map(r => ({
        username: r.username,
        userId: r.id,
        ends: r.banned_until ? fmtTimeSec(r.banned_until) : "—",
        reason: r.ban_reason || "",
        lastIp: r.last_ip || ""
      }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
  });

app.post("/api/owner/ban", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const username = normalizeUsername(req.body?.username);
    const duration = String(req.body?.duration || "").trim();
    const reason = String(req.body?.reason || "").trim();

    if (!username || !duration) return res.status(400).json({ ok: false, error: "Missing fields" });

    const u = await dbGet(`SELECT id FROM users WHERE username=?`, [username]);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    const ms = parseDurationToMs(duration);
    if (ms === null) return res.status(400).json({ ok: false, error: "Invalid duration (use 10m/1h/3d/permanent)" });

    const until = (ms === Infinity) ? (nowMs() + (1000 * 60 * 60 * 24 * 365 * 100)) : (nowMs() + ms);
    await dbRun(`UPDATE users SET banned_until=?, ban_reason=? WHERE id=?`, [until, clampStr(reason, 600), u.id]);

    // revoke tokens immediately
    await dbRun(`UPDATE users SET token_version=token_version+1 WHERE id=?`, [u.id]);
    await revokeUserSessions(u.id);

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/unban", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const username = normalizeUsername(req.body?.username);
    if (!username) return res.status(400).json({ ok: false, error: "Missing username" });

    const u = await dbGet(`SELECT id FROM users WHERE username=?`, [username]);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    await dbRun(`UPDATE users SET banned_until=0, ban_reason='' WHERE id=?`, [u.id]);
    // revoke tokens just in case
    await dbRun(`UPDATE users SET token_version=token_version+1 WHERE id=?`, [u.id]);
    await revokeUserSessions(u.id);

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/owner/reports", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const rows = await dbAll(
      `SELECT id, created_at, reporter_username, target_type, target_username, target_ref, body
       FROM reports
       WHERE status='open'
       ORDER BY created_at DESC
       LIMIT 300`
    );

    return res.json({
      ok: true,
      items: rows.map(r => ({
        id: r.id,
        title: `${fmtTimeSec(r.created_at)} • ${r.target_type}`,
        reporter: r.reporter_username,
        targetUsername: r.target_username,
        target: r.target_ref,
        body: r.body
      }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/reports/dismiss", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const id = parseInt(String(req.body?.id || ""), 10);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: "Missing id" });

    await dbRun(`UPDATE reports SET status='dismissed' WHERE id=?`, [id]);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// -------- Owner DM ban management --------
app.get("/api/owner/dm-bans", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const rows = await dbAll(
      `SELECT db.user_id, u.username, db.banned_until, db.ban_reason, db.created_at, u.last_ip
       FROM dm_bans db
       JOIN users u ON u.id = db.user_id
       WHERE db.banned_until > ?
       ORDER BY db.banned_until DESC
       LIMIT 500`,
      [nowMs()]
    );

    return res.json({
      ok: true,
      items: rows.map(r => ({
        username: r.username,
        userId: r.user_id,
        ends: r.banned_until ? fmtTimeSec(r.banned_until) : "—",
        reason: r.ban_reason || "",
        lastIp: r.last_ip || ""
      }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/dm-ban", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const username = normalizeUsername(req.body?.username);
    const duration = String(req.body?.duration || "").trim();
    const reason = String(req.body?.reason || "").trim();

    if (!username || !duration) return res.status(400).json({ ok: false, error: "Missing fields" });

    const u = await dbGet(`SELECT id FROM users WHERE username=?`, [username]);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    const ms = parseDurationToMs(duration);
    if (ms === null) return res.status(400).json({ ok: false, error: "Invalid duration (use 10m/1h/3d/permanent)" });

    const until = (ms === Infinity) ? (nowMs() + (1000 * 60 * 60 * 24 * 365 * 100)) : (nowMs() + ms);
    await dbRun(
      `INSERT INTO dm_bans(user_id, banned_until, ban_reason, created_at) VALUES(?,?,?,?)
       ON CONFLICT(user_id) DO UPDATE SET banned_until=excluded.banned_until, ban_reason=excluded.ban_reason`,
      [u.id, until, clampStr(reason, 600), nowMs()]
    );

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/dm-unban", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const username = normalizeUsername(req.body?.username);
    if (!username) return res.status(400).json({ ok: false, error: "Missing username" });

    const u = await dbGet(`SELECT id FROM users WHERE username=?`, [username]);
    if (!u) return res.status(404).json({ ok: false, error: "User not found" });

    await dbRun(`DELETE FROM dm_bans WHERE user_id=?`, [u.id]);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/owner/dm-appeals", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const rows = await dbAll(
      `SELECT id, user_id, username, appeal_text, created_at
       FROM dm_appeals
       WHERE status='open'
       ORDER BY created_at DESC
       LIMIT 300`
    );

    return res.json({
      ok: true,
      items: rows.map(r => ({
        id: r.id,
        title: `${fmtTimeSec(r.created_at)} • DM Ban Appeal`,
        username: r.username,
        userId: r.user_id,
        body: r.appeal_text
      }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/owner/dm-appeals/dismiss", async (req, res) => {
  try {
    if (!requireOwner(req, res)) return;

    const id = parseInt(String(req.body?.id || ""), 10);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: "Missing id" });

    await dbRun(`UPDATE dm_appeals SET status='dismissed' WHERE id=?`, [id]);
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// -------- DM APIs (user-level) --------
app.get("/api/dm/search-users", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const q = String(req.query?.q || "").trim();
    if (!q || q.length < 2) return res.json({ ok: true, users: [] });

    const rows = await dbAll(
      `SELECT id, username FROM users 
       WHERE username LIKE ? AND id != ? 
       ORDER BY username 
       LIMIT 20`,
      [`%${q}%`, user.id]
    );

    return res.json({
      ok: true,
      users: rows.map(r => ({ id: r.id, username: r.username }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/dm/request", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    if (await isUserDmBanned(user.id)) {
      return res.status(403).json({ ok: false, error: "DM banned" });
    }

    const toUserId = String(req.body?.toUserId || "").trim();
    const inviteMessage = String(req.body?.inviteMessage || "").trim();

    if (!toUserId) return res.status(400).json({ ok: false, error: "Missing toUserId" });
    if (toUserId === user.id) return res.status(400).json({ ok: false, error: "Cannot DM yourself" });

    const targetUser = await dbGet(`SELECT id, username FROM users WHERE id=?`, [toUserId]);
    if (!targetUser) return res.status(404).json({ ok: false, error: "User not found" });

    // Check if target is DM banned
    if (await isUserDmBanned(toUserId)) {
      return res.status(403).json({ ok: false, error: "Target user is DM banned" });
    }

    // Check if thread already exists
    const threadId = generateThreadId(user.id, toUserId);
    const existingThread = await dbGet(`SELECT id FROM dm_threads WHERE id=?`, [threadId]);
    if (existingThread) {
      return res.status(409).json({ ok: false, error: "Thread already exists" });
    }

    // Check for recent declined request (3 day cooldown)
    const threeDaysAgo = nowMs() - (3 * 24 * 60 * 60 * 1000);
    const recentDecline = await dbGet(
      `SELECT id FROM dm_requests 
       WHERE from_user_id=? AND to_user_id=? AND status='declined' AND responded_at > ?`,
      [user.id, toUserId, threeDaysAgo]
    );
    if (recentDecline) {
      return res.status(429).json({ ok: false, error: "Please wait 3 days after a decline" });
    }

    // Check for existing pending request
    const pending = await dbGet(
      `SELECT id FROM dm_requests WHERE from_user_id=? AND to_user_id=? AND status='pending'`,
      [user.id, toUserId]
    );
    if (pending) {
      return res.status(409).json({ ok: false, error: "Request already pending" });
    }

    // Create request
    const result = await dbRun(
      `INSERT INTO dm_requests(from_user_id, to_user_id, invite_message, status, created_at)
       VALUES(?,?,?,?,?)`,
      [user.id, toUserId, clampStr(inviteMessage, 500), 'pending', nowMs()]
    );

    // Notify via WebSocket
    notifyUser(toUserId, { type: 'new_request', requestId: result.lastID, from: { id: user.id, username: user.username } });

    return res.json({ ok: true, requestId: result.lastID });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/dm/pending-requests", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    if (await isUserDmBanned(user.id)) {
      return res.json({ ok: true, count: 0, requests: [] });
    }

    const rows = await dbAll(
      `SELECT r.id, r.from_user_id, u.username, r.invite_message, r.created_at
       FROM dm_requests r
       JOIN users u ON u.id = r.from_user_id
       WHERE r.to_user_id=? AND r.status='pending'
       ORDER BY r.created_at DESC`,
      [user.id]
    );

    return res.json({
      ok: true,
      count: rows.length,
      requests: rows.map(r => ({
        id: r.id,
        from: { id: r.from_user_id, username: r.username },
        inviteMessage: r.invite_message || "",
        createdAt: r.created_at
      }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/dm/request/:id/accept", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    if (await isUserDmBanned(user.id)) {
      return res.status(403).json({ ok: false, error: "DM banned" });
    }

    const requestId = parseInt(req.params.id, 10);
    if (!Number.isFinite(requestId)) return res.status(400).json({ ok: false, error: "Invalid request ID" });

    const request = await dbGet(`SELECT * FROM dm_requests WHERE id=? AND to_user_id=?`, [requestId, user.id]);
    if (!request) return res.status(404).json({ ok: false, error: "Request not found" });
    if (request.status !== 'pending') return res.status(409).json({ ok: false, error: "Request already responded to" });

    // Check if sender is DM banned
    if (await isUserDmBanned(request.from_user_id)) {
      await dbRun(`UPDATE dm_requests SET status='declined', responded_at=? WHERE id=?`, [nowMs(), requestId]);
      return res.status(403).json({ ok: false, error: "Sender is DM banned" });
    }

    // Create thread
    const threadId = generateThreadId(user.id, request.from_user_id);
    await dbRun(
      `INSERT INTO dm_threads(id, user_a, user_b, created_at, last_message_at) VALUES(?,?,?,?,?)`,
      [threadId, user.id, request.from_user_id, nowMs(), nowMs()]
    );

    // Update request status
    await dbRun(`UPDATE dm_requests SET status='accepted', responded_at=? WHERE id=?`, [nowMs(), requestId]);

    // Notify sender
    notifyUser(request.from_user_id, { type: 'request_accepted', threadId, from: { id: user.id, username: user.username } });

    return res.json({ ok: true, threadId });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/dm/request/:id/decline", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const requestId = parseInt(req.params.id, 10);
    if (!Number.isFinite(requestId)) return res.status(400).json({ ok: false, error: "Invalid request ID" });

    const request = await dbGet(`SELECT * FROM dm_requests WHERE id=? AND to_user_id=?`, [requestId, user.id]);
    if (!request) return res.status(404).json({ ok: false, error: "Request not found" });
    if (request.status !== 'pending') return res.status(409).json({ ok: false, error: "Request already responded to" });

    // Update request status
    await dbRun(`UPDATE dm_requests SET status='declined', responded_at=? WHERE id=?`, [nowMs(), requestId]);

    // Notify sender
    notifyUser(request.from_user_id, { type: 'request_declined', from: { id: user.id, username: user.username } });

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/dm/threads", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    if (await isUserDmBanned(user.id)) {
      return res.json({ ok: true, threads: [] });
    }

    const rows = await dbAll(
      `SELECT t.id, t.user_a, t.user_b, t.last_message_at, 
              ua.username as username_a, ub.username as username_b,
              (SELECT COUNT(*) FROM dm_messages m 
               LEFT JOIN dm_reads r ON r.thread_id = t.id AND r.user_id = ?
               WHERE m.thread_id = t.id AND m.from_user_id != ? 
               AND (r.last_read_message_id IS NULL OR m.id > r.last_read_message_id)) as unread_count
       FROM dm_threads t
       JOIN users ua ON ua.id = t.user_a
       JOIN users ub ON ub.id = t.user_b
       WHERE t.user_a=? OR t.user_b=?
       ORDER BY t.last_message_at DESC`,
      [user.id, user.id, user.id, user.id]
    );

    return res.json({
      ok: true,
      threads: rows.map(r => {
        const otherUserId = r.user_a === user.id ? r.user_b : r.user_a;
        const otherUsername = r.user_a === user.id ? r.username_b : r.username_a;
        return {
          id: r.id,
          otherUser: { id: otherUserId, username: otherUsername },
          lastMessageAt: r.last_message_at,
          unreadCount: Number(r.unread_count || 0)
        };
      })
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/dm/threads/:threadId/messages", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    if (await isUserDmBanned(user.id)) {
      return res.status(403).json({ ok: false, error: "DM banned" });
    }

    const threadId = String(req.params.threadId || "").trim();
    if (!threadId) return res.status(400).json({ ok: false, error: "Missing thread ID" });

    // Verify user is part of thread
    const thread = await dbGet(`SELECT * FROM dm_threads WHERE id=?`, [threadId]);
    if (!thread) return res.status(404).json({ ok: false, error: "Thread not found" });
    if (thread.user_a !== user.id && thread.user_b !== user.id) {
      return res.status(403).json({ ok: false, error: "Not authorized" });
    }

    const limit = Math.min(100, Math.max(1, parseInt(String(req.query?.limit || "50"), 10)));
    const rows = await dbAll(
      `SELECT m.id, m.from_user_id, u.username, m.message, m.created_at
       FROM dm_messages m
       JOIN users u ON u.id = m.from_user_id
       WHERE m.thread_id=?
       ORDER BY m.created_at DESC
       LIMIT ?`,
      [threadId, limit]
    );

    return res.json({
      ok: true,
      messages: rows.reverse().map(r => ({
        id: r.id,
        from: { id: r.from_user_id, username: r.username },
        message: r.message,
        createdAt: r.created_at
      }))
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/dm/threads/:threadId/messages", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    if (await isUserDmBanned(user.id)) {
      return res.status(403).json({ ok: false, error: "DM banned" });
    }

    const threadId = String(req.params.threadId || "").trim();
    const message = String(req.body?.message || "").trim();

    if (!threadId) return res.status(400).json({ ok: false, error: "Missing thread ID" });
    if (!message) return res.status(400).json({ ok: false, error: "Missing message" });
    if (message.length > 2000) return res.status(400).json({ ok: false, error: "Message too long" });

    // Verify user is part of thread
    const thread = await dbGet(`SELECT * FROM dm_threads WHERE id=?`, [threadId]);
    if (!thread) return res.status(404).json({ ok: false, error: "Thread not found" });
    if (thread.user_a !== user.id && thread.user_b !== user.id) {
      return res.status(403).json({ ok: false, error: "Not authorized" });
    }

    const otherUserId = thread.user_a === user.id ? thread.user_b : thread.user_a;

    // Check if other user is DM banned
    if (await isUserDmBanned(otherUserId)) {
      return res.status(403).json({ ok: false, error: "Recipient is DM banned" });
    }

    // Insert message
    const result = await dbRun(
      `INSERT INTO dm_messages(thread_id, from_user_id, message, created_at) VALUES(?,?,?,?)`,
      [threadId, user.id, message, nowMs()]
    );

    // Update thread last_message_at
    await dbRun(`UPDATE dm_threads SET last_message_at=? WHERE id=?`, [nowMs(), threadId]);

    // Notify other user
    notifyUser(otherUserId, { 
      type: 'new_message', 
      threadId, 
      messageId: result.lastID,
      from: { id: user.id, username: user.username },
      message 
    });

    return res.json({ ok: true, messageId: result.lastID });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/dm/threads/:threadId/read", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const threadId = String(req.params.threadId || "").trim();
    if (!threadId) return res.status(400).json({ ok: false, error: "Missing thread ID" });

    // Verify user is part of thread
    const thread = await dbGet(`SELECT * FROM dm_threads WHERE id=?`, [threadId]);
    if (!thread) return res.status(404).json({ ok: false, error: "Thread not found" });
    if (thread.user_a !== user.id && thread.user_b !== user.id) {
      return res.status(403).json({ ok: false, error: "Not authorized" });
    }

    // Get latest message ID in this thread
    const lastMsg = await dbGet(`SELECT id FROM dm_messages WHERE thread_id=? ORDER BY created_at DESC LIMIT 1`, [threadId]);
    if (!lastMsg) return res.json({ ok: true }); // No messages to mark read

    // Update or insert read marker
    await dbRun(
      `INSERT INTO dm_reads(thread_id, user_id, last_read_message_id, last_read_at) VALUES(?,?,?,?)
       ON CONFLICT(thread_id, user_id) DO UPDATE SET last_read_message_id=excluded.last_read_message_id, last_read_at=excluded.last_read_at`,
      [threadId, user.id, lastMsg.id, nowMs()]
    );

    // Notify self to update unread count
    notifyUser(user.id, { type: 'unread_update' });

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/dm/unread-count", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    if (await isUserDmBanned(user.id)) {
      return res.json({ ok: true, count: 0 });
    }

    const result = await dbGet(
      `SELECT COUNT(DISTINCT m.thread_id) as unread_threads,
              COUNT(*) as unread_messages
       FROM dm_messages m
       JOIN dm_threads t ON t.id = m.thread_id
       LEFT JOIN dm_reads r ON r.thread_id = m.thread_id AND r.user_id = ?
       WHERE (t.user_a=? OR t.user_b=?) 
       AND m.from_user_id != ?
       AND (r.last_read_message_id IS NULL OR m.id > r.last_read_message_id)`,
      [user.id, user.id, user.id, user.id]
    );

    return res.json({ 
      ok: true, 
      count: Number(result?.unread_messages || 0),
      unreadThreads: Number(result?.unread_threads || 0)
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/dm/appeal", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const appealText = String(req.body?.appealText || "").trim();
    if (!appealText) return res.status(400).json({ ok: false, error: "Missing appeal text" });
    if (appealText.length > 1000) return res.status(400).json({ ok: false, error: "Appeal too long (max 1000 chars)" });

    // Check if user is actually DM banned
    if (!await isUserDmBanned(user.id)) {
      return res.status(400).json({ ok: false, error: "You are not DM banned" });
    }

    // Check for recent appeal (prevent spam)
    const oneDayAgo = nowMs() - (24 * 60 * 60 * 1000);
    const recentAppeal = await dbGet(
      `SELECT id FROM dm_appeals WHERE user_id=? AND created_at > ?`,
      [user.id, oneDayAgo]
    );
    if (recentAppeal) {
      return res.status(429).json({ ok: false, error: "Please wait 24 hours between appeals" });
    }

    // Create appeal
    await dbRun(
      `INSERT INTO dm_appeals(user_id, username, appeal_text, created_at, status) VALUES(?,?,?,?,?)`,
      [user.id, user.username, appealText, nowMs(), 'open']
    );

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/dm/ban-info", async (req, res) => {
  try {
    const user = await requireUser(req, res);
    if (!user) return;

    const ban = await getDmBan(user.id);
    if (!ban) {
      return res.json({ ok: true, ban: null });
    }

    return res.json({
      ok: true,
      ban: {
        reason: ban.ban_reason || "",
        bannedUntil: Number(ban.banned_until || 0),
        createdAt: Number(ban.created_at || 0)
      }
    });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// -----------------------
// Auth protect /divine/* (including /divine/profile/*) + activity logging + redirect-on-next-load
// -----------------------
app.use("/divine", async (req, res, next) => {
  try {
    const user = await verifyUserFromRequest(req);
    if (!user) return res.redirect(302, "/");

    try { await updateLastIp(user.id, getReqIp(req)); } catch {}
    try { await updateLastSeen(user.id); } catch {}

    try {
      if (await isUserBanned(user)) {
        clearUserCookie(res);
        return res.redirect(302, "/banned");
      }
    } catch (e) {
      console.error("Ban check error:", e);
    }

    // One-time redirect tool
    try {
      const redir = await getAndConsumeRedirect(user.id);
      if (redir) return res.redirect(302, redir);
    } catch {}

    // Activity log
    try {
      await logActivity(user, req.originalUrl || req.path || "", getReqIp(req));
    } catch {}

    req.user = user;
    return next();
  } catch {
    return res.redirect(302, "/");
  }
});

// -----------------------
// DM ban enforcement for /divine/dm/*
// -----------------------
app.use("/divine/dm", async (req, res, next) => {
  try {
    const user = req.user; // Already set by /divine middleware
    if (!user) return res.redirect(302, "/");

    // Check DM ban
    const dmBan = await getDmBan(user.id);
    if (dmBan) {
      const until = parseInt(dmBan.banned_until || "0", 10);
      if (until && nowMs() < until) {
        // Allow access to ban.html itself
        if (req.path === "/ban.html" || req.path === "/ban.js") {
          return next();
        }
        // Redirect to ban page
        return res.redirect(302, "/divine/dm/ban.html");
      }
    }

    return next();
  } catch {
    return res.redirect(302, "/");
  }
});

// -----------------------
// Protected /divine routes (after authentication middleware)
// -----------------------
// Convenience redirect
app.get("/divine", (req, res) => res.redirect(302, "/divine/"));

// Main divine page
app.get("/divine/", (req, res) => sendRepoFile(res, "divine/index.html"));

// Profile page redirects
app.get("/divine/profile", (req, res) => res.redirect(302, "/divine/profile/"));
app.get("/divine/profile/", (req, res) => sendRepoFile(res, "divine/profile/index.html"));

// Public user profile view
app.get("/divine/u/:username", (req, res) => sendRepoFile(res, "divine/user/index.html"));

// -----------------------
// Static serving
// -----------------------
app.use(express.static(REPO_ROOT, {
  extensions: ["html"],
  index: false,
  maxAge: CONFIG.nodeEnv === "production" ? "1h" : 0,
}));

// Owner route must validate cookie for assets + page view.
// IMPORTANT: This must run BEFORE static serving for /owner assets if you want strictness.
// Your UI will call /owner/pin and then load resources immediately.
app.use("/owner", (req, res, next) => {
  // allow posting PIN without having cookie
  if (req.method === "POST" && req.path === "/pin") return next();

  // If the request is for /owner itself, allow it so the page can show the PIN overlay.
  // But any /owner/* asset fetch requires the cookie.
  if (req.path === "/" || req.path === "") return next();

  const ok = consumeOwnerOnceCookie(req, res);
  if (!ok) return res.status(401).send("Owner PIN required.");
  return next();
});

// Fallback
app.use((req, res) => {
  const f = path.join(REPO_ROOT, "404.html");
  if (fs.existsSync(f)) return res.status(404).sendFile(f);
  return res.status(404).redirect(302, "/");
});

// -----------------------
// WebSocket Server
// -----------------------
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/ws" });

wss.on("connection", async (ws, req) => {
  let userId = null;
  
  try {
    // Parse cookies from upgrade request
    const cookies = {};
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
      cookieHeader.split(";").forEach(cookie => {
        const parts = cookie.split("=");
        const key = parts[0].trim();
        const value = parts.slice(1).join("=").trim();
        cookies[key] = value;
      });
    }

    // Verify JWT from cookie
    const token = cookies[COOKIE_USER];
    if (!token) {
      ws.close(4001, "Unauthorized");
      return;
    }

    const userIdFromJWT = verifyJWT(token);
    if (!userIdFromJWT) {
      ws.close(4001, "Unauthorized");
      return;
    }

    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [String(userIdFromJWT)]);
    if (!user) {
      ws.close(4001, "Unauthorized");
      return;
    }

    // Check site-wide ban
    if (await isUserBanned(user)) {
      ws.close(4003, "Banned");
      return;
    }

    userId = user.id;
    registerWsClient(userId, ws);

    // Send initial state
    ws.send(JSON.stringify({ type: "connected", userId }));

  } catch (e) {
    console.error("WS auth error:", e);
    ws.close(4000, "Error");
    return;
  }

  ws.on("close", () => {
    if (userId) {
      unregisterWsClient(userId, ws);
    }
  });

  ws.on("error", (err) => {
    console.error("WS error:", err);
  });
});

// Start
initDb()
  .then(() => {
    server.listen(CONFIG.port, () => {
      console.log(`Divine server listening on :${CONFIG.port}`);
      console.log(`WebSocket server ready at ws://localhost:${CONFIG.port}/ws`);
      console.log(`DB: ${CONFIG.dbPath}`);
    });
  })
  .catch((e) => {
    console.error("Failed to init DB:", e);
    process.exit(1);
  });
