const path = require("path");
const fs = require("fs");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

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
  jwtSecret: requireEnv("JWT_SECRET"),
  authPin: requireEnv("AUTH_PIN"),
  ownerPin: requireEnv("OWNER_PIN"),
  jwtExpiresDays: parseInt(envStr("JWT_EXPIRES_DAYS", "7"), 10) || 7,
  dbPath: envStr("DB_PATH", "/app/data/divine.sqlite"),

  // Env fallback only. Real lockdown state is stored in DB.
  lockdownEnabledEnv: envStr("LOCKDOWN_ENABLED", "0") === "1",

  userPinMaxFails: 3,
  userPinLockSeconds: 300,

  ownerPinMaxFails: 3,
  ownerPinLockSeconds: 24 * 60 * 60,

  usernameCooldownDays: 14,
};

const COOKIE_USER = "dv_auth";
const COOKIE_OWNER_ONCE = "dv_owner_once";

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

function signUserJwt(payload) {
  const exp = `${CONFIG.jwtExpiresDays}d`;
  return jwt.sign(payload, CONFIG.jwtSecret, { expiresIn: exp });
}

function verifyUserJwt(token) {
  try {
    return jwt.verify(token, CONFIG.jwtSecret);
  } catch {
    return null;
  }
}

function setUserCookie(res, token) {
  const isProd = CONFIG.nodeEnv === "production";
  res.cookie(COOKIE_USER, token, {
    httpOnly: true,
    sameSite: "Strict",
    secure: isProd,
    path: "/",
    maxAge: CONFIG.jwtExpiresDays * 24 * 60 * 60 * 1000,
  });
}

function clearUserCookie(res) {
  const isProd = CONFIG.nodeEnv === "production";
  res.cookie(COOKIE_USER, "", {
    httpOnly: true,
    sameSite: "Strict",
    secure: isProd,
    path: "/",
    maxAge: 0,
  });
}

function issueOwnerOnceCookie(res) {
  const isProd = CONFIG.nodeEnv === "production";
  const token = jwt.sign({ ok: true, t: Date.now() }, CONFIG.jwtSecret, { expiresIn: "5m" });
  res.cookie(COOKIE_OWNER_ONCE, token, {
    httpOnly: true,
    sameSite: "Strict",
    secure: isProd,
    path: "/owner",
    maxAge: 5 * 60 * 1000,
  });
}

function consumeOwnerOnceCookie(req, res) {
  const tok = req.cookies[COOKIE_OWNER_ONCE];
  if (!tok) return false;
  try {
    jwt.verify(tok, CONFIG.jwtSecret);
  } catch {
    return false;
  }

  const isProd = CONFIG.nodeEnv === "production";
  res.cookie(COOKIE_OWNER_ONCE, "", {
    httpOnly: true,
    sameSite: "Strict",
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

  await dbRun(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);`);

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

async function updateLastIp(userId, ip) {
  await dbRun(`UPDATE users SET last_ip=? WHERE id=?`, [String(ip || ""), String(userId)]);
}

async function verifyUserFromRequest(req) {
  const tok = req.cookies[COOKIE_USER];
  if (!tok) return null;
  const payload = verifyUserJwt(tok);
  if (!payload || !payload.uid) return null;

  const user = await dbGet(`SELECT * FROM users WHERE id=?`, [String(payload.uid)]);
  if (!user) return null;

  const tvJwt = parseInt(payload.tv || "0", 10);
  const tvDb = parseInt(user.token_version || "0", 10);
  if (tvJwt !== tvDb) return null;

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

// -------- Owner auth helper for APIs (must be called after /owner cookie middleware in chain) --------
function requireOwner(req, res) {
  // Owner cookie is consumed in /owner middleware for page loads.
  // For API calls, we require a fresh pin cookie too, but because you wanted "every reload",
  // we keep owner pin in a short 5m cookie, and allow API calls during that window.
  // The UI calls /owner/pin and then proceeds immediately.
  const tok = req.cookies[COOKIE_OWNER_ONCE];
  if (!tok) {
    res.status(401).json({ ok: false, error: "Owner auth required" });
    return false;
  }
  try {
    jwt.verify(tok, CONFIG.jwtSecret);
  } catch {
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
// App
// -----------------------
const app = express();
app.disable("x-powered-by");
// IMPORTANT: for most hosts you SHOULD set trust proxy true if behind a proxy
// but leaving your original behavior unchanged.
app.set("trust proxy", false);

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
    const enabled = await getLockdownEnabled();
    if (enabled) {
      const f = path.join(REPO_ROOT, "index.lockdown.html");
      if (fs.existsSync(f)) return res.sendFile(f);
    }
  } catch {}
  return sendRepoFile(res, "index.html");
});

// Activation pages
app.get("/activate", (req, res) => sendRepoFile(res, "activate/index.html"));
app.get("/activate/register", (req, res) => sendRepoFile(res, "activate/register/index.html"));

// Owner page (same file; UI does pin overlay)
app.get("/owner", (req, res) => sendRepoFile(res, "owner/index.html"));

// Profile page (inside /divine)
app.get("/divine/profile", (req, res) => res.redirect(302, "/divine/profile/"));
app.get("/divine/profile/", (req, res) => sendRepoFile(res, "divine/profile/index.html"));

// Convenience
app.get("/divine", (req, res) => res.redirect(302, "/divine/"));

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

    const token = signUserJwt({ uid: id, tv: 0 });
    setUserCookie(res, token);
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

    const tv = parseInt(user.token_version || "0", 10);
    const token = signUserJwt({ uid: user.id, tv });
    setUserCookie(res, token);

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
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/logout", (req, res) => {
  clearUserCookie(res);
  return res.json({ ok: true });
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

    // revoke old tokens so JWT isn't stale
    await dbRun(`UPDATE users SET token_version=token_version+1 WHERE id=?`, [user.id]);
    const updated = await dbGet(`SELECT token_version FROM users WHERE id=?`, [user.id]);
    const tv = parseInt(updated?.token_version || "0", 10);

    const token = signUserJwt({ uid: user.id, tv });
    setUserCookie(res, token);

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
    const activeUsers = await dbGet(`SELECT COUNT(*) AS c FROM users WHERE banned_until=0 OR banned_until<=?`, [nowMs()]);
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

// -----------------------
// Auth protect /divine/* (including /divine/profile/*) + activity logging + redirect-on-next-load
// -----------------------
app.use("/divine", async (req, res, next) => {
  try {
    const user = await verifyUserFromRequest(req);
    if (!user) return res.redirect(302, "/");

    try { await updateLastIp(user.id, getReqIp(req)); } catch {}

    if (await isUserBanned(user)) {
      clearUserCookie(res);
      return res.redirect(302, "/");
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

// Start
initDb()
  .then(() => {
    app.listen(CONFIG.port, () => {
      console.log(`Divine server listening on :${CONFIG.port}`);
      console.log(`DB: ${CONFIG.dbPath}`);
    });
  })
  .catch((e) => {
    console.error("Failed to init DB:", e);
    process.exit(1);
  });
