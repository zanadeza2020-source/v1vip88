require("dotenv").config();
const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const slowDown   = require("express-slow-down");
const crypto     = require("crypto");
const path       = require("path");
const fs         = require("fs");
const fetch      = (...a) => import("node-fetch").then(({ default: f }) => f(...a));

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = "2.0.0";

// ── FILE PATHS ────────────────────────────────────────────────
const DB_FILE   = path.join(__dirname, "db.json");
const SESS_FILE = path.join(__dirname, "sessions.json");
const LOG_FILE  = path.join(__dirname, "security.log");

// ── ENCRYPTION ────────────────────────────────────────────────
const ENC_KEY = crypto.scryptSync(
  process.env.SECRET || "medterm_default_secret_change_me",
  "medterm_salt_v2", 32
);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  let enc = cipher.update(String(text), "utf8", "hex");
  enc += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return iv.toString("hex") + ":" + tag + ":" + enc;
}

function decrypt(data) {
  try {
    const [ivHex, tagHex, enc] = data.split(":");
    const iv  = Buffer.from(ivHex, "hex");
    const tag = Buffer.from(tagHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
    decipher.setAuthTag(tag);
    let dec = decipher.update(enc, "hex", "utf8");
    dec += decipher.final("utf8");
    return dec;
  } catch { return null; }
}

function hashPassword(pw) {
  return crypto.scryptSync(
    pw, process.env.SECRET || "salt", 64
  ).toString("hex");
}

function verifyPassword(pw, hash) {
  try {
    const attempt = crypto.scryptSync(pw, process.env.SECRET || "salt", 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(attempt), Buffer.from(hash));
  } catch { return false; }
}

// ── DATABASE ──────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE))
    fs.writeFileSync(DB_FILE, JSON.stringify({
      users: {}, training: [], events: [], reports: [], shared: {},
      settings: {
        max_users: 100,
        registration_open: true,
        default_daily_msgs: 30,
        default_max_words: 400,
        default_max_tokens: 1200,
        admin_daily_msgs: 999,
        admin_max_words: 4000,
        maintenance_mode: false,
        maintenance_msg: "النظام في وضع الصيانة"
      }
    }));
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch (e) { secLog("DB_ERROR", { error: e.message }); return { users:{}, training:[], events:[], reports:[], shared:{}, settings:{} }; }
}

function saveDB(db) {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

function loadSessions() {
  if (!fs.existsSync(SESS_FILE)) fs.writeFileSync(SESS_FILE, JSON.stringify({}));
  try { return JSON.parse(fs.readFileSync(SESS_FILE, "utf8")); }
  catch { return {}; }
}

function saveSessions(s) { fs.writeFileSync(SESS_FILE, JSON.stringify(s)); }

// ── UTILS ─────────────────────────────────────────────────────
const now    = () => new Date().toISOString();
const today  = () => new Date().toISOString().slice(0, 10);
const randId = (n=16) => crypto.randomBytes(n).toString("hex");
const randToken = () => crypto.randomBytes(48).toString("base64url");

function sanitize(s, max=5000) {
  if (typeof s !== "string") return "";
  return s.replace(/[<>]/g, "").replace(/javascript:/gi, "").trim().slice(0, max);
}

function secLog(type, data) {
  const entry = JSON.stringify({ ts: now(), type, data }) + "\n";
  try { fs.appendFileSync(LOG_FILE, entry); } catch {}
}

function logEvent(db, type, data) {
  if (!db.events) db.events = [];
  db.events.push({ type, data, ts: now() });
  if (db.events.length > 1000) db.events = db.events.slice(-1000);
}

// Generate credentials
const ADJ  = ["Alpha","Beta","Prime","Elite","Swift","Smart","Bold","Clear","Nova","Apex"];
const NOUN = ["Mind","Core","Star","Wave","Peak","Flow","Link","Base","Edge","Node"];
function genCreds() {
  const u = ADJ[Math.floor(Math.random()*10)] + NOUN[Math.floor(Math.random()*10)] + (Math.floor(Math.random()*9000)+1000);
  const p = randId(4).toUpperCase().replace(/[^A-Z0-9]/g,"X") + "@" + Math.floor(Math.random()*900+100);
  return { username: u, password: p };
}

function getUserLimits(user, settings) {
  if (user.role === "admin") return {
    daily_msgs:  settings.admin_daily_msgs  || 999,
    max_words:   settings.admin_max_words   || 4000,
    max_tokens:  4000
  };
  // Custom limits override global
  return {
    daily_msgs: user.custom_daily_msgs  ?? (settings.default_daily_msgs  || 30),
    max_words:  user.custom_max_words   ?? (settings.default_max_words   || 400),
    max_tokens: user.custom_max_tokens  ?? (settings.default_max_tokens  || 1200)
  };
}

function checkDailyLimit(user, settings) {
  const lim  = getUserLimits(user, settings);
  const used = user.usage_date === today() ? (user.daily_used || 0) : 0;
  return { ok: used < lim.daily_msgs, used, limit: lim.daily_msgs };
}

// ── SECURITY MIDDLEWARE ───────────────────────────────────────
app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: false,
  xFrameOptions: { action: "deny" },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

// Remove fingerprinting headers
app.use((req, res, next) => {
  res.removeHeader("X-Powered-By");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "30mb" }));

// ── RATE LIMITERS ─────────────────────────────────────────────
// Global API limit
app.use("/api/", rateLimit({
  windowMs: 60000, max: 100, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many requests", error_ar: "طلبات كثيرة جداً" },
  handler: (req, res, _next, options) => {
    secLog("RATE_LIMIT", { ip: req.ip, path: req.path });
    res.status(429).json(options.message);
  }
}));

// Slow down after 20 req/min
app.use("/api/", slowDown({
  windowMs: 60000, delayAfter: 20, delayMs: () => 300, maxDelayMs: 5000
}));

// Login — very strict
const loginLimiter = rateLimit({
  windowMs: 15 * 60000, max: 5, skipSuccessfulRequests: true,
  message: { error: "Too many login attempts. Try again in 15 minutes.", error_ar: "محاولات دخول كثيرة. انتظر 15 دقيقة." },
  handler: (req, res, _next, options) => {
    secLog("LOGIN_ABUSE", { ip: req.ip, username: req.body?.username });
    res.status(429).json(options.message);
  }
});

// Registration limit
const regLimiter = rateLimit({
  windowMs: 60 * 60000, max: 3,
  message: { error: "Registration limit reached.", error_ar: "تم تجاوز حد التسجيل." }
});

// Chat limit — per user
const chatLimiter = rateLimit({
  windowMs: 60000, max: 20,
  keyGenerator: (req) => {
    const cookie = req.headers.cookie || "";
    const m = cookie.match(/mt_s=([^;]+)/);
    return m ? m[1].slice(0, 32) : req.ip;
  },
  message: { error: "Sending too fast. Slow down.", error_ar: "ترسل بسرعة كبيرة." }
});

app.use(express.static(path.join(__dirname, "../frontend")));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
function requireAuth(req, res, next) {
  const cookie = req.headers.cookie || "";
  const m = cookie.match(/mt_s=([^;]+)/);
  const token = m ? m[1] : null;
  if (!token) return res.status(401).json({ error: "Not authenticated", error_ar: "غير مصادق" });

  const sessions = loadSessions();
  const sess = sessions[token];
  if (!sess) return res.status(401).json({ error: "Session expired", error_ar: "انتهت الجلسة" });

  // 24h expiry
  if (Date.now() - sess.created > 86400000) {
    delete sessions[token]; saveSessions(sessions);
    clearCookie(res);
    return res.status(401).json({ error: "Session expired", error_ar: "انتهت الجلسة" });
  }

  // Browser fingerprint check
  const fp = req.headers["user-agent"] || "";
  if (sess.ua && sess.ua !== fp.slice(0, 100)) {
    secLog("FINGERPRINT_MISMATCH", { token: token.slice(0,8), ip: req.ip });
    // Allow but log — don't block (mobile agents can change)
  }

  req.user = sess;
  req.sessionToken = token;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Forbidden", error_ar: "ممنوع" });
  next();
}

// Maintenance mode check
function checkMaintenance(req, res, next) {
  if (req.path.startsWith("/api/auth") || req.path.startsWith("/api/admin")) return next();
  const db = loadDB();
  if (db.settings?.maintenance_mode && req.user?.role !== "admin") {
    return res.status(503).json({
      error: db.settings.maintenance_msg || "Maintenance mode",
      error_ar: db.settings.maintenance_msg || "وضع الصيانة"
    });
  }
  next();
}

function setSessionCookie(res, token) {
  res.setHeader("Set-Cookie", `mt_s=${token}; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/`);
}
function clearCookie(res) {
  res.setHeader("Set-Cookie", "mt_s=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/");
}

// ── AUTH ROUTES ───────────────────────────────────────────────
app.post("/api/auth/register", regLimiter, (req, res) => {
  const db = loadDB();
  const { username, password } = req.body;

  // Check maintenance
  if (db.settings?.maintenance_mode)
    return res.status(503).json({ error_ar: "النظام في وضع الصيانة" });

  // Login with existing credentials
  if (username && password) {
    const u = Object.values(db.users).find(x => x.username === username);
    if (!u || !verifyPassword(password, u.password_hash)) {
      secLog("FAILED_LOGIN", { username: sanitize(username), ip: req.ip });
      logEvent(db, "failed_login", { username: sanitize(username) }); saveDB(db);
      return res.status(401).json({ error: "Invalid credentials", error_ar: "بيانات غير صحيحة" });
    }
    const token = randToken();
    const sessions = loadSessions();
    sessions[token] = {
      user_id: u.id, username: u.username, role: u.role,
      created: Date.now(), ip: req.ip, ua: (req.headers["user-agent"]||"").slice(0,100)
    };
    saveSessions(sessions);
    setSessionCookie(res, token);
    u.last_active = now();
    logEvent(db, "login", { username: u.username }); saveDB(db);
    return res.json({ username: u.username, role: u.role, version: APP_VERSION });
  }

  // Check if registration is open
  if (!db.settings?.registration_open)
    return res.status(403).json({ error: "Registration closed", error_ar: "التسجيل مغلق" });

  // Check max users
  const userCount = Object.keys(db.users).length;
  if (userCount >= (db.settings?.max_users || 100))
    return res.status(403).json({ error: "User limit reached", error_ar: "تم الوصول لحد المستخدمين" });

  // Auto-create
  const { username: un, password: pw } = genCreds();
  const id = randId(16);
  db.users[id] = {
    id, username: un, password_hash: hashPassword(pw), role: "user",
    created: now(), last_active: now(),
    daily_used: 0, usage_date: today(),
    total_msgs: 0, total_tokens: 0,
    theme: "dark", personality: "precise", lang: "ar",
    conversations: {}, memory: {}, long_memory: [],
    is_banned: false, ban_reason: "",
    custom_daily_msgs: null, custom_max_words: null, custom_max_tokens: null,
    notes: ""
  };
  const token = randToken();
  const sessions = loadSessions();
  sessions[token] = { user_id: id, username: un, role: "user", created: Date.now(), ip: req.ip, ua: (req.headers["user-agent"]||"").slice(0,100) };
  saveSessions(sessions);
  setSessionCookie(res, token);
  logEvent(db, "register", { username: un }); saveDB(db);
  res.json({ username: un, password: pw, role: "user", version: APP_VERSION, new_user: true });
});

app.post("/api/auth/login", loginLimiter, (req, res) => {
  const db = loadDB();
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error_ar: "أدخل البيانات" });

  const u = Object.values(db.users).find(x => x.username === username);
  if (!u || !verifyPassword(password, u.password_hash)) {
    secLog("FAILED_LOGIN", { username: sanitize(username), ip: req.ip });
    logEvent(db, "failed_login", { username: sanitize(username) }); saveDB(db);
    return res.status(401).json({ error: "Invalid credentials", error_ar: "بيانات غير صحيحة" });
  }
  if (u.is_banned) return res.status(403).json({ error_ar: "حسابك محظور: " + (u.ban_reason || "") });

  const token = randToken();
  const sessions = loadSessions();
  sessions[token] = { user_id: u.id, username: u.username, role: u.role, created: Date.now(), ip: req.ip, ua: (req.headers["user-agent"]||"").slice(0,100) };
  saveSessions(sessions);
  setSessionCookie(res, token);
  u.last_active = now(); logEvent(db, "login", { username: u.username }); saveDB(db);
  res.json({ username: u.username, role: u.role, version: APP_VERSION });
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  const sessions = loadSessions();
  delete sessions[req.sessionToken]; saveSessions(sessions);
  clearCookie(res); res.json({ ok: true });
});

app.get("/api/me", requireAuth, checkMaintenance, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u || u.is_banned) return res.status(403).json({ error_ar: "غير مصرح" });
  const lim = checkDailyLimit(u, db.settings || {});
  const limits = getUserLimits(u, db.settings || {});
  res.json({
    username: u.username, role: u.role, theme: u.theme,
    personality: u.personality, lang: u.lang || "ar",
    version: APP_VERSION, total_msgs: u.total_msgs || 0,
    daily_used: lim.used, daily_limit: lim.limit,
    max_words: limits.max_words, created: u.created,
    memory_count: (u.long_memory || []).length
  });
});

// ── SETTINGS ─────────────────────────────────────────────────
app.post("/api/settings", requireAuth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  const { theme, personality, lang } = req.body;
  const themes = ["dark","sage","dusk","slate","warm"];
  const pers   = ["precise","friendly","concise"];
  const langs  = ["ar","en"];
  if (theme && themes.includes(theme))   u.theme       = theme;
  if (personality && pers.includes(personality)) u.personality = personality;
  if (lang && langs.includes(lang))      u.lang        = lang;
  u.last_active = now(); saveDB(db);
  res.json({ ok: true });
});

// ── CONVERSATIONS ─────────────────────────────────────────────
app.get("/api/conversations", requireAuth, checkMaintenance, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  const list = Object.values(u.conversations || {})
    .filter(c => !c.archived)
    .sort((a,b) => b.last_msg > a.last_msg ? 1 : -1)
    .slice(0, 50);
  res.json({ conversations: list });
});

app.post("/api/conversations", requireAuth, checkMaintenance, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  const id = randId(12);
  if (!u.conversations) u.conversations = {};
  u.conversations[id] = { id, title: req.user.role === "admin" ? "New Chat" : "محادثة", created: now(), last_msg: now(), messages: [], archived: false };
  saveDB(db); res.json({ conv_id: id });
});

app.delete("/api/conversations/:id", requireAuth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  const cid = sanitize(req.params.id);
  if (u?.conversations?.[cid]) u.conversations[cid].archived = true;
  saveDB(db); res.json({ ok: true });
});

app.get("/api/history/:id", requireAuth, (req, res) => {
  const db = loadDB();
  const u  = db.users[req.user.user_id];
  const cid = sanitize(req.params.id);
  const c  = u?.conversations?.[cid];
  res.json({ messages: (c ? c.messages : []).map(m => ({
    role: m.role, content: m.content, ts: m.ts,
    has_image: !!m.has_image, has_doc: !!m.has_doc, deep: !!m.deep
  }))});
});

// ── MEMORY ────────────────────────────────────────────────────
app.get("/api/memory", requireAuth, (req, res) => {
  const db = loadDB(), u = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  res.json({ short_memory: u.memory || {}, long_memory: u.long_memory || [] });
});

app.delete("/api/memory", requireAuth, (req, res) => {
  const db = loadDB(), u = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  u.memory = {}; u.long_memory = []; saveDB(db); res.json({ ok: true });
});

// ── SEARCH HISTORY ────────────────────────────────────────────
app.get("/api/search-history", requireAuth, (req, res) => {
  const db = loadDB(), u = db.users[req.user.user_id];
  const q  = sanitize(req.query.q || "", 200);
  if (!q || q.length < 2) return res.json({ results: [] });
  const results = [];
  Object.values(u.conversations || {}).filter(c => !c.archived).forEach(conv => {
    conv.messages.forEach(m => {
      if (m.content?.toLowerCase().includes(q.toLowerCase())) {
        results.push({ conv_id: conv.id, conv_title: conv.title, role: m.role, content: m.content.slice(0, 200), ts: m.ts });
      }
    });
  });
  res.json({ results: results.slice(0, 20) });
});

// ── SHARE ─────────────────────────────────────────────────────
app.post("/api/share/:conv_id", requireAuth, (req, res) => {
  const db = loadDB(), u = db.users[req.user.user_id];
  const cid = sanitize(req.params.conv_id);
  const conv = u?.conversations?.[cid];
  if (!conv) return res.status(404).json({ error_ar: "غير موجود" });
  const sid = randId(8);
  if (!db.shared) db.shared = {};
  db.shared[sid] = {
    id: sid, title: conv.title, username: req.user.username,
    messages: conv.messages.map(m => ({ role: m.role, content: m.content, ts: m.ts })),
    created: now(), expires: new Date(Date.now() + 7*86400000).toISOString()
  };
  saveDB(db); res.json({ share_id: sid, url: "/shared/" + sid });
});

app.get("/api/shared/:id", (req, res) => {
  const db = loadDB();
  const s  = db.shared?.[req.params.id];
  if (!s) return res.status(404).json({ error_ar: "غير موجود" });
  if (new Date(s.expires) < new Date()) {
    delete db.shared[req.params.id]; saveDB(db);
    return res.status(410).json({ error_ar: "انتهت صلاحية الرابط" });
  }
  res.json(s);
});

app.get("/shared/:id", (_, res) => res.sendFile(path.join(__dirname, "../frontend/shared.html")));

// ── REPORT ────────────────────────────────────────────────────
app.post("/api/report", requireAuth, (req, res) => {
  const db = loadDB();
  const { reason } = req.body;
  if (!reason || reason.length < 5) return res.status(400).json({ error_ar: "اذكر السبب" });
  if (!db.reports) db.reports = [];
  db.reports.push({ id: randId(8), reporter: req.user.username, reason: sanitize(reason, 500), status: "pending", ts: now() });
  logEvent(db, "report", { by: req.user.username });
  saveDB(db); res.json({ ok: true });
});

// ── WEB SEARCH via Mistral ────────────────────────────────────
async function webSearch(query) {
  try {
    const r = await fetch("https://api.mistral.ai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + process.env.MISTRAL_API_KEY },
      body: JSON.stringify({
        model: "mistral-small-latest",
        messages: [
          { role: "system", content: "You are a search assistant. When given a query, provide 5 relevant results in JSON format like: [{\"title\":\"...\",\"url\":\"...\",\"snippet\":\"...\"}]. Return ONLY the JSON array, no extra text." },
          { role: "user", content: "Search for: " + query }
        ],
        temperature: 0.3, max_tokens: 800
      }),
      signal: AbortSignal.timeout(15000)
    });
    if (!r.ok) return null;
    const data = await r.json();
    const text = data.choices?.[0]?.message?.content || "";
    const match = text.match(/\[[\s\S]*\]/);
    if (!match) return null;
    return JSON.parse(match[0]).slice(0, 5);
  } catch { return null; }
}

// ── IMAGE GENERATION via Mistral ──────────────────────────────
async function generateImage(prompt) {
  // Mistral يولد وصفاً تفصيلياً للصورة ثم نعيده كـ SVG فني
  try {
    const r = await fetch("https://api.mistral.ai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + process.env.MISTRAL_API_KEY },
      body: JSON.stringify({
        model: "mistral-large-latest",
        messages: [
          { role: "system", content: "You are an SVG artist. Create a beautiful, detailed SVG image based on the user's description. Return ONLY the SVG code starting with <svg and ending with </svg>. Make it colorful, artistic, and detailed with gradients, shapes, and visual elements. Width: 512, Height: 512." },
          { role: "user", content: "Create an SVG image of: " + prompt }
        ],
        temperature: 0.8, max_tokens: 2000
      }),
      signal: AbortSignal.timeout(30000)
    });
    if (!r.ok) return null;
    const data = await r.json();
    const text = data.choices?.[0]?.message?.content || "";
    const svgMatch = text.match(/<svg[\s\S]*<\/svg>/i);
    if (!svgMatch) return null;
    const svgB64 = Buffer.from(svgMatch[0]).toString("base64");
    return "data:image/svg+xml;base64," + svgB64;
  } catch { return null; }
}

// ── IMAGE GENERATION ROUTE ────────────────────────────────────
app.post("/api/generate-image", requireAuth, chatLimiter, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error_ar: "أدخل وصف الصورة" });
  const img = await generateImage(sanitize(prompt, 500));
  if (!img) return res.status(503).json({ error_ar: "فشل توليد الصورة، حاول مجدداً" });
  res.json({ image: img });
});

// ── CHAT STREAM ───────────────────────────────────────────────
app.post("/api/chat/stream", requireAuth, checkMaintenance, chatLimiter, async (req, res) => {
  const { conv_id, message, images, documents, use_search, deep } = req.body;
  const msg = sanitize(message || "", 8000);
  const cid = sanitize(conv_id || "", 50);

  if (!cid || !msg) return res.status(400).json({ error_ar: "بيانات ناقصة" });

  const db  = loadDB();
  const u   = db.users[req.user.user_id];
  if (!u || u.is_banned) return res.status(403).json({ error_ar: "غير مصرح" });

  const settings = db.settings || {};
  const lim = getUserLimits(u, settings);
  const limitCheck = checkDailyLimit(u, settings);

  if (msg.length > 8000) return res.status(400).json({ error_ar: "الرسالة طويلة جداً" });
  const wc = msg.trim().split(/\s+/).filter(Boolean).length;
  if (wc > lim.max_words) return res.status(429).json({ error_ar: `تجاوزت حد ${lim.max_words} كلمة` });
  if (!limitCheck.ok) return res.status(429).json({ error_ar: `وصلت للحد اليومي (${lim.daily_msgs} رسالة)` });
  if (u.last_msg_ts && Date.now() - u.last_msg_ts < 1500) return res.status(429).json({ error_ar: "انتظر قبل الإرسال" });

  const conv = u.conversations?.[cid];
  if (!conv) return res.status(404).json({ error_ar: "المحادثة غير موجودة" });

  // Validate images
  let safeImgs = [];
  if (Array.isArray(images)) {
    for (const img of images.slice(0, 3)) {
      if (typeof img !== "string" || !img.startsWith("data:image/")) continue;
      if (img.length * 0.75 > 10 * 1024 * 1024) continue;
      safeImgs.push(img);
    }
  }

  // Validate & extract docs properly
  let safeDocs = [];
  if (Array.isArray(documents)) {
    for (const doc of documents.slice(0, 3)) {
      if (!doc?.data || typeof doc.data !== "string") continue;
      if (doc.data.length * 0.75 > 10 * 1024 * 1024) continue;

      let extractedText = null;
      const mimeType = doc.type || "";
      const name = doc.name || "file";

      try {
        const base64 = doc.data.includes(",") ? doc.data.split(",")[1] : doc.data;
        const buffer = Buffer.from(base64, "base64");

        if (mimeType.includes("text") || name.match(/\.(txt|md|csv|json|js|py|html|css|xml|yaml|yml|sh|sql)$/i)) {
          // Text files — read directly
          extractedText = buffer.toString("utf8").slice(0, 12000);
        } else if (name.match(/\.csv$/i)) {
          // CSV — format nicely
          extractedText = buffer.toString("utf8").slice(0, 8000);
        } else if (name.match(/\.json$/i)) {
          // JSON — parse and format
          try {
            const parsed = JSON.parse(buffer.toString("utf8"));
            extractedText = JSON.stringify(parsed, null, 2).slice(0, 8000);
          } catch { extractedText = buffer.toString("utf8").slice(0, 8000); }
        } else if (mimeType.includes("pdf") || name.match(/\.pdf$/i)) {
          // PDF — extract readable text (basic)
          const raw = buffer.toString("latin1");
          const textMatches = raw.match(/BT[\s\S]*?ET/g) || [];
          const pdfText = textMatches.map(block => {
            const tjMatch = block.match(/\(([^)]+)\)\s*Tj/g) || [];
            return tjMatch.map(t => t.replace(/\(([^)]+)\)\s*Tj/, "$1")).join(" ");
          }).join("\n").replace(/[^\x20-\x7E\u0600-\u06FF\n]/g," ").replace(/\s+/g," ").trim().slice(0, 8000);
          extractedText = pdfText.length > 50 ? pdfText : "PDF content (binary — please describe what you need from this document)";
        } else {
          // Other — try as UTF-8 text
          const raw = buffer.toString("utf8").replace(/[^\x20-\x7E\u0600-\u06FF\n\t]/g," ").replace(/\s+/g," ").trim();
          extractedText = raw.length > 20 ? raw.slice(0, 8000) : null;
        }
      } catch { extractedText = null; }

      if (extractedText) {
        safeDocs.push({
          name,
          text: `=== File: ${name} ===\n${extractedText}\n=== End of ${name} ===`
        });
      }
    }
  }

  // Save user message
  conv.messages.push({ role:"user", content:msg, has_image:safeImgs.length>0, has_doc:safeDocs.length>0, ts:now() });
  if (conv.messages.filter(m=>m.role==="user").length===1) conv.title = msg.slice(0, 45);
  conv.last_msg = now();
  u.last_msg_ts = Date.now();
  if (u.usage_date !== today()) { u.daily_used = 0; u.usage_date = today(); }
  u.daily_used++;
  saveDB(db);

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  const send = (data) => res.write("data: " + JSON.stringify(data) + "\n\n");

  // Web search
  let searchBlock = "";
  let searchResults = null;
  if (use_search) {
    send({ status: u.lang === "en" ? "🔍 Searching the web..." : "🔍 جاري البحث في الإنترنت..." });
    searchResults = await webSearch(msg);
    if (searchResults?.length) {
      searchBlock = "\n\n[Search Results]\n" + searchResults.map((r,i) => `${i+1}. ${r.title}\n${r.snippet}\nSource: ${r.url}`).join("\n\n");
      send({ status: u.lang === "en" ? `✅ Found ${searchResults.length} results` : `✅ ${searchResults.length} نتائج` });
    }
  }

  // Memory
  const memShort = Object.entries(u.memory || {}).map(([k,v]) => k+": "+v).join("\n");
  const memLong  = (u.long_memory || []).slice(-10).map(m => "- "+m).join("\n");
  const memBlock = (memShort || memLong) ? "\n\n[User Memory]\n" + memShort + (memLong ? "\n" + memLong : "") : "";

  // System prompt
  const lang = u.lang || "ar";
  const PERSONALITIES = {
    precise:  { ar: "أنت MedTerm، مساعد ذكاء اصطناعي متقدم ودقيق. قدّم إجابات كاملة ومنظمة مع عناوين وقوائم ورسائل واضحة. لا تترك الإجابة ناقصة أبداً.", en: "You are MedTerm, an advanced precise AI. Give complete, well-structured answers with headers, lists, and clear formatting. Never give incomplete answers." },
    friendly: { ar: "أنت MedTerm، مساعد ذكي وودود. كن دافئاً وشاملاً ودقيقاً في إجاباتك.", en: "You are MedTerm, a friendly smart assistant. Be warm, thorough, and precise." },
    concise:  { ar: "أنت MedTerm، مساعد ذكي مختصر. كن مباشراً لكن أكمل الإجابة دائماً.", en: "You are MedTerm, a concise smart assistant. Be direct but always complete." }
  };
  const pers = PERSONALITIES[u.personality] || PERSONALITIES.precise;
  const langInstr = lang === "en" ? "Reply in English." : lang === "ar" ? "رد باللغة العربية." : "Reply in the same language the user uses.";
  const sysPrompt = (pers[lang] || pers.ar) + " " + langInstr + memBlock + searchBlock;

  const model = safeImgs.length > 0 ? "pixtral-12b-2409" : "mistral-large-latest";
  const history = conv.messages.slice(-13, -1);

  const deepInstruction = deep ? "\n\nTHINK DEEPLY: Before answering, show your step-by-step reasoning briefly, then give the complete answer." : "";
  const finalSysPrompt = sysPrompt + deepInstruction;

  // Build messages
  const mistralMsgs = [{ role: "system", content: finalSysPrompt }];
  history.forEach(m => mistralMsgs.push({ role: m.role, content: m.content }));

  if (safeImgs.length > 0) {
    const docBlock = safeDocs.length ? "\n\n" + safeDocs.map(d => d.text).join("\n\n") : "";
    const parts = [{ type: "text", text: msg + docBlock }];
    safeImgs.forEach(img => parts.push({ type: "image_url", image_url: { url: img } }));
    mistralMsgs.push({ role: "user", content: parts });
  } else {
    const docBlock = safeDocs.length
      ? "\n\n" + safeDocs.map(d => d.text).join("\n\n") + "\n\n---\nUser question about the file(s) above: " + msg
      : msg;
    mistralMsgs.push({ role: "user", content: docBlock });
  }

  send({ status: u.lang === "en" ? "🤖 Thinking..." : "🤖 جاري التفكير..." });

  try {
    const apiRes = await fetch("https://api.mistral.ai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + process.env.MISTRAL_API_KEY },
      body: JSON.stringify({ model, messages: mistralMsgs, temperature: deep ? 0.2 : 0.3, max_tokens: lim.max_tokens, stream: true }),
      signal: AbortSignal.timeout(90000)
    });

    if (!apiRes.ok) {
      const e = await apiRes.json().catch(() => ({}));
      send({ error: e.message || "Mistral API error" }); return res.end();
    }

    let fullReply = "";
    for await (const chunk of apiRes.body) {
      const lines = chunk.toString().split("\n").filter(l => l.startsWith("data: "));
      for (const line of lines) {
        const raw = line.slice(6).trim();
        if (raw === "[DONE]") continue;
        try {
          const j = JSON.parse(raw);
          const delta = j.choices?.[0]?.delta?.content || "";
          if (delta) { fullReply += delta; send({ delta }); }
        } catch {}
      }
    }

    const tokens = Math.ceil((msg.length + fullReply.length) / 3);
    const db2 = loadDB();
    const u2  = db2.users[req.user.user_id];
    const c2  = u2?.conversations?.[cid];

    if (c2) {
      c2.messages.push({ role: "assistant", content: fullReply, tokens, model, deep: !!deep, ts: now() });
      u2.total_msgs   = (u2.total_msgs || 0) + 1;
      u2.total_tokens = (u2.total_tokens || 0) + tokens;
    }

    // Extract memory
    if (!u2.memory) u2.memory = {};
    const memPatterns = [
      { r: /my name is (\w+)/i, k: "name" },
      { r: /i(?:'m| am) from ([\w\s]+)/i, k: "country" },
      { r: /i(?:'m| am) (\d+) years/i, k: "age" },
      { r: /اسمي\s+([\u0600-\u06FF\w]+)/, k: "name" },
      { r: /(?:أنا من|من)\s+([\u0600-\u06FF\w]+)/, k: "country" },
      { r: /عمري\s+(\d+)/, k: "age" },
      { r: /أحب\s+([\u0600-\u06FF\w\s]{3,30})/, k: "interests" }
    ];
    memPatterns.forEach(({ r, k }) => { const m = msg.match(r); if (m) u2.memory[k] = sanitize(m[1], 50); });

    // Long memory
    if (!u2.long_memory) u2.long_memory = [];
    if (msg.length > 30 && fullReply.length > 80) {
      u2.long_memory.push(`[${new Date().toLocaleDateString()}] Q: ${msg.slice(0, 60)} → ${fullReply.slice(0, 100)}`);
      if (u2.long_memory.length > 50) u2.long_memory = u2.long_memory.slice(-50);
    }

    // Training data
    db2.training.push({ user_id: req.user.user_id, username: req.user.username, user_msg: msg, assistant_msg: fullReply, model, tokens, deep: !!deep, lang, ts: now() });
    logEvent(db2, "chat", { username: req.user.username, tokens, deep: !!deep });
    saveDB(db2);

    send({ done: true, tokens, remaining: lim.daily_msgs - (u2.daily_used || 0), sources: searchResults?.map(r => ({ title: r.title, url: r.url })) });
    res.end();

  } catch (e) {
    send({ error: e.name === "TimeoutError" ? "انتهت المهلة" : "خطأ في الاتصال" });
    res.end();
  }
});

// ── STATS ─────────────────────────────────────────────────────
app.get("/api/stats", requireAuth, (req, res) => {
  const db = loadDB(), u = db.users[req.user.user_id];
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  const lim = checkDailyLimit(u, db.settings || {});
  res.json({
    total_msgs: u.total_msgs || 0, total_tokens: u.total_tokens || 0,
    conversations: Object.values(u.conversations || {}).filter(c => !c.archived).length,
    daily_used: lim.used, daily_limit: lim.limit,
    training_pairs: db.training.filter(t => t.user_id === req.user.user_id).length,
    memory_count: (u.long_memory || []).length, version: APP_VERSION
  });
});

// ── ADMIN ROUTES ──────────────────────────────────────────────
app.get("/api/admin/dashboard", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const users = Object.values(db.users);
  const s = db.settings || {};
  const totalMsgs   = users.reduce((a,u) => a + (u.total_msgs||0), 0);
  const totalTokens = users.reduce((a,u) => a + (u.total_tokens||0), 0);
  const todayUsage  = users.reduce((a,u) => a + (u.usage_date===today()?(u.daily_used||0):0), 0);
  const act = {};
  db.training.forEach(t => { const d=t.ts?.slice(0,10); if(d) act[d]=(act[d]||0)+1; });
  const modelUsage = {};
  db.training.forEach(t => { modelUsage[t.model]=(modelUsage[t.model]||0)+1; });
  res.json({
    overview: {
      totalUsers: users.length, activeToday: users.filter(u=>u.last_active?.slice(0,10)===today()).length,
      activeWeek: users.filter(u=>Date.now()-new Date(u.last_active||0)<7*86400000).length,
      adminCount: users.filter(u=>u.role==="admin").length,
      bannedCount: users.filter(u=>u.is_banned).length,
      totalMsgs, totalTokens, totalTraining: db.training.length, todayUsage,
      pendingReports: (db.reports||[]).filter(r=>r.status==="pending").length
    },
    settings: s,
    topUsers: users.sort((a,b)=>(b.total_msgs||0)-(a.total_msgs||0)).slice(0,10)
      .map(u=>({ username:u.username, role:u.role, total_msgs:u.total_msgs||0, total_tokens:u.total_tokens||0, created:u.created, last_active:u.last_active, is_banned:u.is_banned })),
    activity: Object.entries(act).sort().slice(-14).map(([day,count])=>({day,count})),
    recentEvents: (db.events||[]).slice(-100).reverse(),
    modelUsage, reports: (db.reports||[]).slice(-20).reverse(),
    version: APP_VERSION
  });
});

app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({ users: Object.values(db.users).map(u => ({
    id: u.id, username: u.username, role: u.role,
    total_msgs: u.total_msgs||0, total_tokens: u.total_tokens||0,
    daily_used: u.usage_date===today()?(u.daily_used||0):0,
    daily_limit: getUserLimits(u, db.settings||{}).daily_msgs,
    max_words: getUserLimits(u, db.settings||{}).max_words,
    created: u.created, last_active: u.last_active,
    is_banned: u.is_banned||false, ban_reason: u.ban_reason||"",
    custom_daily_msgs: u.custom_daily_msgs, custom_max_words: u.custom_max_words,
    notes: u.notes||""
  })), total: Object.keys(db.users).length });
});

// Update user (admin full control)
app.put("/api/admin/users/:username", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const u  = Object.values(db.users).find(x => x.username === req.params.username);
  if (!u) return res.status(404).json({ error_ar: "المستخدم غير موجود" });
  if (u.username === req.user.username && req.body.role === "user")
    return res.status(400).json({ error_ar: "لا يمكنك تخفيض نفسك" });

  const { role, is_banned, ban_reason, custom_daily_msgs, custom_max_words, custom_max_tokens, notes, reset_limit } = req.body;
  if (role && ["user","admin"].includes(role)) u.role = role;
  if (typeof is_banned === "boolean") u.is_banned = is_banned;
  if (ban_reason !== undefined) u.ban_reason = sanitize(ban_reason, 200);
  if (custom_daily_msgs !== undefined) u.custom_daily_msgs = custom_daily_msgs === null ? null : parseInt(custom_daily_msgs)||null;
  if (custom_max_words !== undefined) u.custom_max_words = custom_max_words === null ? null : parseInt(custom_max_words)||null;
  if (custom_max_tokens !== undefined) u.custom_max_tokens = custom_max_tokens === null ? null : parseInt(custom_max_tokens)||null;
  if (notes !== undefined) u.notes = sanitize(notes, 500);
  if (reset_limit) { u.daily_used = 0; u.usage_date = today(); }

  logEvent(db, "admin_user_update", { by: req.user.username, target: u.username, changes: req.body });
  saveDB(db); res.json({ ok: true });
});

app.delete("/api/admin/users/:username", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const u  = Object.values(db.users).find(x => x.username === req.params.username);
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  if (u.username === req.user.username) return res.status(400).json({ error_ar: "لا يمكنك حذف نفسك" });
  delete db.users[u.id];
  // Invalidate sessions
  const sessions = loadSessions();
  Object.keys(sessions).forEach(k => { if (sessions[k].user_id === u.id) delete sessions[k]; });
  saveSessions(sessions);
  logEvent(db, "user_deleted", { by: req.user.username, target: u.username });
  saveDB(db); res.json({ ok: true });
});

// Global settings update
app.put("/api/admin/settings", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  if (!db.settings) db.settings = {};
  const {
    max_users, registration_open, default_daily_msgs, default_max_words, default_max_tokens,
    admin_daily_msgs, admin_max_words, maintenance_mode, maintenance_msg
  } = req.body;
  if (max_users !== undefined)         db.settings.max_users         = parseInt(max_users)||100;
  if (registration_open !== undefined) db.settings.registration_open = !!registration_open;
  if (default_daily_msgs !== undefined)db.settings.default_daily_msgs= parseInt(default_daily_msgs)||30;
  if (default_max_words !== undefined) db.settings.default_max_words = parseInt(default_max_words)||400;
  if (default_max_tokens !== undefined)db.settings.default_max_tokens= parseInt(default_max_tokens)||1200;
  if (admin_daily_msgs !== undefined)  db.settings.admin_daily_msgs  = parseInt(admin_daily_msgs)||999;
  if (admin_max_words !== undefined)   db.settings.admin_max_words   = parseInt(admin_max_words)||4000;
  if (maintenance_mode !== undefined)  db.settings.maintenance_mode  = !!maintenance_mode;
  if (maintenance_msg !== undefined)   db.settings.maintenance_msg   = sanitize(maintenance_msg, 200);
  logEvent(db, "settings_update", { by: req.user.username, settings: req.body });
  saveDB(db); res.json({ ok: true, settings: db.settings });
});

// Reports
app.get("/api/admin/reports", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({ reports: (db.reports||[]).slice().reverse() });
});

app.put("/api/admin/reports/:id", requireAuth, requireAdmin, (req, res) => {
  const db = loadDB();
  const r  = (db.reports||[]).find(x => x.id === req.params.id);
  if (r) r.status = req.body.status || "resolved";
  saveDB(db); res.json({ ok: true });
});

// Export training
app.get("/api/admin/export-training", requireAuth, requireAdmin, (req, res) => {
  const db   = loadDB();
  const jsonl = db.training.map(r => JSON.stringify({
    messages: [
      { role: "system",    content: "You are MedTerm, an advanced AI assistant." },
      { role: "user",      content: r.user_msg },
      { role: "assistant", content: r.assistant_msg }
    ]
  })).join("\n");
  res.setHeader("Content-Type", "application/jsonl");
  res.setHeader("Content-Disposition", "attachment; filename=training.jsonl");
  res.send(jsonl);
});

// Security logs (admin)
app.get("/api/admin/security-log", requireAuth, requireAdmin, (req, res) => {
  try {
    const logs = fs.existsSync(LOG_FILE)
      ? fs.readFileSync(LOG_FILE, "utf8").trim().split("\n").slice(-100).reverse().map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean)
      : [];
    res.json({ logs });
  } catch { res.json({ logs: [] }); }
});

// Admin panel
app.get("/admin", requireAuth, requireAdmin, (_, res) =>
  res.sendFile(path.join(__dirname, "../frontend/admin.html"))
);

// Export chat as HTML
app.get("/api/export/html/:conv_id", requireAuth, (req, res) => {
  const db = loadDB(), u = db.users[req.user.user_id];
  const cid = sanitize(req.params.conv_id);
  const conv = u?.conversations?.[cid];
  if (!conv) return res.status(404).json({ error_ar: "غير موجود" });
  const msgs = conv.messages.map(m =>
    `<div style="margin:14px 0;padding:12px 16px;background:${m.role==="user"?"#eef2ff":"#f9fafb"};border-radius:10px;font-family:Arial;direction:rtl">
      <strong>${m.role==="user"?"أنت":"MedTerm"}</strong>
      <div style="margin-top:6px;white-space:pre-wrap">${(m.content||"").replace(/</g,"&lt;")}</div>
      <small style="color:#999;font-size:11px">${m.ts||""}</small>
    </div>`).join("");
  res.setHeader("Content-Type","text/html;charset=utf-8");
  res.setHeader("Content-Disposition",`attachment; filename=chat.html`);
  res.send(`<!DOCTYPE html><html dir="rtl"><head><meta charset="UTF-8"/><title>${conv.title}</title></head><body style="max-width:800px;margin:0 auto;padding:20px"><h1 style="color:#3b82f6">${conv.title}</h1>${msgs}<footer style="color:#999;font-size:12px;text-align:center;margin-top:20px;padding-top:10px;border-top:1px solid #eee">MedTerm v${APP_VERSION} · ${now()}</footer></body></html>`);
});

app.get("*", (_, res) => res.sendFile(path.join(__dirname, "../frontend/index.html")));
app.listen(PORT, () => console.log(`\nMedTerm v${APP_VERSION} → http://localhost:${PORT}\n`));
