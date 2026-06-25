require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const slowDown  = require("express-slow-down");
const crypto    = require("crypto");
const path      = require("path");
const fs        = require("fs");
const mongoose  = require("mongoose");
const fetch     = (...a) => import("node-fetch").then(({ default: f }) => f(...a));

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = "2.1.0";

// ── MONGODB CONNECTION ────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost/medterm", {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
}).then(() => console.log("✅ MongoDB connected"))
  .catch(e => console.error("❌ MongoDB error:", e.message));

// ── SCHEMAS ───────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  _id: String,
  username: { type: String, unique: true, index: true },
  password_hash: String,
  role: { type: String, default: "user" },
  plan: { type: String, default: "free" },
  device_id: { type: String, index: true },
  ip_registered: String,
  created: String,
  last_active: String,
  last_reset: String,
  daily_msgs_used:   { type: Number, default: 0 },
  daily_images_used: { type: Number, default: 0 },
  daily_files_used:  { type: Number, default: 0 },
  total_msgs:   { type: Number, default: 0 },
  total_tokens: { type: Number, default: 0 },
  theme: { type: String, default: "dark" },
  personality: { type: String, default: "precise" },
  lang: { type: String, default: "ar" },
  conversations: { type: Map, of: mongoose.Schema.Types.Mixed, default: {} },
  memory: { type: Map, of: String, default: {} },
  long_memory: [String],
  is_banned: { type: Boolean, default: false },
  ban_reason: { type: String, default: "" },
  custom_daily_msgs:   { type: Number, default: null },
  custom_max_words:    { type: Number, default: null },
  custom_max_tokens:   { type: Number, default: null },
  last_msg_ts: Number,
  notes: { type: String, default: "" }
}, { timestamps: false });

const SessionSchema = new mongoose.Schema({
  _id: String,
  user_id: String,
  username: String,
  role: String,
  created: { type: Number, default: Date.now },
  ip: String,
  ua: String,
  device_id: String
});
SessionSchema.index({ created: 1 }, { expireAfterSeconds: 86400 });

const EventSchema = new mongoose.Schema({
  type: String,
  data: mongoose.Schema.Types.Mixed,
  ts: { type: Date, default: Date.now }
});
EventSchema.index({ ts: -1 });

const TrainingSchema = new mongoose.Schema({
  user_id: String,
  username: String,
  user_msg: String,
  assistant_msg: String,
  model: String,
  tokens: Number,
  deep: Boolean,
  lang: String,
  ts: { type: Date, default: Date.now }
});

const ReportSchema = new mongoose.Schema({
  _id: String,
  reporter: String,
  reason: String,
  status: { type: String, default: "pending" },
  ts: { type: Date, default: Date.now }
});

const SettingsSchema = new mongoose.Schema({
  _id: { type: String, default: "global" },
  max_users: { type: Number, default: 100 },
  registration_open: { type: Boolean, default: true },
  default_daily_msgs:  { type: Number, default: 20 },
  default_max_words:   { type: Number, default: 400 },
  default_max_tokens:  { type: Number, default: 1200 },
  admin_daily_msgs:    { type: Number, default: 9999 },
  admin_max_words:     { type: Number, default: 8000 },
  maintenance_mode:    { type: Boolean, default: false },
  maintenance_msg:     { type: String, default: "النظام في وضع الصيانة" }
});

const User     = mongoose.model("User",     UserSchema);
const Session  = mongoose.model("Session",  SessionSchema);
const Event    = mongoose.model("Event",    EventSchema);
const Training = mongoose.model("Training", TrainingSchema);
const Report   = mongoose.model("Report",   ReportSchema);
const Settings = mongoose.model("Settings", SettingsSchema);

async function getSettings() {
  let s = await Settings.findById("global").lean();
  if (!s) { s = await Settings.create({ _id: "global" }); s = s.toObject(); }
  return s;
}

// ── ENCRYPTION ────────────────────────────────────────────────
const ENC_KEY = crypto.scryptSync(process.env.SECRET || "medterm_secret_v2", "medterm_salt", 32);

function hashPassword(pw) {
  return crypto.scryptSync(pw, process.env.SECRET || "salt", 64).toString("hex");
}
function verifyPassword(pw, hash) {
  try {
    const attempt = crypto.scryptSync(pw, process.env.SECRET || "salt", 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(attempt), Buffer.from(hash));
  } catch { return false; }
}

// ── UTILS ─────────────────────────────────────────────────────
const now     = () => new Date().toISOString();
const randId  = (n=16) => crypto.randomBytes(n).toString("hex");
const randTok = () => crypto.randomBytes(48).toString("base64url");

function sanitize(s, max=5000) {
  if (typeof s !== "string") return "";
  return s.replace(/[<>]/g,"").replace(/javascript:/gi,"").trim().slice(0, max);
}

function secLog(type, data) {
  console.log(`[SEC] ${type}:`, JSON.stringify(data));
}

async function logEvent(type, data) {
  try { await Event.create({ type, data }); } catch {}
}

const ADJ  = ["Alpha","Beta","Prime","Elite","Swift","Smart","Bold","Clear","Nova","Apex"];
const NOUN = ["Mind","Core","Star","Wave","Peak","Flow","Link","Base","Edge","Node"];
function genCreds() {
  const u = ADJ[Math.floor(Math.random()*10)] + NOUN[Math.floor(Math.random()*10)] + (Math.floor(Math.random()*9000)+1000);
  const p = randId(4).toUpperCase().replace(/[^A-Z0-9]/g,"X") + "@" + Math.floor(Math.random()*900+100);
  return { username: u, password: p };
}

// ── PLANS ─────────────────────────────────────────────────────
const PLANS = {
  free:  { name:"مجاني",  daily_msgs:20,   daily_images:5,  daily_files:5,  max_words:400,  max_tokens:1200, max_file_mb:5,  reset_hours:24 },
  pro:   { name:"VIP ⭐", daily_msgs:200,  daily_images:50, daily_files:50, max_words:2000, max_tokens:4000, max_file_mb:20, reset_hours:24 },
  admin: { name:"مشرف",  daily_msgs:9999, daily_images:999,daily_files:999,max_words:8000, max_tokens:4000, max_file_mb:50, reset_hours:24 }
};

function getPlan(user) {
  if (user.role === "admin") return PLANS.admin;
  return PLANS[user.plan] || PLANS.free;
}

function checkUsage(user) {
  const plan = getPlan(user);
  const lastReset = user.last_reset ? new Date(user.last_reset) : new Date(0);
  const hoursSince = (Date.now() - lastReset.getTime()) / 3600000;
  if (hoursSince >= plan.reset_hours) {
    user.daily_msgs_used   = 0;
    user.daily_images_used = 0;
    user.daily_files_used  = 0;
    user.last_reset = now();
  }
  return {
    plan,
    msgs:   { used: user.daily_msgs_used   || 0, limit: plan.daily_msgs   },
    images: { used: user.daily_images_used || 0, limit: plan.daily_images },
    files:  { used: user.daily_files_used  || 0, limit: plan.daily_files  },
    reset_in: Math.max(0, plan.reset_hours - hoursSince),
    msgs_ok:   (user.daily_msgs_used   || 0) < plan.daily_msgs,
    images_ok: (user.daily_images_used || 0) < plan.daily_images,
    files_ok:  (user.daily_files_used  || 0) < plan.daily_files
  };
}

function getUserLimits(user) {
  const plan = getPlan(user);
  return {
    daily_msgs:  user.custom_daily_msgs  ?? plan.daily_msgs,
    max_words:   user.custom_max_words   ?? plan.max_words,
    max_tokens:  plan.max_tokens,
    max_file_mb: plan.max_file_mb
  };
}

function getDeviceId(req) {
  const ua   = req.headers["user-agent"] || "";
  const lang = req.headers["accept-language"] || "";
  return crypto.createHash("sha256").update(ua + "|" + lang).digest("hex").slice(0, 32);
}

// ── MIDDLEWARE ────────────────────────────────────────────────
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false, xFrameOptions: { action: "deny" }, hsts: { maxAge: 31536000 } }));
app.use((_, res, next) => { res.removeHeader("X-Powered-By"); next(); });
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "30mb" }));

app.use("/api/", rateLimit({
  windowMs: 60000, max: 120,
  message: { error_ar: "طلبات كثيرة جداً، انتظر دقيقة" },
  handler: (req, res, _, opts) => { secLog("RATE_LIMIT", { ip: req.ip }); res.status(429).json(opts.message); }
}));
app.use("/api/", slowDown({ windowMs: 60000, delayAfter: 25, delayMs: () => 300, maxDelayMs: 4000 }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60000, max: 5, skipSuccessfulRequests: true,
  message: { error_ar: "محاولات كثيرة، انتظر 15 دقيقة" },
  handler: (req, res, _, opts) => { secLog("LOGIN_ABUSE", { ip: req.ip }); res.status(429).json(opts.message); }
});
const regLimiter  = rateLimit({ windowMs: 3600000, max: 5, message: { error_ar: "تم تجاوز حد التسجيل" } });
const chatLimiter = rateLimit({
  windowMs: 60000, max: 25,
  keyGenerator: req => { const m = (req.headers.cookie||"").match(/mt_s=([^;]+)/); return m ? m[1].slice(0,32) : req.ip; },
  message: { error_ar: "ترسل بسرعة كبيرة، انتظر قليلاً" }
});

app.use(express.static(path.join(__dirname, "../frontend")));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
async function requireAuth(req, res, next) {
  const m = (req.headers.cookie||"").match(/mt_s=([^;]+)/);
  const token = m ? m[1] : null;
  if (!token) return res.status(401).json({ error_ar: "غير مصادق" });
  const sess = await Session.findById(token).lean();
  if (!sess) return res.status(401).json({ error_ar: "انتهت الجلسة" });
  req.user = sess; req.sessionToken = token; next();
}

async function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error_ar: "ممنوع" });
  next();
}

async function checkMaintenance(req, res, next) {
  if (req.path.startsWith("/api/auth") || req.path.startsWith("/api/superadmin")) return next();
  const s = await getSettings();
  if (s.maintenance_mode && req.user?.role !== "admin")
    return res.status(503).json({ error_ar: s.maintenance_msg || "وضع الصيانة" });
  next();
}

function setSessionCookie(res, token) {
  res.setHeader("Set-Cookie", `mt_s=${token}; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/`);
}
function clearCookie(res) {
  res.setHeader("Set-Cookie", "mt_s=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/");
}

// ── AUTH ROUTES ───────────────────────────────────────────────
app.post("/api/auth/register", regLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const s = await getSettings();

    // Login with existing creds
    if (username && password) {
      const u = await User.findOne({ username }).lean();
      if (!u || !verifyPassword(password, u.password_hash)) {
        await logEvent("failed_login", { username: sanitize(username) });
        return res.status(401).json({ error_ar: "بيانات غير صحيحة" });
      }
      if (u.is_banned) return res.status(403).json({ error_ar: "حسابك محظور: " + u.ban_reason });
      const token = randTok();
      await Session.create({ _id: token, user_id: u._id, username: u.username, role: u.role, ip: req.ip, ua: (req.headers["user-agent"]||"").slice(0,100) });
      setSessionCookie(res, token);
      await User.findByIdAndUpdate(u._id, { last_active: now() });
      await logEvent("login", { username: u.username });
      return res.json({ username: u.username, role: u.role, version: APP_VERSION });
    }

    if (!s.registration_open) return res.status(403).json({ error_ar: "التسجيل مغلق" });
    const count = await User.countDocuments();
    if (count >= s.max_users) return res.status(403).json({ error_ar: "وصلنا لحد المستخدمين" });

    // Device check
    const deviceId = getDeviceId(req);
    const existing = await User.findOne({ device_id: deviceId }).lean();
    if (existing) {
      if (existing.is_banned) return res.status(403).json({ error_ar: "هذا الجهاز محظور" });
      const token = randTok();
      await Session.create({ _id: token, user_id: existing._id, username: existing.username, role: existing.role, device_id: deviceId, ip: req.ip, ua: (req.headers["user-agent"]||"").slice(0,100) });
      setSessionCookie(res, token);
      await User.findByIdAndUpdate(existing._id, { last_active: now() });
      await logEvent("device_relogin", { username: existing.username });
      return res.json({ username: existing.username, role: existing.role, version: APP_VERSION, new_user: false });
    }

    // Create new user
    const { username: un, password: pw } = genCreds();
    const id = randId(16);
    await User.create({ _id: id, username: un, password_hash: hashPassword(pw), device_id: deviceId, ip_registered: req.ip, created: now(), last_active: now(), last_reset: now() });
    const token = randTok();
    await Session.create({ _id: token, user_id: id, username: un, role: "user", device_id: deviceId, ip: req.ip, ua: (req.headers["user-agent"]||"").slice(0,100) });
    setSessionCookie(res, token);
    await logEvent("register", { username: un });
    res.json({ username: un, password: pw, role: "user", plan: "free", version: APP_VERSION, new_user: true });
  } catch (e) { console.error("Register error:", e); res.status(500).json({ error_ar: "خطأ في السيرفر" }); }
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error_ar: "أدخل البيانات" });
    const u = await User.findOne({ username }).lean();
    if (!u || !verifyPassword(password, u.password_hash)) {
      await logEvent("failed_login", { username: sanitize(username) });
      return res.status(401).json({ error_ar: "بيانات غير صحيحة" });
    }
    if (u.is_banned) return res.status(403).json({ error_ar: "حسابك محظور: " + u.ban_reason });
    const token = randTok();
    await Session.create({ _id: token, user_id: u._id, username: u.username, role: u.role, ip: req.ip, ua: (req.headers["user-agent"]||"").slice(0,100) });
    setSessionCookie(res, token);
    await User.findByIdAndUpdate(u._id, { last_active: now() });
    await logEvent("login", { username: u.username });
    res.json({ username: u.username, role: u.role, version: APP_VERSION });
  } catch (e) { res.status(500).json({ error_ar: "خطأ في السيرفر" }); }
});

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  await Session.findByIdAndDelete(req.sessionToken);
  clearCookie(res); res.json({ ok: true });
});

app.get("/api/me", requireAuth, checkMaintenance, async (req, res) => {
  try {
    const u = await User.findById(req.user.user_id).lean();
    if (!u || u.is_banned) return res.status(403).json({ error_ar: "غير مصرح" });
    const usage  = checkUsage(u);
    const limits = getUserLimits(u);
    if (usage.msgs.used === 0 && u.last_reset !== u.last_reset) await User.findByIdAndUpdate(u._id, { daily_msgs_used:0, daily_images_used:0, daily_files_used:0, last_reset: now() });
    res.json({
      username: u.username, role: u.role, theme: u.theme,
      personality: u.personality, lang: u.lang || "ar",
      version: APP_VERSION, total_msgs: u.total_msgs || 0,
      plan: u.plan || "free", plan_name: usage.plan.name,
      daily_used: usage.msgs.used, daily_limit: usage.msgs.limit,
      images_used: usage.images.used, images_limit: usage.images.limit,
      files_used: usage.files.used, files_limit: usage.files.limit,
      reset_in_hours: Math.round(usage.reset_in * 10) / 10,
      max_words: limits.max_words, max_file_mb: limits.max_file_mb,
      created: u.created, memory_count: (u.long_memory || []).length
    });
  } catch (e) { res.status(500).json({ error_ar: "خطأ" }); }
});

// ── SETTINGS ─────────────────────────────────────────────────
app.post("/api/settings", requireAuth, async (req, res) => {
  const { theme, personality, lang } = req.body;
  const update = {};
  if (["dark","sage","dusk","slate","warm"].includes(theme)) update.theme = theme;
  if (["precise","friendly","concise"].includes(personality)) update.personality = personality;
  if (["ar","en"].includes(lang)) update.lang = lang;
  update.last_active = now();
  await User.findByIdAndUpdate(req.user.user_id, update);
  res.json({ ok: true });
});

// ── CONVERSATIONS ─────────────────────────────────────────────
app.get("/api/conversations", requireAuth, checkMaintenance, async (req, res) => {
  const u = await User.findById(req.user.user_id).select("conversations").lean();
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  const convs = Object.values(u.conversations || {})
    .filter(c => !c.archived)
    .sort((a,b) => b.last_msg > a.last_msg ? 1 : -1)
    .slice(0, 50);
  res.json({ conversations: convs });
});

app.post("/api/conversations", requireAuth, checkMaintenance, async (req, res) => {
  const id = randId(12);
  const conv = { id, title: "محادثة", created: now(), last_msg: now(), messages: [], archived: false };
  await User.findByIdAndUpdate(req.user.user_id, { [`conversations.${id}`]: conv });
  res.json({ conv_id: id });
});

app.delete("/api/conversations/:id", requireAuth, async (req, res) => {
  const cid = sanitize(req.params.id);
  await User.findByIdAndUpdate(req.user.user_id, { [`conversations.${cid}.archived`]: true });
  res.json({ ok: true });
});

app.get("/api/history/:id", requireAuth, async (req, res) => {
  const u = await User.findById(req.user.user_id).select("conversations").lean();
  const cid = sanitize(req.params.id);
  const c = u?.conversations?.[cid];
  res.json({ messages: (c?.messages || []).map(m => ({ role:m.role, content:m.content, ts:m.ts, has_image:!!m.has_image, deep:!!m.deep })) });
});

// ── MEMORY ────────────────────────────────────────────────────
app.get("/api/memory", requireAuth, async (req, res) => {
  const u = await User.findById(req.user.user_id).select("memory long_memory").lean();
  res.json({ short_memory: u?.memory || {}, long_memory: u?.long_memory || [] });
});
app.delete("/api/memory", requireAuth, async (req, res) => {
  await User.findByIdAndUpdate(req.user.user_id, { memory: {}, long_memory: [] });
  res.json({ ok: true });
});

// ── SEARCH HISTORY ────────────────────────────────────────────
app.get("/api/search-history", requireAuth, async (req, res) => {
  const q = sanitize(req.query.q || "", 200);
  if (q.length < 2) return res.json({ results: [] });
  const u = await User.findById(req.user.user_id).select("conversations").lean();
  const results = [];
  Object.values(u?.conversations || {}).filter(c => !c.archived).forEach(conv => {
    (conv.messages || []).forEach(m => {
      if (m.content?.toLowerCase().includes(q.toLowerCase()))
        results.push({ conv_id:conv.id, conv_title:conv.title, role:m.role, content:m.content.slice(0,200), ts:m.ts });
    });
  });
  res.json({ results: results.slice(0, 20) });
});

// ── SHARE ─────────────────────────────────────────────────────
const ShareSchema = new mongoose.Schema({ _id:String, title:String, username:String, messages:[mongoose.Schema.Types.Mixed], expires:Date });
ShareSchema.index({ expires: 1 }, { expireAfterSeconds: 0 });
const Share = mongoose.model("Share", ShareSchema);

app.post("/api/share/:conv_id", requireAuth, async (req, res) => {
  const cid = sanitize(req.params.conv_id);
  const u = await User.findById(req.user.user_id).select("conversations").lean();
  const conv = u?.conversations?.[cid];
  if (!conv) return res.status(404).json({ error_ar: "غير موجود" });
  const sid = randId(8);
  await Share.create({ _id:sid, title:conv.title, username:req.user.username, messages:conv.messages.map(m=>({role:m.role,content:m.content,ts:m.ts})), expires:new Date(Date.now()+7*86400000) });
  res.json({ share_id:sid, url:"/shared/"+sid });
});

app.get("/api/shared/:id", async (req, res) => {
  const s = await Share.findById(req.params.id).lean();
  if (!s) return res.status(404).json({ error_ar: "الرابط غير صالح أو منتهي" });
  res.json(s);
});
app.get("/shared/:id", (_, res) => res.sendFile(path.join(__dirname,"../frontend/shared.html")));

// ── REPORT ────────────────────────────────────────────────────
app.post("/api/report", requireAuth, async (req, res) => {
  const { reason } = req.body;
  if (!reason || reason.length < 5) return res.status(400).json({ error_ar: "اذكر السبب" });
  await Report.create({ _id:randId(8), reporter:req.user.username, reason:sanitize(reason,500) });
  await logEvent("report", { by:req.user.username });
  res.json({ ok:true });
});

// ── MISTRAL HELPERS ───────────────────────────────────────────
async function callMistral(messages, model="mistral-large-latest", temperature=0.3, maxTokens=1200) {
  const r = await fetch("https://api.mistral.ai/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type":"application/json", "Authorization":"Bearer "+process.env.MISTRAL_API_KEY },
    body: JSON.stringify({ model, messages, temperature, max_tokens: maxTokens, stream: false }),
    signal: AbortSignal.timeout(30000)
  });
  if (!r.ok) return null;
  const d = await r.json();
  return d.choices?.[0]?.message?.content || null;
}

async function webSearch(query) {
  try {
    const res = await callMistral([
      { role:"system", content:'Return ONLY a JSON array of 5 web search results for the query. Format: [{"title":"...","url":"https://...","snippet":"..."}]. No extra text.' },
      { role:"user", content:"Search: " + query }
    ], "mistral-small-latest", 0.2, 600);
    const match = res?.match(/\[[\s\S]*\]/);
    return match ? JSON.parse(match[0]).slice(0,5) : null;
  } catch { return null; }
}

async function generateImage(prompt) {
  try {
    const svg = await callMistral([
      { role:"system", content:"You are an SVG artist. Create a beautiful, detailed, colorful SVG (512x512) based on the description. Return ONLY the SVG code starting with <svg and ending with </svg>. Use gradients, shapes, and visual elements." },
      { role:"user", content:"Create SVG of: " + prompt }
    ], "mistral-large-latest", 0.8, 2000);
    const m = svg?.match(/<svg[\s\S]*<\/svg>/i);
    if (!m) return null;
    return "data:image/svg+xml;base64," + Buffer.from(m[0]).toString("base64");
  } catch { return null; }
}

// ── IMAGE GENERATION ──────────────────────────────────────────
app.post("/api/generate-image", requireAuth, chatLimiter, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error_ar: "أدخل وصف الصورة" });
  const u = await User.findById(req.user.user_id).lean();
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  const usage = checkUsage(u);
  if (!usage.images_ok) return res.status(429).json({ error_ar: `وصلت لحد الصور (${usage.images.limit}/يوم)` });
  const img = await generateImage(sanitize(prompt, 500));
  if (!img) return res.status(503).json({ error_ar: "فشل التوليد، حاول مجدداً" });
  await User.findByIdAndUpdate(req.user.user_id, { $inc: { daily_images_used: 1 } });
  res.json({ image: img });
});

// ── CHAT STREAM ───────────────────────────────────────────────
app.post("/api/chat/stream", requireAuth, checkMaintenance, chatLimiter, async (req, res) => {
  const { conv_id, message, images, documents, use_search, deep } = req.body;
  const msg = sanitize(message || "", 8000);
  const cid = sanitize(conv_id || "", 50);
  if (!cid || !msg) return res.status(400).json({ error_ar: "بيانات ناقصة" });

  const u = await User.findById(req.user.user_id).lean();
  if (!u || u.is_banned) return res.status(403).json({ error_ar: "غير مصرح" });

  const usage  = checkUsage(u);
  const limits = getUserLimits(u);

  if (msg.length > 8000) return res.status(400).json({ error_ar: "الرسالة طويلة جداً" });
  const wc = msg.trim().split(/\s+/).filter(Boolean).length;
  if (wc > limits.max_words) return res.status(429).json({ error_ar: `تجاوزت حد ${limits.max_words} كلمة` });
  if (u.last_msg_ts && Date.now() - u.last_msg_ts < 1500) return res.status(429).json({ error_ar: "انتظر قليلاً" });

  // Check limit — show subscription message
  if (!usage.msgs_ok) {
    const subMsg = `عزيزي المستخدم،\n\nلقد انتهت فترتك التجريبية المجانية.\n\n**✨ اشترك الآن في MedTerm AI**\n\n**مميزات الاشتراك VIP:**\n- 200 رسالة يومياً\n- 50 صورة يومياً\n- بحث دقيق وذكي\n- بدون حدود عملية\n\n**💰 السعر: 5 شيكل فقط / شهر**\n\n**طرق الدفع:**\nبال باي أو جوال باي\nالرقم: 0597111855\nباسم: إياد معروف\n\nبعد التحويل راسل المهندس نادر:\n📱 [+972 59-385-0520](https://wa.me/972593850520)\n\n_يتجدد الحد المجاني بعد ${Math.ceil(usage.reset_in)} ساعة_`;
    return res.status(429).json({ error_ar: subMsg, is_subscription_msg: true, reset_in: usage.reset_in });
  }

  // Auto-create conversation
  let conv = u.conversations?.[cid];
  if (!conv) {
    conv = { id:cid, title:msg.slice(0,45), created:now(), last_msg:now(), messages:[], archived:false };
    await User.findByIdAndUpdate(req.user.user_id, { [`conversations.${cid}`]: conv });
  }

  // Validate images
  let safeImgs = [];
  if (Array.isArray(images) && images.length > 0) {
    if (!usage.images_ok) return res.status(429).json({ error_ar: `وصلت لحد الصور (${usage.images.limit}/يوم)` });
    for (const img of images.slice(0,3)) {
      if (typeof img!=="string" || !img.startsWith("data:image/")) continue;
      if (img.length * 0.75 > limits.max_file_mb * 1024 * 1024) continue;
      safeImgs.push(img);
    }
  }

  // Extract docs
  let safeDocs = [];
  if (Array.isArray(documents) && documents.length > 0) {
    if (!usage.files_ok) return res.status(429).json({ error_ar: `وصلت لحد الملفات (${usage.files.limit}/يوم)` });
    for (const doc of documents.slice(0,3)) {
      if (!doc?.data || typeof doc.data !== "string") continue;
      if (doc.data.length * 0.75 > limits.max_file_mb * 1024 * 1024) continue;
      try {
        const base64 = doc.data.includes(",") ? doc.data.split(",")[1] : doc.data;
        const buffer = Buffer.from(base64, "base64");
        const name   = doc.name || "file";
        let text = null;
        if (doc.type?.includes("text") || name.match(/\.(txt|md|csv|json|js|py|html|css|xml|sh|sql)$/i)) {
          text = buffer.toString("utf8").slice(0, 12000);
        } else if (name.match(/\.json$/i)) {
          try { text = JSON.stringify(JSON.parse(buffer.toString("utf8")), null, 2).slice(0, 8000); } catch { text = buffer.toString("utf8").slice(0, 8000); }
        } else if (name.match(/\.pdf$/i)) {
          const raw = buffer.toString("latin1");
          const blocks = (raw.match(/BT[\s\S]*?ET/g) || []);
          const pdfText = blocks.map(b => (b.match(/\(([^)]+)\)\s*Tj/g)||[]).map(t=>t.replace(/\(([^)]+)\)\s*Tj/,"$1")).join(" ")).join("\n")
            .replace(/[^\x20-\x7E\u0600-\u06FF\n]/g," ").replace(/\s+/g," ").trim().slice(0, 8000);
          text = pdfText.length > 50 ? pdfText : `محتوى PDF (${name}) — اسألني عن محتوى الملف`;
        } else {
          const raw = buffer.toString("utf8").replace(/[^\x20-\x7E\u0600-\u06FF\n\t]/g," ").replace(/\s+/g," ").trim();
          text = raw.length > 20 ? raw.slice(0, 8000) : null;
        }
        if (text) safeDocs.push({ name, text: `=== ${name} ===\n${text}\n=== نهاية ${name} ===` });
      } catch {}
    }
  }

  // SSE headers
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");
  const send = d => res.write("data: " + JSON.stringify(d) + "\n\n");

  // Web search
  let searchBlock = "", searchResults = null;
  if (use_search) {
    send({ status: u.lang==="en" ? "🔍 Searching..." : "🔍 جاري البحث..." });
    searchResults = await webSearch(msg);
    if (searchResults?.length) {
      searchBlock = "\n\n[Search Results]\n" + searchResults.map((r,i)=>`${i+1}. ${r.title}\n${r.snippet}\n${r.url}`).join("\n\n");
      send({ status: u.lang==="en" ? `✅ ${searchResults.length} results` : `✅ ${searchResults.length} نتائج` });
    }
  }

  // Memory
  const memShort = Object.entries(u.memory||{}).map(([k,v])=>k+": "+v).join("\n");
  const memLong  = (u.long_memory||[]).slice(-8).map(m=>"- "+m).join("\n");
  const memBlock = (memShort||memLong) ? "\n\n[User Memory]\n"+memShort+(memLong?"\n"+memLong:"") : "";

  // System prompt
  const lang = u.lang || "ar";
  const PERSONALITIES = {
    precise: {
      ar: `أنت MedTerm AI، مساعد ذكاء اصطناعي دقيق ومتقدم.\nقواعد الإجابة:\n- ابدأ الإجابة مباشرة بدون مقدمات\n- ردود متوسطة الطول: دقيقة وشاملة وليست طويلة جداً\n- استخدم النقاط والعناوين فقط عند الحاجة\n- كن دقيقاً 100% في المعلومات\n- إذا لم تعرف شيئاً قل ذلك`,
      en: `You are MedTerm AI, a precise and advanced assistant.\nRules:\n- Start the answer directly, no preamble\n- Medium-length: precise, complete, not too long\n- Use bullet points/headers only when needed\n- Be 100% accurate\n- If unsure, say so`
    },
    friendly: {
      ar: `أنت MedTerm AI، مساعد ذكي وودود.\n- ابدأ مباشرة بدون مقدمات طويلة\n- ردود متوسطة ودقيقة`,
      en: `You are MedTerm AI, friendly and smart.\n- Start directly\n- Medium, precise answers`
    },
    concise: {
      ar: `أنت MedTerm AI، مساعد مختصر ودقيق.\n- أجوبة قصيرة ومباشرة\n- النقطة الأساسية فقط\n- دقيق 100%`,
      en: `You are MedTerm AI, concise and accurate.\n- Short, direct answers\n- Key point only\n- 100% accurate`
    }
  };
  const pers = PERSONALITIES[u.personality] || PERSONALITIES.precise;
  const langInstr = lang==="en" ? "Reply in English." : "رد باللغة العربية.";
  const sysPrompt = (pers[lang]||pers.ar) + "\n" + langInstr + memBlock + searchBlock;
  const deepInstr = deep ? "\n\nفكّر خطوة بخطوة بشكل مختصر ثم أجب." : "";

  const model = safeImgs.length > 0 ? "pixtral-12b-2409" : "mistral-large-latest";
  const history = (conv.messages || []).slice(-12);
  const mistralMsgs = [{ role:"system", content:sysPrompt + deepInstr }];
  history.forEach(m => mistralMsgs.push({ role:m.role, content:m.content }));

  if (safeImgs.length > 0) {
    const parts = [{ type:"text", text: msg + (safeDocs.length ? "\n\n" + safeDocs.map(d=>d.text).join("\n\n") : "") }];
    safeImgs.forEach(img => parts.push({ type:"image_url", image_url:{ url:img } }));
    mistralMsgs.push({ role:"user", content:parts });
  } else {
    const docBlock = safeDocs.length ? "\n\n" + safeDocs.map(d=>d.text).join("\n\n") + "\n\n---\nالسؤال: " + msg : msg;
    mistralMsgs.push({ role:"user", content:docBlock });
  }

  send({ status: u.lang==="en" ? "🤖 Thinking..." : "🤖 جاري التفكير..." });

  try {
    const apiRes = await fetch("https://api.mistral.ai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type":"application/json", "Authorization":"Bearer "+process.env.MISTRAL_API_KEY },
      body: JSON.stringify({ model, messages:mistralMsgs, temperature:deep?0.2:0.3, max_tokens:limits.max_tokens, stream:true }),
      signal: AbortSignal.timeout(90000)
    });

    if (!apiRes.ok) {
      const e = await apiRes.json().catch(()=>({}));
      send({ error: e.message || "Mistral error" }); return res.end();
    }

    let fullReply = "";
    for await (const chunk of apiRes.body) {
      for (const line of chunk.toString().split("\n").filter(l=>l.startsWith("data: "))) {
        const raw = line.slice(6).trim();
        if (raw==="[DONE]") continue;
        try {
          const j = JSON.parse(raw);
          const delta = j.choices?.[0]?.delta?.content || "";
          if (delta) { fullReply += delta; send({ delta }); }
        } catch {}
      }
    }

    const tokens = Math.ceil((msg.length + fullReply.length) / 3);

    // Save to MongoDB
    const newMsg = { role:"user", content:msg, has_image:safeImgs.length>0, ts:now() };
    const aiMsg  = { role:"assistant", content:fullReply, tokens, model, deep:!!deep, ts:now() };
    const title  = conv.messages?.length === 0 ? msg.slice(0,45) : conv.title;

    const update = {
      [`conversations.${cid}.messages`]: [...(conv.messages||[]), newMsg, aiMsg],
      [`conversations.${cid}.last_msg`]: now(),
      [`conversations.${cid}.title`]: title,
      last_active: now(),
      last_msg_ts: Date.now(),
      $inc: {
        total_msgs: 1,
        total_tokens: tokens,
        daily_msgs_used: 1,
        ...(safeImgs.length > 0 ? { daily_images_used: safeImgs.length } : {}),
        ...(safeDocs.length > 0 ? { daily_files_used: safeDocs.length } : {})
      }
    };

    // Extract short memory
    const uCurrent = await User.findById(req.user.user_id).lean();
    const memPatterns = [
      { r:/my name is (\w+)/i, k:"name" }, { r:/اسمي\s+([\u0600-\u06FF\w]+)/, k:"name" },
      { r:/i(?:'m| am) from ([\w\s]+)/i, k:"country" }, { r:/(?:أنا من|من)\s+([\u0600-\u06FF\w]+)/, k:"country" },
      { r:/i(?:'m| am) (\d+) years/i, k:"age" }, { r:/عمري\s+(\d+)/, k:"age" }
    ];
    const memUpdates = {};
    memPatterns.forEach(({ r, k }) => { const m = msg.match(r); if(m) memUpdates[`memory.${k}`] = sanitize(m[1],50); });
    Object.assign(update, memUpdates);

    // Long memory
    if (msg.length > 30 && fullReply.length > 80) {
      const longMem = [...(uCurrent?.long_memory||[]), `[${new Date().toLocaleDateString()}] ${msg.slice(0,60)} → ${fullReply.slice(0,100)}`].slice(-50);
      update.long_memory = longMem;
    }

    await User.findByIdAndUpdate(req.user.user_id, update);

    // Save training
    await Training.create({ user_id:req.user.user_id, username:req.user.username, user_msg:msg, assistant_msg:fullReply, model, tokens, deep:!!deep, lang });
    await logEvent("chat", { username:req.user.username, tokens });

    send({ done:true, tokens, sources: searchResults?.map(r=>({ title:r.title, url:r.url })) });
    res.end();

  } catch (e) {
    send({ error: e.name==="TimeoutError" ? "انتهت المهلة" : "خطأ في الاتصال" });
    res.end();
  }
});

// ── STATS ─────────────────────────────────────────────────────
app.get("/api/stats", requireAuth, async (req, res) => {
  const u = await User.findById(req.user.user_id).lean();
  if (!u) return res.status(404).json({ error_ar: "غير موجود" });
  const usage  = checkUsage(u);
  const convs  = Object.values(u.conversations||{}).filter(c=>!c.archived).length;
  const train  = await Training.countDocuments({ user_id: req.user.user_id });
  res.json({
    total_msgs:u.total_msgs||0, total_tokens:u.total_tokens||0,
    conversations:convs, daily_used:usage.msgs.used, daily_limit:usage.msgs.limit,
    training_pairs:train, memory_count:(u.long_memory||[]).length, version:APP_VERSION
  });
});

// ── EXPORT ────────────────────────────────────────────────────
app.get("/api/export/html/:conv_id", requireAuth, async (req, res) => {
  const u = await User.findById(req.user.user_id).select("conversations").lean();
  const cid = sanitize(req.params.conv_id);
  const conv = u?.conversations?.[cid];
  if (!conv) return res.status(404).json({ error_ar: "غير موجود" });
  const msgs = (conv.messages||[]).map(m=>`<div style="margin:12px 0;padding:10px 14px;background:${m.role==="user"?"#eef2ff":"#f9fafb"};border-radius:9px;direction:rtl;font-family:Arial"><strong>${m.role==="user"?"أنت":"MedTerm"}</strong><div style="margin-top:5px;white-space:pre-wrap">${(m.content||"").replace(/</g,"&lt;")}</div><small style="color:#999">${m.ts||""}</small></div>`).join("");
  res.setHeader("Content-Type","text/html;charset=utf-8");
  res.setHeader("Content-Disposition","attachment; filename=chat.html");
  res.send(`<!DOCTYPE html><html dir="rtl"><head><meta charset="UTF-8"/><title>${conv.title}</title></head><body style="max-width:800px;margin:0 auto;padding:20px"><h1 style="color:#3b82f6">${conv.title}</h1>${msgs}</body></html>`);
});

// ── SUPERADMIN ────────────────────────────────────────────────
const ADMIN_USER = process.env.ADMIN_USER || "medterm_admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "change_me";
const adminTokens = new Map();

app.post("/api/superadmin/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    secLog("SUPERADMIN_FAIL", { ip: req.ip });
    return res.status(401).json({ error: "Invalid" });
  }
  const token = randTok();
  adminTokens.set(token, Date.now());
  setTimeout(() => adminTokens.delete(token), 3600000);
  res.json({ token });
});

function requireSuperAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];
  const t = token && adminTokens.get(token);
  if (!t || Date.now() - t > 3600000) { adminTokens.delete(token); return res.status(401).json({ error:"Not authenticated" }); }
  next();
}

app.get("/api/superadmin/data", requireSuperAdmin, async (req, res) => {
  const s = await getSettings();
  const users = await User.find({}).select("-conversations -memory -long_memory -password_hash").lean();
  const totalMsgs   = users.reduce((a,u)=>a+(u.total_msgs||0),0);
  const totalTokens = users.reduce((a,u)=>a+(u.total_tokens||0),0);
  const today = new Date().toISOString().slice(0,10);
  const todayUsage  = users.reduce((a,u)=>a+(u.last_reset?.slice(0,10)===today?u.daily_msgs_used||0:0),0);
  const act = await Training.aggregate([{ $group:{ _id:{ $dateToString:{format:"%Y-%m-%d",date:"$ts"} }, count:{$sum:1} } },{ $sort:{ _id:1 } },{ $limit:14 }]);
  const reports  = await Report.find({}).sort({ ts:-1 }).limit(30).lean();
  const events   = await Event.find({}).sort({ ts:-1 }).limit(50).lean();
  res.json({
    overview: { totalUsers:users.length, totalMsgs, totalTokens, totalTraining:await Training.countDocuments(), activeToday:users.filter(u=>u.last_active?.slice(0,10)===today).length, bannedCount:users.filter(u=>u.is_banned).length, todayUsage, pendingReports:reports.filter(r=>r.status==="pending").length, settings:s },
    users: users.map(u=>({ id:u._id, username:u.username, role:u.role, plan:u.plan||"free", total_msgs:u.total_msgs||0, total_tokens:u.total_tokens||0, daily_used:u.daily_msgs_used||0, daily_limit:getUserLimits(u).daily_msgs, is_banned:u.is_banned||false, ban_reason:u.ban_reason||"", created:u.created, last_active:u.last_active, custom_daily_msgs:u.custom_daily_msgs, custom_max_words:u.custom_max_words, notes:u.notes||"" })),
    activity: act.map(a=>({ day:a._id, count:a.count })),
    reports, events
  });
});

app.put("/api/superadmin/user/:username", requireSuperAdmin, async (req, res) => {
  const { role, plan, is_banned, ban_reason, custom_daily_msgs, custom_max_words, reset_limit, notes } = req.body;
  const update = {};
  if (role && ["user","admin"].includes(role))   update.role = role;
  if (plan && ["free","pro"].includes(plan))      update.plan = plan;
  if (typeof is_banned === "boolean")             update.is_banned = is_banned;
  if (ban_reason !== undefined)                   update.ban_reason = sanitize(ban_reason, 200);
  if (custom_daily_msgs !== undefined)            update.custom_daily_msgs = custom_daily_msgs===null?null:parseInt(custom_daily_msgs)||null;
  if (custom_max_words !== undefined)             update.custom_max_words  = custom_max_words===null?null:parseInt(custom_max_words)||null;
  if (notes !== undefined)                        update.notes = sanitize(notes, 500);
  if (reset_limit) { update.daily_msgs_used=0; update.daily_images_used=0; update.daily_files_used=0; update.last_reset=now(); }
  await User.findOneAndUpdate({ username: req.params.username }, update);
  await logEvent("superadmin_update", { target:req.params.username });
  res.json({ ok:true });
});

app.delete("/api/superadmin/user/:username", requireSuperAdmin, async (req, res) => {
  const u = await User.findOne({ username: req.params.username });
  if (!u) return res.status(404).json({ error:"Not found" });
  await Session.deleteMany({ user_id: u._id });
  await User.findByIdAndDelete(u._id);
  await logEvent("superadmin_delete", { target: req.params.username });
  res.json({ ok:true });
});

app.put("/api/superadmin/settings", requireSuperAdmin, async (req, res) => {
  const { max_users, registration_open, default_daily_msgs, default_max_words, maintenance_mode, maintenance_msg } = req.body;
  const update = {};
  if (max_users !== undefined)          update.max_users          = parseInt(max_users)||100;
  if (registration_open !== undefined)  update.registration_open  = !!registration_open;
  if (default_daily_msgs !== undefined) update.default_daily_msgs = parseInt(default_daily_msgs)||20;
  if (default_max_words !== undefined)  update.default_max_words  = parseInt(default_max_words)||400;
  if (maintenance_mode !== undefined)   update.maintenance_mode   = !!maintenance_mode;
  if (maintenance_msg !== undefined)    update.maintenance_msg    = sanitize(maintenance_msg, 200);
  await Settings.findByIdAndUpdate("global", update, { upsert: true });
  await logEvent("settings_update", req.body);
  res.json({ ok:true });
});

app.put("/api/superadmin/reports/:id", requireSuperAdmin, async (req, res) => {
  await Report.findByIdAndUpdate(req.params.id, { status: req.body.status || "resolved" });
  res.json({ ok:true });
});

app.get("/api/superadmin/export", requireSuperAdmin, async (req, res) => {
  const training = await Training.find({}).lean();
  const jsonl = training.map(r => JSON.stringify({ messages:[{ role:"system", content:"You are MedTerm AI." },{ role:"user", content:r.user_msg },{ role:"assistant", content:r.assistant_msg }] })).join("\n");
  res.setHeader("Content-Type","application/jsonl");
  res.setHeader("Content-Disposition","attachment; filename=training.jsonl");
  res.send(jsonl);
});

app.get("/dashboard", (_, res) => res.sendFile(path.join(__dirname,"../frontend/dashboard.html")));
app.get("*", (_, res) => res.sendFile(path.join(__dirname,"../frontend/index.html")));
app.listen(PORT, () => console.log(`\nMedTerm v${APP_VERSION} → http://localhost:${PORT}\n`));
