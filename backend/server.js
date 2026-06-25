require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const helmet   = require("helmet");
const rateLimit= require("express-rate-limit");
const slowDown = require("express-slow-down");
const crypto   = require("crypto");
const path     = require("path");
const mongoose = require("mongoose");
const fetch    = (...a) => import("node-fetch").then(({default:f})=>f(...a));

const app = express();
const PORT = process.env.PORT || 3000;
const VER  = "2.1.0";

// ── MONGODB ───────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI||"mongodb://localhost/medterm",{
  serverSelectionTimeoutMS:10000, socketTimeoutMS:45000
}).then(()=>console.log("✅ MongoDB connected"))
  .catch(e=>console.error("❌ MongoDB:",e.message));

// ── SCHEMAS ───────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  _id:String, username:{type:String,unique:true,index:true},
  password_hash:String, role:{type:String,default:"user"}, plan:{type:String,default:"free"},
  device_id:{type:String,index:true}, ip_registered:String,
  created:String, last_active:String, last_reset:String,
  daily_msgs_used:{type:Number,default:0}, daily_images_used:{type:Number,default:0}, daily_files_used:{type:Number,default:0},
  total_msgs:{type:Number,default:0}, total_tokens:{type:Number,default:0},
  theme:{type:String,default:"dark"}, personality:{type:String,default:"precise"}, lang:{type:String,default:"ar"},
  conversations:{type:Map,of:mongoose.Schema.Types.Mixed,default:{}},
  memory:{type:Map,of:String,default:{}}, long_memory:[String],
  is_banned:{type:Boolean,default:false}, ban_reason:{type:String,default:""},
  custom_daily_msgs:{type:Number,default:null}, custom_max_words:{type:Number,default:null},
  last_msg_ts:Number, notes:{type:String,default:""}
});
const SessionSchema = new mongoose.Schema({
  _id:String, user_id:String, username:String, role:String,
  created:{type:Number,default:Date.now}, ip:String, ua:String, device_id:String
});
SessionSchema.index({created:1},{expireAfterSeconds:86400});
const EventSchema   = new mongoose.Schema({type:String,data:mongoose.Schema.Types.Mixed,ts:{type:Date,default:Date.now}});
const TrainingSchema= new mongoose.Schema({user_id:String,username:String,user_msg:String,assistant_msg:String,model:String,tokens:Number,deep:Boolean,lang:String,ts:{type:Date,default:Date.now}});
const ReportSchema  = new mongoose.Schema({_id:String,reporter:String,reason:String,status:{type:String,default:"pending"},ts:{type:Date,default:Date.now}});
const ShareSchema   = new mongoose.Schema({_id:String,title:String,username:String,messages:[mongoose.Schema.Types.Mixed],expires:Date});
ShareSchema.index({expires:1},{expireAfterSeconds:0});
const SettingsSchema= new mongoose.Schema({
  _id:{type:String,default:"global"},
  max_users:{type:Number,default:100}, registration_open:{type:Boolean,default:true},
  default_daily_msgs:{type:Number,default:20}, default_max_words:{type:Number,default:400},
  default_max_tokens:{type:Number,default:1200}, admin_daily_msgs:{type:Number,default:9999},
  admin_max_words:{type:Number,default:8000}, maintenance_mode:{type:Boolean,default:false},
  maintenance_msg:{type:String,default:"النظام في وضع الصيانة"}
});

const User     = mongoose.model("User",UserSchema);
const Session  = mongoose.model("Session",SessionSchema);
const Event    = mongoose.model("Event",EventSchema);
const Training = mongoose.model("Training",TrainingSchema);
const Report   = mongoose.model("Report",ReportSchema);
const Share    = mongoose.model("Share",ShareSchema);
const Settings = mongoose.model("Settings",SettingsSchema);

async function getSettings(){
  let s=await Settings.findById("global").lean();
  if(!s){s=await Settings.create({_id:"global"});s=s.toObject();}
  return s;
}

// ── CRYPTO ────────────────────────────────────────────────────
function hashPw(pw){ return crypto.scryptSync(pw,process.env.SECRET||"salt",64).toString("hex"); }
function verifyPw(pw,hash){
  try{const a=crypto.scryptSync(pw,process.env.SECRET||"salt",64).toString("hex");return crypto.timingSafeEqual(Buffer.from(a),Buffer.from(hash));}
  catch{return false;}
}

// ── UTILS ─────────────────────────────────────────────────────
const now    = ()=>new Date().toISOString();
const randId = (n=16)=>crypto.randomBytes(n).toString("hex");
const randTok= ()=>crypto.randomBytes(48).toString("base64url");
const san    = (s,max=5000)=>typeof s!=="string"?"":s.replace(/[<>]/g,"").replace(/javascript:/gi,"").trim().slice(0,max);
const logEv  = async(type,data)=>{ try{await Event.create({type,data});}catch{} };
const ADJ=["Alpha","Beta","Prime","Elite","Swift","Smart","Bold","Clear","Nova","Apex"];
const NOUN=["Mind","Core","Star","Wave","Peak","Flow","Link","Base","Edge","Node"];
function genCreds(){
  const u=ADJ[Math.floor(Math.random()*10)]+NOUN[Math.floor(Math.random()*10)]+(Math.floor(Math.random()*9000)+1000);
  const p=randId(4).toUpperCase().replace(/[^A-Z0-9]/g,"X")+"@"+Math.floor(Math.random()*900+100);
  return{username:u,password:p};
}

// ── PLANS ─────────────────────────────────────────────────────
const PLANS={
  free: {name:"مجاني",  daily_msgs:20,   daily_images:5,  daily_files:5,  max_words:400,  max_tokens:1200, max_file_mb:5,  reset_hours:24},
  pro:  {name:"VIP ⭐", daily_msgs:200,  daily_images:50, daily_files:50, max_words:2000, max_tokens:4000, max_file_mb:20, reset_hours:24},
  admin:{name:"مشرف",   daily_msgs:9999, daily_images:999,daily_files:999,max_words:8000, max_tokens:4000, max_file_mb:50, reset_hours:24}
};
function getPlan(u){return u.role==="admin"?PLANS.admin:PLANS[u.plan]||PLANS.free;}
function checkUsage(u){
  const plan=getPlan(u);
  const hrs=(Date.now()-new Date(u.last_reset||0).getTime())/3600000;
  if(hrs>=plan.reset_hours){u.daily_msgs_used=0;u.daily_images_used=0;u.daily_files_used=0;u.last_reset=now();}
  return{
    plan,
    msgs:{used:u.daily_msgs_used||0,limit:plan.daily_msgs},
    images:{used:u.daily_images_used||0,limit:plan.daily_images},
    files:{used:u.daily_files_used||0,limit:plan.daily_files},
    reset_in:Math.max(0,plan.reset_hours-hrs),
    msgs_ok:(u.daily_msgs_used||0)<plan.daily_msgs,
    images_ok:(u.daily_images_used||0)<plan.daily_images,
    files_ok:(u.daily_files_used||0)<plan.daily_files
  };
}
function getLimits(u){
  const plan=getPlan(u);
  return{daily_msgs:u.custom_daily_msgs??plan.daily_msgs,max_words:u.custom_max_words??plan.max_words,max_tokens:plan.max_tokens,max_file_mb:plan.max_file_mb};
}
function getDeviceId(req){
  return crypto.createHash("sha256").update((req.headers["user-agent"]||"")+(req.headers["accept-language"]||"")).digest("hex").slice(0,32);
}

// ── MIDDLEWARE ────────────────────────────────────────────────
app.set("trust proxy",1);
app.use(helmet({contentSecurityPolicy:false,xFrameOptions:{action:"deny"},hsts:{maxAge:31536000}}));
app.use((_,res,next)=>{res.removeHeader("X-Powered-By");next();});
app.use(cors({origin:true,credentials:true}));
app.use(express.json({limit:"30mb"}));
app.use("/api/",rateLimit({windowMs:60000,max:120,message:{error_ar:"طلبات كثيرة جداً"},handler:(req,res,_,opts)=>{console.log("RATE",req.ip);res.status(429).json(opts.message);}}));
app.use("/api/",slowDown({windowMs:60000,delayAfter:25,delayMs:()=>300,maxDelayMs:4000}));
const loginLim=rateLimit({windowMs:900000,max:5,skipSuccessfulRequests:true,message:{error_ar:"محاولات كثيرة، انتظر 15 دقيقة"}});
const regLim  =rateLimit({windowMs:3600000,max:5,message:{error_ar:"تم تجاوز حد التسجيل"}});
const chatLim =rateLimit({windowMs:60000,max:25,keyGenerator:req=>{const m=(req.headers.cookie||"").match(/mt_s=([^;]+)/);return m?m[1].slice(0,32):req.ip;},message:{error_ar:"ترسل بسرعة، انتظر قليلاً"}});
app.use(express.static(path.join(__dirname,"../frontend")));

// ── AUTH MW ───────────────────────────────────────────────────
async function auth(req,res,next){
  const m=(req.headers.cookie||"").match(/mt_s=([^;]+)/);
  if(!m)return res.status(401).json({error_ar:"غير مصادق"});
  const sess=await Session.findById(m[1]).lean();
  if(!sess)return res.status(401).json({error_ar:"انتهت الجلسة"});
  req.user=sess;req.tok=m[1];next();
}
async function adminOnly(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error_ar:"ممنوع"});next();}
async function checkMaint(req,res,next){
  if(req.path.startsWith("/api/auth")||req.path.startsWith("/api/superadmin"))return next();
  const s=await getSettings();
  if(s.maintenance_mode&&req.user?.role!=="admin")return res.status(503).json({error_ar:s.maintenance_msg||"وضع الصيانة"});
  next();
}
const setC=(res,tok)=>res.setHeader("Set-Cookie",`mt_s=${tok}; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/`);
const clrC =(res)=>res.setHeader("Set-Cookie","mt_s=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/");

// ── AUTH ──────────────────────────────────────────────────────
app.post("/api/auth/register",regLim,async(req,res)=>{
  try{
    const{username,password}=req.body;
    const s=await getSettings();
    // Login with credentials
    if(username&&password){
      const u=await User.findOne({username}).lean();
      if(!u||!verifyPw(password,u.password_hash)){await logEv("failed_login",{username:san(username)});return res.status(401).json({error_ar:"بيانات غير صحيحة"});}
      if(u.is_banned)return res.status(403).json({error_ar:"حسابك محظور: "+u.ban_reason});
      const tok=randTok();
      await Session.create({_id:tok,user_id:u._id,username:u.username,role:u.role,ip:req.ip,ua:(req.headers["user-agent"]||"").slice(0,100)});
      setC(res,tok);await User.findByIdAndUpdate(u._id,{last_active:now()});await logEv("login",{username:u.username});
      return res.json({username:u.username,role:u.role,plan:u.plan||"free",version:VER});
    }
    if(!s.registration_open)return res.status(403).json({error_ar:"التسجيل مغلق"});
    if(await User.countDocuments()>=s.max_users)return res.status(403).json({error_ar:"وصلنا لحد المستخدمين"});
    // Device check — one account per browser
    const did=getDeviceId(req);
    const ex=await User.findOne({device_id:did}).lean();
    if(ex){
      if(ex.is_banned)return res.status(403).json({error_ar:"هذا الجهاز محظور"});
      const tok=randTok();
      await Session.create({_id:tok,user_id:ex._id,username:ex.username,role:ex.role,device_id:did,ip:req.ip,ua:(req.headers["user-agent"]||"").slice(0,100)});
      setC(res,tok);await User.findByIdAndUpdate(ex._id,{last_active:now()});await logEv("device_relogin",{username:ex.username});
      return res.json({username:ex.username,role:ex.role,plan:ex.plan||"free",version:VER,new_user:false});
    }
    // Create new
    const{username:un,password:pw}=genCreds();const id=randId(16);
    await User.create({_id:id,username:un,password_hash:hashPw(pw),device_id:did,ip_registered:req.ip,created:now(),last_active:now(),last_reset:now()});
    const tok=randTok();
    await Session.create({_id:tok,user_id:id,username:un,role:"user",device_id:did,ip:req.ip,ua:(req.headers["user-agent"]||"").slice(0,100)});
    setC(res,tok);await logEv("register",{username:un});
    res.json({username:un,password:pw,role:"user",plan:"free",version:VER,new_user:true});
  }catch(e){console.error("Register:",e);res.status(500).json({error_ar:"خطأ في السيرفر"});}
});

app.post("/api/auth/login",loginLim,async(req,res)=>{
  try{
    const{username,password}=req.body;
    if(!username||!password)return res.status(400).json({error_ar:"أدخل البيانات"});
    const u=await User.findOne({username}).lean();
    if(!u||!verifyPw(password,u.password_hash)){await logEv("failed_login",{username:san(username)});return res.status(401).json({error_ar:"بيانات غير صحيحة"});}
    if(u.is_banned)return res.status(403).json({error_ar:"حسابك محظور: "+u.ban_reason});
    const tok=randTok();
    await Session.create({_id:tok,user_id:u._id,username:u.username,role:u.role,ip:req.ip,ua:(req.headers["user-agent"]||"").slice(0,100)});
    setC(res,tok);await User.findByIdAndUpdate(u._id,{last_active:now()});await logEv("login",{username:u.username});
    res.json({username:u.username,role:u.role,plan:u.plan||"free",version:VER});
  }catch(e){res.status(500).json({error_ar:"خطأ"});}
});

app.post("/api/auth/logout",auth,async(req,res)=>{
  await Session.findByIdAndDelete(req.tok);clrC(res);res.json({ok:true});
});

app.get("/api/me",auth,checkMaint,async(req,res)=>{
  try{
    const u=await User.findById(req.user.user_id).lean();
    if(!u||u.is_banned)return res.status(403).json({error_ar:"غير مصرح"});
    const usage=checkUsage(u);const lim=getLimits(u);
    res.json({
      username:u.username,role:u.role,theme:u.theme,personality:u.personality,lang:u.lang||"ar",
      version:VER,total_msgs:u.total_msgs||0,plan:u.plan||"free",plan_name:usage.plan.name,
      daily_used:usage.msgs.used,daily_limit:usage.msgs.limit,
      images_used:usage.images.used,images_limit:usage.images.limit,
      files_used:usage.files.used,files_limit:usage.files.limit,
      reset_in_hours:Math.round(usage.reset_in*10)/10,
      max_words:lim.max_words,max_file_mb:lim.max_file_mb,
      created:u.created,memory_count:(u.long_memory||[]).length
    });
  }catch(e){res.status(500).json({error_ar:"خطأ"});}
});

app.post("/api/settings",auth,async(req,res)=>{
  const{theme,personality,lang}=req.body;const up={};
  if(["dark","sage","dusk","slate","warm"].includes(theme))up.theme=theme;
  if(["precise","friendly","concise"].includes(personality))up.personality=personality;
  if(["ar","en"].includes(lang))up.lang=lang;
  up.last_active=now();await User.findByIdAndUpdate(req.user.user_id,up);res.json({ok:true});
});

// ── CONVERSATIONS ─────────────────────────────────────────────
app.get("/api/conversations",auth,checkMaint,async(req,res)=>{
  const u=await User.findById(req.user.user_id).select("conversations").lean();
  const list=Object.values(u?.conversations||{}).filter(c=>!c.archived).sort((a,b)=>b.last_msg>a.last_msg?1:-1).slice(0,50);
  res.json({conversations:list});
});
app.post("/api/conversations",auth,checkMaint,async(req,res)=>{
  const id=randId(12);
  const conv={id,title:"محادثة",created:now(),last_msg:now(),messages:[],archived:false};
  await User.findByIdAndUpdate(req.user.user_id,{[`conversations.${id}`]:conv});
  res.json({conv_id:id});
});
app.delete("/api/conversations/:id",auth,async(req,res)=>{
  await User.findByIdAndUpdate(req.user.user_id,{[`conversations.${san(req.params.id)}.archived`]:true});
  res.json({ok:true});
});
app.get("/api/history/:id",auth,async(req,res)=>{
  const u=await User.findById(req.user.user_id).select("conversations").lean();
  const c=u?.conversations?.[san(req.params.id)];
  res.json({messages:(c?.messages||[]).map(m=>({role:m.role,content:m.content,ts:m.ts,has_image:!!m.has_image,deep:!!m.deep}))});
});

// ── MEMORY ────────────────────────────────────────────────────
app.get("/api/memory",auth,async(req,res)=>{
  const u=await User.findById(req.user.user_id).select("memory long_memory").lean();
  res.json({short_memory:u?.memory||{},long_memory:u?.long_memory||[]});
});
app.delete("/api/memory",auth,async(req,res)=>{
  await User.findByIdAndUpdate(req.user.user_id,{memory:{},long_memory:[]});res.json({ok:true});
});

// ── SEARCH HISTORY ────────────────────────────────────────────
app.get("/api/search-history",auth,async(req,res)=>{
  const q=san(req.query.q||"",200);if(q.length<2)return res.json({results:[]});
  const u=await User.findById(req.user.user_id).select("conversations").lean();
  const results=[];
  Object.values(u?.conversations||{}).filter(c=>!c.archived).forEach(conv=>{
    (conv.messages||[]).forEach(m=>{if(m.content?.toLowerCase().includes(q.toLowerCase()))results.push({conv_id:conv.id,conv_title:conv.title,role:m.role,content:m.content.slice(0,200),ts:m.ts});});
  });
  res.json({results:results.slice(0,20)});
});

// ── SHARE ─────────────────────────────────────────────────────
app.post("/api/share/:conv_id",auth,async(req,res)=>{
  const u=await User.findById(req.user.user_id).select("conversations").lean();
  const conv=u?.conversations?.[san(req.params.conv_id)];
  if(!conv)return res.status(404).json({error_ar:"غير موجود"});
  const sid=randId(8);
  await Share.create({_id:sid,title:conv.title,username:req.user.username,messages:(conv.messages||[]).map(m=>({role:m.role,content:m.content,ts:m.ts})),expires:new Date(Date.now()+7*86400000)});
  res.json({share_id:sid,url:"/shared/"+sid});
});
app.get("/api/shared/:id",async(req,res)=>{
  const s=await Share.findById(req.params.id).lean();
  if(!s)return res.status(404).json({error_ar:"الرابط غير صالح"});
  res.json(s);
});
app.get("/shared/:id",(_,res)=>res.sendFile(path.join(__dirname,"../frontend/shared.html")));

// ── REPORT ────────────────────────────────────────────────────
app.post("/api/report",auth,async(req,res)=>{
  const{reason}=req.body;if(!reason||reason.length<5)return res.status(400).json({error_ar:"اذكر السبب"});
  await Report.create({_id:randId(8),reporter:req.user.username,reason:san(reason,500)});
  await logEv("report",{by:req.user.username});res.json({ok:true});
});

// ── STATS ─────────────────────────────────────────────────────
app.get("/api/stats",auth,async(req,res)=>{
  const u=await User.findById(req.user.user_id).lean();if(!u)return res.status(404).json({error_ar:"غير موجود"});
  const usage=checkUsage(u);const convs=Object.values(u.conversations||{}).filter(c=>!c.archived).length;
  const train=await Training.countDocuments({user_id:req.user.user_id});
  res.json({total_msgs:u.total_msgs||0,total_tokens:u.total_tokens||0,conversations:convs,daily_used:usage.msgs.used,daily_limit:usage.msgs.limit,training_pairs:train,memory_count:(u.long_memory||[]).length,version:VER});
});

// ── EXPORT ────────────────────────────────────────────────────
app.get("/api/export/html/:conv_id",auth,async(req,res)=>{
  const u=await User.findById(req.user.user_id).select("conversations").lean();
  const conv=u?.conversations?.[san(req.params.conv_id)];if(!conv)return res.status(404).json({error_ar:"غير موجود"});
  const msgs=(conv.messages||[]).map(m=>`<div style="margin:12px 0;padding:10px 14px;background:${m.role==="user"?"#eef2ff":"#f9fafb"};border-radius:9px;direction:rtl;font-family:Arial"><strong>${m.role==="user"?"أنت":"MedTerm"}</strong><div style="margin-top:5px;white-space:pre-wrap">${(m.content||"").replace(/</g,"&lt;")}</div><small style="color:#999">${m.ts||""}</small></div>`).join("");
  res.setHeader("Content-Type","text/html;charset=utf-8");res.setHeader("Content-Disposition","attachment; filename=chat.html");
  res.send(`<!DOCTYPE html><html dir="rtl"><head><meta charset="UTF-8"/><title>${conv.title}</title></head><body style="max-width:800px;margin:0 auto;padding:20px"><h1 style="color:#3b82f6">${conv.title}</h1>${msgs}</body></html>`);
});

// ── MISTRAL ───────────────────────────────────────────────────
async function webSearch(query){
  try{
    const r=await fetch("https://api.mistral.ai/v1/chat/completions",{
      method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+process.env.MISTRAL_API_KEY},
      body:JSON.stringify({model:"mistral-small-latest",messages:[{role:"system",content:'Return ONLY a JSON array of 5 results: [{"title":"...","url":"https://...","snippet":"..."}]. No extra text.'},{role:"user",content:"Search: "+query}],temperature:0.2,max_tokens:600}),
      signal:AbortSignal.timeout(15000)
    });
    if(!r.ok)return null;
    const d=await r.json();const t=d.choices?.[0]?.message?.content||"";
    const m=t.match(/\[[\s\S]*\]/);return m?JSON.parse(m[0]).slice(0,5):null;
  }catch{return null;}
}

async function generateImage(prompt){
  try{
    const r=await fetch("https://api.mistral.ai/v1/chat/completions",{
      method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+process.env.MISTRAL_API_KEY},
      body:JSON.stringify({model:"mistral-large-latest",messages:[{role:"system",content:"Create a beautiful, colorful, detailed SVG image (512x512) based on the description. Return ONLY the SVG code starting with <svg and ending with </svg>. Use gradients, shapes, and visual elements. Make it artistic and detailed."},{role:"user",content:"Create SVG: "+prompt}],temperature:0.8,max_tokens:2000}),
      signal:AbortSignal.timeout(30000)
    });
    if(!r.ok)return null;
    const d=await r.json();const t=d.choices?.[0]?.message?.content||"";
    const m=t.match(/<svg[\s\S]*<\/svg>/i);
    return m?"data:image/svg+xml;base64,"+Buffer.from(m[0]).toString("base64"):null;
  }catch{return null;}
}

// ── IMAGE GENERATION ──────────────────────────────────────────
app.post("/api/generate-image",auth,chatLim,async(req,res)=>{
  const{prompt}=req.body;if(!prompt)return res.status(400).json({error_ar:"أدخل وصف الصورة"});
  const u=await User.findById(req.user.user_id).lean();if(!u)return res.status(404).json({error_ar:"غير موجود"});
  const usage=checkUsage(u);
  if(!usage.images_ok)return res.status(429).json({error_ar:`وصلت لحد الصور (${usage.images.limit}/يوم). يتجدد بعد ${Math.ceil(usage.reset_in)} ساعة`});
  const img=await generateImage(san(prompt,500));
  if(!img)return res.status(503).json({error_ar:"فشل التوليد، حاول مجدداً"});
  await User.findByIdAndUpdate(req.user.user_id,{$inc:{daily_images_used:1}});
  res.json({image:img});
});

// ── CHAT STREAM ───────────────────────────────────────────────
app.post("/api/chat/stream",auth,checkMaint,chatLim,async(req,res)=>{
  const{conv_id,message,images,documents,use_search,deep}=req.body;
  const msg=san(message||"",8000);const cid=san(conv_id||"",50);
  if(!cid||!msg)return res.status(400).json({error_ar:"بيانات ناقصة"});

  const u=await User.findById(req.user.user_id).lean();
  if(!u||u.is_banned)return res.status(403).json({error_ar:"غير مصرح"});

  const usage=checkUsage(u);const lim=getLimits(u);
  if(msg.length>8000)return res.status(400).json({error_ar:"الرسالة طويلة جداً"});
  const wc=msg.trim().split(/\s+/).filter(Boolean).length;
  if(wc>lim.max_words)return res.status(429).json({error_ar:`تجاوزت حد ${lim.max_words} كلمة`});
  if(u.last_msg_ts&&Date.now()-u.last_msg_ts<1500)return res.status(429).json({error_ar:"انتظر قليلاً"});

  // Subscription message
  if(!usage.msgs_ok){
    const subMsg=`عزيزي المستخدم،\n\nلقد انتهت فترتك التجريبية المجانية.\n\n**✨ اشترك الآن في MedTerm AI**\n\n**مميزات الاشتراك VIP:**\n- 200 رسالة يومياً بدون حدود\n- 50 صورة يومياً\n- بحث دقيق في الإنترنت\n- دعم الملفات والمستندات\n- ذاكرة دائمة وشخصية\n\n**💰 السعر: 5 شيكل فقط / شهر**\nأرخص بـ 20 مرة من باقي الأدوات!\n\n**طرق الدفع:**\nبال باي أو جوال باي\nالرقم: **0597111855**\nباسم: **إياد معروف**\n\nبعد التحويل راسل المهندس نادر:\n📱 [+972 59-385-0520](https://wa.me/972593850520)\n\n_يتجدد حدك المجاني بعد ${Math.ceil(usage.reset_in)} ساعة_`;
    return res.status(429).json({error_ar:subMsg,is_subscription_msg:true,reset_in:usage.reset_in});
  }

  // Auto-create conversation
  let conv=u.conversations?.[cid];
  if(!conv){
    conv={id:cid,title:msg.slice(0,45),created:now(),last_msg:now(),messages:[],archived:false};
    await User.findByIdAndUpdate(req.user.user_id,{[`conversations.${cid}`]:conv});
  }

  // Validate images
  let safeImgs=[];
  if(Array.isArray(images)&&images.length>0){
    if(!usage.images_ok)return res.status(429).json({error_ar:`وصلت لحد الصور (${usage.images.limit}/يوم)`});
    for(const img of images.slice(0,3)){
      if(typeof img!=="string"||!img.startsWith("data:image/"))continue;
      if(img.length*0.75>lim.max_file_mb*1024*1024)continue;
      safeImgs.push(img);
    }
  }

  // Extract docs
  let safeDocs=[];
  if(Array.isArray(documents)&&documents.length>0){
    if(!usage.files_ok)return res.status(429).json({error_ar:`وصلت لحد الملفات (${usage.files.limit}/يوم)`});
    for(const doc of documents.slice(0,3)){
      if(!doc?.data||typeof doc.data!=="string")continue;
      if(doc.data.length*0.75>lim.max_file_mb*1024*1024)continue;
      try{
        const b64=doc.data.includes(",")?doc.data.split(",")[1]:doc.data;
        const buf=Buffer.from(b64,"base64");const name=doc.name||"file";let text=null;
        if(doc.type?.includes("text")||name.match(/\.(txt|md|csv|json|js|py|html|css|xml|sh|sql)$/i)){text=buf.toString("utf8").slice(0,12000);}
        else if(name.match(/\.json$/i)){try{text=JSON.stringify(JSON.parse(buf.toString("utf8")),null,2).slice(0,8000);}catch{text=buf.toString("utf8").slice(0,8000);}}
        else if(name.match(/\.pdf$/i)){
          const raw=buf.toString("latin1");
          const pdfText=(raw.match(/BT[\s\S]*?ET/g)||[]).map(b=>(b.match(/\(([^)]+)\)\s*Tj/g)||[]).map(t=>t.replace(/\(([^)]+)\)\s*Tj/,"$1")).join(" ")).join("\n").replace(/[^\x20-\x7E\u0600-\u06FF\n]/g," ").replace(/\s+/g," ").trim().slice(0,8000);
          text=pdfText.length>50?pdfText:`ملف PDF (${name}) — اسأل عن محتواه`;
        }else{const raw=buf.toString("utf8").replace(/[^\x20-\x7E\u0600-\u06FF\n\t]/g," ").replace(/\s+/g," ").trim();text=raw.length>20?raw.slice(0,8000):null;}
        if(text)safeDocs.push({name,text:`=== ${name} ===\n${text}\n=== نهاية ${name} ===`});
      }catch{}
    }
  }

  // SSE
  res.setHeader("Content-Type","text/event-stream");res.setHeader("Cache-Control","no-cache");res.setHeader("X-Accel-Buffering","no");
  const send=d=>res.write("data: "+JSON.stringify(d)+"\n\n");

  // Web search
  let searchBlock="",searchResults=null;
  if(use_search){
    send({status:u.lang==="en"?"🔍 Searching...":"🔍 جاري البحث..."});
    searchResults=await webSearch(msg);
    if(searchResults?.length){
      searchBlock="\n\n[Search Results]\n"+searchResults.map((r,i)=>`${i+1}. ${r.title}\n${r.snippet}\n${r.url}`).join("\n\n");
      send({status:u.lang==="en"?`✅ ${searchResults.length} results`:`✅ ${searchResults.length} نتائج`});
    }
  }

  // Memory
  const memS=Object.entries(u.memory||{}).map(([k,v])=>k+": "+v).join("\n");
  const memL=(u.long_memory||[]).slice(-8).map(m=>"- "+m).join("\n");
  const memBlock=(memS||memL)?"\n\n[User Memory]\n"+memS+(memL?"\n"+memL:""):"";

  // System prompt
  const lang=u.lang||"ar";
  const SYS={
    precise:{ar:`أنت MedTerm AI، مساعد ذكاء اصطناعي دقيق ومتقدم.\n- ابدأ الإجابة مباشرة بدون مقدمات\n- ردود متوسطة: دقيقة وشاملة وليست طويلة\n- استخدم النقاط والعناوين فقط عند الحاجة\n- دقيق 100% في المعلومات\n- إذا لم تعرف قل ذلك`,en:`You are MedTerm AI, a precise advanced assistant.\n- Start directly, no preamble\n- Medium answers: precise and complete\n- Use bullets/headers only when needed\n- 100% accurate\n- Say when unsure`},
    friendly:{ar:`أنت MedTerm AI، مساعد ذكي وودود.\n- ابدأ مباشرة\n- ردود متوسطة ودقيقة`,en:`You are MedTerm AI, friendly and smart.\n- Start directly\n- Medium, precise answers`},
    concise:{ar:`أنت MedTerm AI مختصر.\n- أجوبة قصيرة ومباشرة\n- النقطة الأساسية فقط`,en:`You are MedTerm AI, concise.\n- Short direct answers\n- Key point only`}
  };
  const pers=SYS[u.personality]||SYS.precise;
  const langI=lang==="en"?"Reply in English.":"رد باللغة العربية.";
  const sysP=(pers[lang]||pers.ar)+"\n"+langI+memBlock+searchBlock+(deep?"\n\nفكّر خطوة بخطوة بشكل مختصر ثم أجب.":"");

  const model=safeImgs.length>0?"pixtral-12b-2409":"mistral-large-latest";
  const history=(conv.messages||[]).slice(-12);
  const msgs=[{role:"system",content:sysP},...history.map(m=>({role:m.role,content:m.content}))];

  if(safeImgs.length>0){
    const parts=[{type:"text",text:msg+(safeDocs.length?"\n\n"+safeDocs.map(d=>d.text).join("\n\n"):"")}];
    safeImgs.forEach(img=>parts.push({type:"image_url",image_url:{url:img}}));
    msgs.push({role:"user",content:parts});
  }else{
    msgs.push({role:"user",content:safeDocs.length?safeDocs.map(d=>d.text).join("\n\n")+"\n\n---\nالسؤال: "+msg:msg});
  }

  send({status:u.lang==="en"?"🤖 Thinking...":"🤖 جاري التفكير..."});

  try{
    const apiRes=await fetch("https://api.mistral.ai/v1/chat/completions",{
      method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+process.env.MISTRAL_API_KEY},
      body:JSON.stringify({model,messages:msgs,temperature:deep?0.2:0.3,max_tokens:lim.max_tokens,stream:true}),
      signal:AbortSignal.timeout(90000)
    });
    if(!apiRes.ok){const e=await apiRes.json().catch(()=>({}));send({error:e.message||"Mistral error"});return res.end();}

    let full="";
    for await(const chunk of apiRes.body){
      for(const line of chunk.toString().split("\n").filter(l=>l.startsWith("data: "))){
        const raw=line.slice(6).trim();if(raw==="[DONE]")continue;
        try{const j=JSON.parse(raw);const d=j.choices?.[0]?.delta?.content||"";if(d){full+=d;send({delta:d});}}catch{}
      }
    }

    const tokens=Math.ceil((msg.length+full.length)/3);
    const up={[`conversations.${cid}.messages`]:[...(conv.messages||[]),{role:"user",content:msg,has_image:safeImgs.length>0,ts:now()},{role:"assistant",content:full,tokens,model,deep:!!deep,ts:now()}],[`conversations.${cid}.last_msg`]:now(),[`conversations.${cid}.title`]:conv.messages?.length===0?msg.slice(0,45):conv.title,last_active:now(),last_msg_ts:Date.now(),$inc:{total_msgs:1,total_tokens:tokens,daily_msgs_used:1,...(safeImgs.length>0?{daily_images_used:safeImgs.length}:{}),...(safeDocs.length>0?{daily_files_used:safeDocs.length}:{})}};

    // Memory extraction
    const memP=[{r:/my name is (\w+)/i,k:"name"},{r:/اسمي\s+([\u0600-\u06FF\w]+)/,k:"name"},{r:/i(?:'m| am) from ([\w\s]+)/i,k:"country"},{r:/(?:أنا من|من)\s+([\u0600-\u06FF\w]+)/,k:"country"},{r:/i(?:'m| am) (\d+) years/i,k:"age"},{r:/عمري\s+(\d+)/,k:"age"}];
    memP.forEach(({r,k})=>{const m=msg.match(r);if(m)up[`memory.${k}`]=san(m[1],50);});

    // Long memory
    const uFresh=await User.findById(req.user.user_id).lean();
    if(msg.length>30&&full.length>80){
      const lm=[...(uFresh?.long_memory||[]),`[${new Date().toLocaleDateString()}] ${msg.slice(0,60)} → ${full.slice(0,100)}`].slice(-50);
      up.long_memory=lm;
    }
    await User.findByIdAndUpdate(req.user.user_id,up);
    await Training.create({user_id:req.user.user_id,username:req.user.username,user_msg:msg,assistant_msg:full,model,tokens,deep:!!deep,lang});
    await logEv("chat",{username:req.user.username,tokens});
    send({done:true,tokens,sources:searchResults?.map(r=>({title:r.title,url:r.url}))});res.end();
  }catch(e){send({error:e.name==="TimeoutError"?"انتهت المهلة":"خطأ في الاتصال"});res.end();}
});

// ── SUPERADMIN ────────────────────────────────────────────────
const ADMIN_USER=process.env.ADMIN_USER||"medterm_admin";
const ADMIN_PASS=process.env.ADMIN_PASS||"change_me";
const adminToks=new Map();

app.post("/api/superadmin/login",loginLim,(req,res)=>{
  const{username,password}=req.body;
  if(username!==ADMIN_USER||password!==ADMIN_PASS){console.log("SUPERADMIN_FAIL",req.ip);return res.status(401).json({error:"Invalid"});}
  const tok=randTok();adminToks.set(tok,Date.now());setTimeout(()=>adminToks.delete(tok),3600000);
  res.json({token:tok});
});
function adminAuth(req,res,next){
  const tok=req.headers["x-admin-token"];const t=tok&&adminToks.get(tok);
  if(!t||Date.now()-t>3600000){adminToks.delete(tok);return res.status(401).json({error:"Not authenticated"});}
  next();
}

app.get("/api/superadmin/data",adminAuth,async(req,res)=>{
  const s=await getSettings();
  const users=await User.find({}).select("-conversations -memory -long_memory -password_hash").lean();
  const totalMsgs=users.reduce((a,u)=>a+(u.total_msgs||0),0);
  const totalTokens=users.reduce((a,u)=>a+(u.total_tokens||0),0);
  const today=new Date().toISOString().slice(0,10);
  const act=await Training.aggregate([{$group:{_id:{$dateToString:{format:"%Y-%m-%d",date:"$ts"}},count:{$sum:1}}},{$sort:{_id:1}},{$limit:14}]);
  const reports=await Report.find({}).sort({ts:-1}).limit(30).lean();
  const events=await Event.find({}).sort({ts:-1}).limit(50).lean();
  res.json({
    overview:{totalUsers:users.length,totalMsgs,totalTokens,totalTraining:await Training.countDocuments(),activeToday:users.filter(u=>u.last_active?.slice(0,10)===today).length,bannedCount:users.filter(u=>u.is_banned).length,todayUsage:users.reduce((a,u)=>a+(u.last_reset?.slice(0,10)===today?u.daily_msgs_used||0:0),0),pendingReports:reports.filter(r=>r.status==="pending").length,settings:s},
    users:users.map(u=>({id:u._id,username:u.username,role:u.role,plan:u.plan||"free",total_msgs:u.total_msgs||0,total_tokens:u.total_tokens||0,daily_used:u.daily_msgs_used||0,daily_limit:getLimits(u).daily_msgs,is_banned:u.is_banned||false,ban_reason:u.ban_reason||"",created:u.created,last_active:u.last_active,custom_daily_msgs:u.custom_daily_msgs,custom_max_words:u.custom_max_words,notes:u.notes||""})),
    activity:act.map(a=>({day:a._id,count:a.count})),reports,events
  });
});

app.put("/api/superadmin/user/:username",adminAuth,async(req,res)=>{
  const{role,plan,is_banned,ban_reason,custom_daily_msgs,custom_max_words,reset_limit,notes}=req.body;
  const up={};
  if(role&&["user","admin"].includes(role))up.role=role;
  if(plan&&["free","pro"].includes(plan))up.plan=plan;
  if(typeof is_banned==="boolean")up.is_banned=is_banned;
  if(ban_reason!==undefined)up.ban_reason=san(ban_reason,200);
  if(custom_daily_msgs!==undefined)up.custom_daily_msgs=custom_daily_msgs===null?null:parseInt(custom_daily_msgs)||null;
  if(custom_max_words!==undefined)up.custom_max_words=custom_max_words===null?null:parseInt(custom_max_words)||null;
  if(notes!==undefined)up.notes=san(notes,500);
  if(reset_limit){up.daily_msgs_used=0;up.daily_images_used=0;up.daily_files_used=0;up.last_reset=now();}
  await User.findOneAndUpdate({username:req.params.username},up);
  await logEv("superadmin_update",{target:req.params.username});res.json({ok:true});
});

app.delete("/api/superadmin/user/:username",adminAuth,async(req,res)=>{
  const u=await User.findOne({username:req.params.username});if(!u)return res.status(404).json({error:"Not found"});
  await Session.deleteMany({user_id:u._id});await User.findByIdAndDelete(u._id);
  await logEv("superadmin_delete",{target:req.params.username});res.json({ok:true});
});

app.put("/api/superadmin/settings",adminAuth,async(req,res)=>{
  const{max_users,registration_open,default_daily_msgs,default_max_words,maintenance_mode,maintenance_msg}=req.body;
  const up={};
  if(max_users!==undefined)up.max_users=parseInt(max_users)||100;
  if(registration_open!==undefined)up.registration_open=!!registration_open;
  if(default_daily_msgs!==undefined)up.default_daily_msgs=parseInt(default_daily_msgs)||20;
  if(default_max_words!==undefined)up.default_max_words=parseInt(default_max_words)||400;
  if(maintenance_mode!==undefined)up.maintenance_mode=!!maintenance_mode;
  if(maintenance_msg!==undefined)up.maintenance_msg=san(maintenance_msg,200);
  await Settings.findByIdAndUpdate("global",up,{upsert:true});
  await logEv("settings_update",req.body);res.json({ok:true});
});

app.put("/api/superadmin/reports/:id",adminAuth,async(req,res)=>{
  await Report.findByIdAndUpdate(req.params.id,{status:req.body.status||"resolved"});res.json({ok:true});
});

app.get("/api/superadmin/export",adminAuth,async(req,res)=>{
  const tr=await Training.find({}).lean();
  const jsonl=tr.map(r=>JSON.stringify({messages:[{role:"system",content:"You are MedTerm AI."},{role:"user",content:r.user_msg},{role:"assistant",content:r.assistant_msg}]})).join("\n");
  res.setHeader("Content-Type","application/jsonl");res.setHeader("Content-Disposition","attachment; filename=training.jsonl");res.send(jsonl);
});

app.get("/dashboard",(_,res)=>res.sendFile(path.join(__dirname,"../frontend/dashboard.html")));
app.get("*",(_,res)=>res.sendFile(path.join(__dirname,"../frontend/index.html")));
app.listen(PORT,()=>console.log(`\nMedTerm v${VER} → http://localhost:${PORT}\n`));
