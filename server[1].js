import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";

const app=express(), db=new Database("skilldz.db");
const PORT=Number(process.env.PORT||3000), JWT_SECRET=process.env.JWT_SECRET;
app.use(cors()); app.use(express.json());
if(!JWT_SECRET || JWT_SECRET==="CHANGE_ME_TO_A_LONG_RANDOM_SECRET") console.warn("Set a strong JWT_SECRET in .env before production.");

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS courses(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,price_da INTEGER NOT NULL,description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,course_id INTEGER NOT NULL,amount_da INTEGER NOT NULL,status TEXT DEFAULT 'pending',provider TEXT DEFAULT 'edahabia',provider_reference TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS enrollments(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,course_id INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,course_id));
`);
if(db.prepare("SELECT COUNT(*) n FROM courses").get().n===0)
 db.prepare("INSERT INTO courses(title,price_da,description) VALUES(?,?,?)").run("Lancer son e-commerce en Algérie",4900,"De l'idée à la première vente.");

function auth(req,res,next){
 const h=req.headers.authorization||"", t=h.startsWith("Bearer ")?h.slice(7):null;
 if(!t)return res.status(401).json({error:"Authentification requise."});
 try{req.user=jwt.verify(t,JWT_SECRET);next()}catch{return res.status(401).json({error:"Session invalide."})}
}
app.get("/api/health",(_,res)=>res.json({ok:true,service:"SkillDZ API"}));
app.get("/api/courses",(_,res)=>res.json(db.prepare("SELECT id,title,price_da,description FROM courses").all()));

app.post("/api/register",async(req,res)=>{
 const {name,email,password}=req.body||{};
 if(!name||!email||!password||password.length<8)return res.status(400).json({error:"Nom, email et mot de passe (8 caractères minimum) requis."});
 try{
  const hash=await bcrypt.hash(password,12);
  const r=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name.trim(),email.trim().toLowerCase(),hash);
  res.status(201).json({token:jwt.sign({id:r.lastInsertRowid,email:email.trim().toLowerCase()},JWT_SECRET,{expiresIn:"7d"})});
 }catch{res.status(409).json({error:"Cet email est déjà utilisé."})}
});

app.post("/api/login",async(req,res)=>{
 const {email,password}=req.body||{},u=db.prepare("SELECT * FROM users WHERE email=?").get(String(email||"").trim().toLowerCase());
 if(!u||!(await bcrypt.compare(password||"",u.password_hash)))return res.status(401).json({error:"Email ou mot de passe incorrect."});
 res.json({token:jwt.sign({id:u.id,email:u.email},JWT_SECRET,{expiresIn:"7d"})});
});

app.get("/api/me",auth,(req,res)=>res.json(db.prepare("SELECT id,name,email FROM users WHERE id=?").get(req.user.id)));

app.post("/api/orders",auth,(req,res)=>{
 const c=db.prepare("SELECT * FROM courses WHERE id=?").get(Number(req.body?.course_id));
 if(!c)return res.status(404).json({error:"Formation introuvable."});
 const r=db.prepare("INSERT INTO orders(user_id,course_id,amount_da,status,provider) VALUES(?,?,?,?,?)").run(req.user.id,c.id,c.price_da,"pending","edahabia");
 res.status(201).json({order_id:r.lastInsertRowid,status:"pending",provider:"edahabia",amount_da:c.price_da});
});

app.get("/api/my-courses",auth,(req,res)=>res.json(db.prepare("SELECT c.id,c.title,c.price_da,e.created_at FROM enrollments e JOIN courses c ON c.id=e.course_id WHERE e.user_id=?").all(req.user.id)));

/* Placeholder: only the official provider-specific, authenticated webhook may mark an order paid. */
app.post("/api/payment/webhook",(_,res)=>res.status(501).json({error:"Webhook Edahabia non configuré.",message:"Connecter ici les paramètres marchands officiels après validation."}));

app.listen(PORT,()=>console.log("SkillDZ API listening on port "+PORT));
