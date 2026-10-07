import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";

const app = express();
const db = new Database("skilldz.db");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

if (
  !JWT_SECRET ||
  JWT_SECRET === "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
) {
  console.warn("Set a strong JWT_SECRET in .env before production.");
}

/* =========================
   DATABASE
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS courses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  price_da INTEGER NOT NULL,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  course_id INTEGER NOT NULL,
  amount_da INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  provider TEXT DEFAULT 'edahabia',
  provider_reference TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrollments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  course_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, course_id)
);
`);

/* =========================
   DEFAULT COURSE
========================= */

if (
  db.prepare("SELECT COUNT(*) n FROM courses").get().n === 0
) {
  db.prepare(
    "INSERT INTO courses(title,price_da,description) VALUES(?,?,?)"
  ).run(
    "Lancer son e-commerce en Algérie",
    4900,
    "De l'idée à la première vente."
  );
}

/* =========================
   AUTHENTICATION
========================= */

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: "Authentification requise."
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Session invalide."
    });
  }
}

/* =========================
   HEALTH
========================= */

app.get("/api/health", (_, res) => {
  res.json({
    ok: true,
    service: "SkillDZ API"
  });
});

/* =========================
   COURSES
========================= */

app.get("/api/courses", (_, res) => {
  const courses = db
    .prepare(
      "SELECT id,title,price_da,description FROM courses"
    )
    .all();

  res.json(courses);
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body || {};

  if (
    !name ||
    !email ||
    !password ||
    password.length < 8
  ) {
    return res.status(400).json({
      error:
        "Nom, email et mot de passe (8 caractères minimum) requis."
    });
  }

  try {
    const hash = await bcrypt.hash(password, 12);

    const cleanEmail = email.trim().toLowerCase();

    const result = db
      .prepare(
        "INSERT INTO users(name,email,password_hash) VALUES(?,?,?)"
      )
      .run(
        name.trim(),
        cleanEmail,
        hash
      );

    const token = jwt.sign(
      {
        id: result.lastInsertRowid,
        email: cleanEmail
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.status(201).json({
      token
    });

  } catch {
    res.status(409).json({
      error: "Cet email est déjà utilisé."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};

  const user = db
    .prepare("SELECT * FROM users WHERE email=?")
    .get(
      String(email || "")
        .trim()
        .toLowerCase()
    );

  if (
    !user ||
    !(await bcrypt.compare(
      password || "",
      user.password_hash
    ))
  ) {
    return res.status(401).json({
      error: "Email ou mot de passe incorrect."
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );

  res.json({
    token
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, (req, res) => {
  const user = db
    .prepare(
      "SELECT id,name,email FROM users WHERE id=?"
    )
    .get(req.user.id);

  res.json(user);
});

/* =========================
   CREATE ORDER
========================= */

app.post("/api/orders", auth, (req, res) => {
  const course = db
    .prepare("SELECT * FROM courses WHERE id=?")
    .get(Number(req.body?.course_id));

  if (!course) {
    return res.status(404).json({
      error: "Formation introuvable."
    });
  }

  const result = db
    .prepare(
      `INSERT INTO orders
      (user_id,course_id,amount_da,status,provider)
      VALUES(?,?,?,?,?)`
    )
    .run(
      req.user.id,
      course.id,
      course.price_da,
      "pending",
      "edahabia"
    );

  res.status(201).json({
    order_id: result.lastInsertRowid,
    status: "pending",
    provider: "edahabia",
    amount_da: course.price_da
  });
});

/* =========================
   MY COURSES
========================= */

app.get("/api/my-courses", auth, (req, res) => {
  const courses = db
    .prepare(
      `SELECT
        c.id,
        c.title,
        c.price_da,
        c.description,
        e.created_at
      FROM enrollments e
      JOIN courses c
        ON c.id = e.course_id
      WHERE e.user_id=?`
    )
    .all(req.user.id);

  res.json(courses);
});

/* =========================
   CHECK COURSE ACCESS
========================= */

app.get(
  "/api/courses/:courseId/access",
  auth,
  (req, res) => {
    const courseId = Number(req.params.courseId);

    const course = db
      .prepare("SELECT id,title FROM courses WHERE id=?")
      .get(courseId);

    if (!course) {
      return res.status(404).json({
        error: "Formation introuvable."
      });
    }

    const enrollment = db
      .prepare(
        `SELECT id
         FROM enrollments
         WHERE user_id=?
         AND course_id=?`
      )
      .get(
        req.user.id,
        courseId
      );

    res.json({
      course_id: courseId,
      has_access: Boolean(enrollment)
    });
  }
);

/* =========================
   PAYMENT WEBHOOK
========================= */

/*
  IMPORTANT :
  L'inscription à une formation ne doit être créée
  qu'après confirmation réelle du paiement.

  Le webhook Edahabia officiel sera connecté ici
  plus tard.
*/

app.post(
  "/api/payment/webhook",
  (_, res) => {
    res.status(501).json({
      error: "Webhook Edahabia non configuré.",
      message:
        "Connecter ici les paramètres marchands officiels après validation."
    });
  }
);

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log(
    "SkillDZ API listening on port " + PORT
  );
});
