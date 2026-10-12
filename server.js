
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
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "")
  .trim()
  .toLowerCase();

app.use(cors());
app.use(express.json({ limit: "100kb" }));

if (!JWT_SECRET || JWT_SECRET === "CHANGE_ME_TO_A_LONG_RANDOM_SECRET") {
  throw new Error("Configure un JWT_SECRET fort dans Render.");
}

/* =========================
   DATABASE
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  price_da INTEGER NOT NULL,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  course_id INTEGER NOT NULL,
  amount_da INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  provider TEXT DEFAULT 'edahabia',
  provider_reference TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrollments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  course_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, course_id)
);
`);

// Migration : ajoute role aux anciennes bases de données.
const userColumns = db.prepare("PRAGMA table_info(users)").all();

if (!userColumns.some((column) => column.name === "role")) {
  db.exec(
    "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"
  );
}

// L'adresse définie dans ADMIN_EMAIL est la référence administrateur.
if (ADMIN_EMAIL) {
  db.prepare("UPDATE users SET role = 'user' WHERE role = 'admin'").run();

  db.prepare(
    "UPDATE users SET role = 'admin' WHERE lower(email) = ?"
  ).run(ADMIN_EMAIL);
}

/* =========================
   DEFAULT COURSE
========================= */

if (db.prepare("SELECT COUNT(*) AS n FROM courses").get().n === 0) {
  db.prepare(
    "INSERT INTO courses(title, price_da, description) VALUES (?, ?, ?)"
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
      error: "Session invalide ou expirée."
    });
  }
}

// Vérifie le rôle actuel dans la base, pas dans le token.
function requireAdmin(req, res, next) {
  const user = db.prepare(
    "SELECT role FROM users WHERE id = ?"
  ).get(req.user.id);

  if (!user || user.role !== "admin") {
    return res.status(403).json({
      error: "Accès réservé à l'administrateur."
    });
  }

  next();
}

function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function validateCourse(body) {
  const title = typeof body?.title === "string"
    ? body.title.trim()
    : "";

  const description = typeof body?.description === "string"
    ? body.description.trim()
    : "";

  const price = Number(body?.price_da);

  if (
    !title ||
    title.length > 200 ||
    !description ||
    description.length > 10000 ||
    !Number.isSafeInteger(price) ||
    price < 0
  ) {
    return {
      error: "Titre, description ou prix invalide."
    };
  }

  return {
    course: {
      title,
      description,
      price_da: price
    }
  };
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
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body || {};

  if (
    typeof name !== "string" ||
    typeof email !== "string" ||
    typeof password !== "string" ||
    !name.trim() ||
    name.trim().length > 100 ||
    email.trim().length > 254 ||
    password.length < 8 ||
    password.length > 200
  ) {
    return res.status(400).json({
      error: "Nom, email valide et mot de passe de 8 caractères minimum requis."
    });
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (name, email, password_hash)
      VALUES (?, ?, ?)
    `).run(name.trim(), cleanEmail, hash);

    res.status(201).json({
      token: createToken({
        id: Number(result.lastInsertRowid),
        email: cleanEmail
      })
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "Cet email est déjà utilisé."
      });
    }

    console.error("Erreur inscription :", error);
    res.status(500).json({
      error: "Erreur lors de l'inscription."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  const email = typeof req.body?.email === "string"
    ? req.body.email.trim().toLowerCase()
    : "";

  const password = typeof req.body?.password === "string"
    ? req.body.password
    : "";

  const user = db.prepare(
    "SELECT * FROM users WHERE email = ?"
  ).get(email);

  if (
    !user ||
    !(await bcrypt.compare(password, user.password_hash))
  ) {
    return res.status(401).json({
      error: "Email ou mot de passe incorrect."
    });
  }

  res.json({
    token: createToken(user)
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, (req, res) => {
  const user = db.prepare(`
    SELECT id, name, email, role
    FROM users
    WHERE id = ?
  `).get(req.user.id);

  if (!user) {
    return res.status(404).json({
      error: "Utilisateur introuvable."
    });
  }

  res.json(user);
});

/* =========================
   PUBLIC COURSES
========================= */

app.get("/api/courses", (_, res) => {
  const courses = db.prepare(`
    SELECT id, title, price_da, description
    FROM courses
    ORDER BY id DESC
  `).all();

  res.json(courses);
});

/* =========================
   ADMIN: LIST COURSES
========================= */

app.get("/api/admin/courses", auth, requireAdmin, (_, res) => {
  res.json(
    db.prepare(`
      SELECT id, title, price_da, description
      FROM courses
      ORDER BY id DESC
    `).all()
  );
});

/* =========================
   ADMIN: CREATE COURSE
========================= */

app.post("/api/admin/courses", auth, requireAdmin, (req, res) => {
  const result = validateCourse(req.body);

  if (result.error) {
    return res.status(400).json({ error: result.error });
  }

  const { title, price_da, description } = result.course;

  const created = db.prepare(`
    INSERT INTO courses (title, price_da, description)
    VALUES (?, ?, ?)
  `).run(title, price_da, description);

  res.status(201).json({
    id: Number(created.lastInsertRowid),
    title,
    price_da,
    description
  });
});

/* =========================
   ADMIN: UPDATE COURSE
========================= */

app.put("/api/admin/courses/:id", auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({
      error: "Identifiant de formation invalide."
    });
  }

  const existing = db.prepare(
    "SELECT id FROM courses WHERE id = ?"
  ).get(id);

  if (!existing) {
    return res.status(404).json({
      error: "Formation introuvable."
    });
  }

  const result = validateCourse(req.body);

  if (result.error) {
    return res.status(400).json({ error: result.error });
  }

  const { title, price_da, description } = result.course;

  db.prepare(`
    UPDATE courses
    SET title = ?, price_da = ?, description = ?
    WHERE id = ?
  `).run(title, price_da, description, id);

  res.json({
    id,
    title,
    price_da,
    description
  });
});

/* =========================
   ADMIN: DELETE COURSE
========================= */

app.delete("/api/admin/courses/:id", auth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({
      error: "Identifiant de formation invalide."
    });
  }

  const course = db.prepare(
    "SELECT id FROM courses WHERE id = ?"
  ).get(id);

  if (!course) {
    return res.status(404).json({
      error: "Formation introuvable."
    });
  }

  const references = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM orders WHERE course_id = ?) AS orders_count,
      (SELECT COUNT(*) FROM enrollments WHERE course_id = ?) AS enrollments_count
  `).get(id, id);

  if (references.orders_count > 0 || references.enrollments_count > 0) {
    return res.status(409).json({
      error: "Cette formation est liée à des commandes ou des inscriptions. Elle ne peut pas être supprimée."
    });
  }

  db.prepare("DELETE FROM courses WHERE id = ?").run(id);

  res.json({ ok: true, message: "Formation supprimée." });
});

/* =========================
   CREATE ORDER
========================= */

app.post("/api/orders", auth, (req, res) => {
  const courseId = Number(req.body?.course_id);

  if (!Number.isSafeInteger(courseId) || courseId < 1) {
    return res.status(400).json({
      error: "Identifiant de formation invalide."
    });
  }

  const course = db.prepare(
    "SELECT id, price_da FROM courses WHERE id = ?"
  ).get(courseId);

  if (!course) {
    return res.status(404).json({
      error: "Formation introuvable."
    });
  }

  const result = db.prepare(`
    INSERT INTO orders
      (user_id, course_id, amount_da, status, provider)
    VALUES (?, ?, ?, ?, ?)
  `).run(req.user.id, course.id, course.price_da, "pending", "edahabia");

  res.status(201).json({
    order_id: Number(result.lastInsertRowid),
    status: "pending",
    provider: "edahabia",
    amount_da: course.price_da
  });
});

/* =========================
   MY COURSES
========================= */

app.get("/api/my-courses", auth, (req, res) => {
  const courses = db.prepare(`
    SELECT c.id, c.title, c.price_da, c.description, e.created_at
    FROM enrollments e
    JOIN courses c ON c.id = e.course_id
    WHERE e.user_id = ?
  `).all(req.user.id);

  res.json(courses);
});

/* =========================
   CHECK COURSE ACCESS
========================= */

app.get("/api/courses/:courseId/access", auth, (req, res) => {
  const courseId = Number(req.params.courseId);

  const course = db.prepare(
    "SELECT id FROM courses WHERE id = ?"
  ).get(courseId);

  if (!course) {
    return res.status(404).json({
      error: "Formation introuvable."
    });
  }

  const enrollment = db.prepare(`
    SELECT id FROM enrollments
    WHERE user_id = ? AND course_id = ?
  `).get(req.user.id, courseId);

  res.json({
    course_id: courseId,
    has_access: Boolean(enrollment)
  });
});

/* =========================
   TEMPORARY TEST ACCESS
========================= */

app.post("/api/test-access", auth, (req, res) => {
  if (
    !process.env.TEST_ACCESS_KEY ||
    req.headers["x-test-access-key"] !== process.env.TEST_ACCESS_KEY
  ) {
    return res.status(403).json({
      error: "Accès de test refusé."
    });
  }

  const courseId = Number(req.body?.course_id);

  const course = db.prepare(
    "SELECT id FROM courses WHERE id = ?"
  ).get(courseId);

  if (!course) {
    return res.status(404).json({
      error: "Formation introuvable."
    });
  }

  db.prepare(`
    INSERT OR IGNORE INTO enrollments (user_id, course_id)
    VALUES (?, ?)
  `).run(req.user.id, courseId);

  res.json({
    ok: true,
    message: "Accès de test activé."
  });
});

/* =========================
   PAYMENT WEBHOOK
========================= */

// Aucun paiement réel n'est confirmé par cette route.
app.post("/api/payment/webhook", (_, res) => {
  res.status(501).json({
    error: "Webhook Edahabia non configuré.",
    message: "Connecter le système marchand officiel avant d'activer les paiements."
  });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log("SkillDZ API listening on port " + PORT);
});
