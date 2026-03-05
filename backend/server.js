/**
 * Schoolify — Node.js Backend
 * ─────────────────────────────────────────────
 * Stack: Express · JWT · bcrypt · lowdb (JSON file DB)
 *
 * Setup:
 *   npm install express jsonwebtoken bcryptjs cors uuid lowdb
 *   node server.js
 *
 * Runs on: http://localhost:3001
 */

const express  = require("express");
const jwt      = require("jsonwebtoken");
const bcrypt   = require("bcryptjs");
const cors     = require("cors");
const { v4: uuid } = require("uuid");
const fs       = require("fs");
const path     = require("path");

const app    = express();
const PORT   = 3001;
const SECRET = process.env.JWT_SECRET || "schoolify_dev_secret_change_in_prod";

app.use(cors({ origin: "*" }));
app.use(express.json());

// ── Lightweight JSON DB ───────────────────────────────────────────────────────
const DB_PATH = path.join(__dirname, "db.json");

const defaultDB = { users: [], profiles: [], academicData: [] };

const readDB  = () => {
  if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify(defaultDB, null, 2));
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
};
const writeDB = (data) => fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));

// ── Auth Middleware ───────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────

// POST /auth/signup
app.post("/auth/signup", async (req, res) => {
  const { email, password, firstName, lastName, role = "student", parentEmail } = req.body;
  if (!email || !password || !firstName) return res.status(400).json({ error: "Missing fields" });

  const db = readDB();
  if (db.users.find(u => u.email === email))
    return res.status(409).json({ error: "Email already registered" });

  const hashed = await bcrypt.hash(password, 10);
  const userId = uuid();

  const user = { id: userId, email, password: hashed, firstName, lastName, role, createdAt: new Date().toISOString() };
  const profile = {
    userId,
    firstName, lastName, email, role,
    avatar: null,
    school: "",
    grade: "",
    graduationYear: "",
    parentEmail: parentEmail || null,
    province: "Ontario",
    targetUniversities: [],
    notifications: { gradeAlerts: true, weeklyReport: true, upcomingExams: true },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  const academicData = {
    userId,
    years: {},
    studyPlans: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.users.push(user);
  db.profiles.push(profile);
  db.academicData.push(academicData);
  writeDB(db);

  const token = jwt.sign({ userId, email, role }, SECRET, { expiresIn: "30d" });
  res.json({ token, profile, message: "Account created" });
});

// POST /auth/login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });

  const profile = db.profiles.find(p => p.userId === user.id);
  const token = jwt.sign({ userId: user.id, email, role: user.role }, SECRET, { expiresIn: "30d" });
  res.json({ token, profile });
});

// POST /auth/refresh
app.post("/auth/refresh", auth, (req, res) => {
  const db = readDB();
  const profile = db.profiles.find(p => p.userId === req.user.userId);
  if (!profile) return res.status(404).json({ error: "User not found" });
  res.json({ profile });
});

// ── PROFILE ROUTES ────────────────────────────────────────────────────────────

// GET /profile
app.get("/profile", auth, (req, res) => {
  const db = readDB();
  const profile = db.profiles.find(p => p.userId === req.user.userId);
  if (!profile) return res.status(404).json({ error: "Profile not found" });
  res.json(profile);
});

// PUT /profile
app.put("/profile", auth, (req, res) => {
  const db = readDB();
  const idx = db.profiles.findIndex(p => p.userId === req.user.userId);
  if (idx === -1) return res.status(404).json({ error: "Profile not found" });

  const allowed = ["firstName","lastName","school","grade","graduationYear","province","targetUniversities","notifications","avatar","parentEmail"];
  const updates = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)));
  db.profiles[idx] = { ...db.profiles[idx], ...updates, updatedAt: new Date().toISOString() };
  writeDB(db);
  res.json(db.profiles[idx]);
});

// ── ACADEMIC DATA ROUTES ──────────────────────────────────────────────────────

// GET /academic
app.get("/academic", auth, (req, res) => {
  const db = readDB();
  const data = db.academicData.find(d => d.userId === req.user.userId);
  if (!data) return res.status(404).json({ error: "Not found" });
  res.json(data);
});

// PUT /academic/years  — full year map replace
app.put("/academic/years", auth, (req, res) => {
  const db = readDB();
  const idx = db.academicData.findIndex(d => d.userId === req.user.userId);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  db.academicData[idx].years = req.body.years;
  db.academicData[idx].updatedAt = new Date().toISOString();
  writeDB(db);
  res.json({ ok: true });
});

// POST /academic/year  — add a single new year
app.post("/academic/year", auth, (req, res) => {
  const { key, label } = req.body;
  if (!key || !label) return res.status(400).json({ error: "key and label required" });
  const db = readDB();
  const idx = db.academicData.findIndex(d => d.userId === req.user.userId);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  if (db.academicData[idx].years[key]) return res.status(409).json({ error: "Year already exists" });
  db.academicData[idx].years[key] = { label, current: false, courses: [] };
  db.academicData[idx].updatedAt = new Date().toISOString();
  writeDB(db);
  res.json(db.academicData[idx].years[key]);
});

// DELETE /academic/year/:key
app.delete("/academic/year/:key", auth, (req, res) => {
  const db = readDB();
  const idx = db.academicData.findIndex(d => d.userId === req.user.userId);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  delete db.academicData[idx].years[req.params.key];
  db.academicData[idx].updatedAt = new Date().toISOString();
  writeDB(db);
  res.json({ ok: true });
});

// POST /academic/study-plan  — save a generated plan
app.post("/academic/study-plan", auth, (req, res) => {
  const db = readDB();
  const idx = db.academicData.findIndex(d => d.userId === req.user.userId);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  const plan = { id: uuid(), ...req.body, createdAt: new Date().toISOString() };
  db.academicData[idx].studyPlans.unshift(plan);
  db.academicData[idx].studyPlans = db.academicData[idx].studyPlans.slice(0, 20); // keep last 20
  db.academicData[idx].updatedAt = new Date().toISOString();
  writeDB(db);
  res.json(plan);
});

// GET /academic/study-plans
app.get("/academic/study-plans", auth, (req, res) => {
  const db = readDB();
  const data = db.academicData.find(d => d.userId === req.user.userId);
  if (!data) return res.status(404).json({ error: "Not found" });
  res.json(data.studyPlans || []);
});

// ── PARENT ROUTES ─────────────────────────────────────────────────────────────

// GET /parent/children  — get all students linked to this parent email
app.get("/parent/children", auth, (req, res) => {
  const db = readDB();
  const parentProfile = db.profiles.find(p => p.userId === req.user.userId);
  if (!parentProfile || parentProfile.role !== "parent")
    return res.status(403).json({ error: "Parent access only" });

  const children = db.profiles.filter(p => p.parentEmail === parentProfile.email);
  const result = children.map(child => {
    const academic = db.academicData.find(d => d.userId === child.userId);
    return { profile: child, academic: academic || null };
  });
  res.json(result);
});

// ── ADMIN ROUTES ──────────────────────────────────────────────────────────────

// GET /admin/users  — list all users (admin only)
app.get("/admin/users", auth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const db = readDB();
  const users = db.profiles.map(p => ({
    ...p,
    academicYears: Object.keys(db.academicData.find(d => d.userId === p.userId)?.years || {}).length
  }));
  res.json(users);
});

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({ status: "ok", time: new Date().toISOString() }));

app.listen(PORT, () => console.log(`Schoolify API running on http://localhost:${PORT}`));
