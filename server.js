const express = require("express");
const Database = require("better-sqlite3");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static("public"));

// --- SQLite DB ---
const db = new Database("./users.db");
console.log("Connected to SQLite DB");

// --- Helper for YYYY-MM-DD ---
function getSimpleDate(date = new Date()) {
  return date.toISOString().split("T")[0];
}

// --- Tables ---
db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT UNIQUE,
    activeSession INTEGER DEFAULT 0,
    lastLogin TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY,
    userId INTEGER,
    planType TEXT,
    startDate TEXT,
    endDate TEXT,
    status TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS renewal_requests (
    id INTEGER PRIMARY KEY,
    userId INTEGER,
    planType TEXT,
    requestDate TEXT,
    status TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
)`).run();

// default admin
db.prepare(`INSERT OR IGNORE INTO admins (username,password) VALUES (?,?)`)
  .run("jay", "3911");
console.log("Default admin ensured: jay / 3911");

// --- Generate session token ---
function generateToken() {
  return crypto.randomBytes(16).toString("hex");
}

// --- In-memory sessions ---
const sessions = {};

// --- Auto logout at midnight ---
function scheduleMidnightLogout() {
  const now = new Date();
  const nextMidnight = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate() + 1,
    0,0,0,0
  );
  const msUntilMidnight = nextMidnight - now;

  setTimeout(() => {
    db.prepare(`UPDATE users SET activeSession=0`).run();
    for (let t in sessions) delete sessions[t];
    console.log("All users auto-logged out at midnight");
    scheduleMidnightLogout();
  }, msUntilMidnight);
}
scheduleMidnightLogout();

// --- Middleware ---
function authMiddleware(req, res, next) {
  const token = req.headers["x-session-token"];
  if (token && sessions[token]) {
    req.user = sessions[token];
    next();
  } else res.status(401).json({ error: "Unauthorized" });
}

function adminAuth(req, res, next) {
  const token = req.headers["x-session-token"];
  if (token && sessions[token] && sessions[token].isAdmin) next();
  else res.status(401).json({ error: "Unauthorized" });
}

// --- User Login ---
app.post("/login", (req, res) => {
  const { login, pass } = req.body;
  const now = getSimpleDate();

  const row = db.prepare(`SELECT * FROM users WHERE (username=? OR email=?) AND password=?`).get(login, login, pass);
  if (!row) return res.status(401).json({ error: "Invalid login." });
  if (row.activeSession) return res.status(403).json({ error: "Logged in currently. Force Logout." });

  const sub = db.prepare(`SELECT * FROM subscriptions WHERE userId=? AND status='active' ORDER BY endDate DESC LIMIT 1`).get(row.id);
  if (!sub || new Date(sub.endDate) < new Date()) return res.status(403).json({ error: "Subscription expired" });

  const token = generateToken();
  sessions[token] = { userId: row.id, username: row.username };

  db.prepare(`UPDATE users SET activeSession=1, lastLogin=? WHERE id=?`).run(now, row.id);

  res.json({
    success: true,
    token,
    username: row.username,
    email: row.email,
    subscription: {
      planType: sub.planType,
      startDate: sub.startDate,
      endDate: sub.endDate
    }
  });
});

// --- Logout ---
app.post("/logout", authMiddleware, (req, res) => {
  const userId = req.user.userId;
  db.prepare(`UPDATE users SET activeSession=0 WHERE id=?`).run(userId);
  for (let t in sessions) if (sessions[t].userId === userId) delete sessions[t];
  res.json({ success: true });
});

// --- Admin login ---
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  const row = db.prepare(`SELECT * FROM admins WHERE username=? AND password=?`).get(username, password);
  if (!row) return res.status(401).json({ error: "Invalid admin login" });
  const token = generateToken();
  sessions[token] = { username: row.username, isAdmin: true };
  res.json({ success: true, token });
});

// --- Admin APIs ---
// List users
app.get("/admin/users", adminAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id AS userId, u.username, u.password, u.email, u.activeSession,
           s.id AS subscriptionId, s.planType, s.startDate, s.endDate, s.status
    FROM users u
    LEFT JOIN subscriptions s ON u.id=s.userId
    ORDER BY u.id, s.startDate DESC
  `).all();
  res.json(rows);
});

// Add user
app.post("/admin/add-user", adminAuth, (req,res)=>{
  const { username,password,email,planType,planDays } = req.body;
  const days = Number(planDays) || (planType==='3d'?3:8);
  const startDate = getSimpleDate();
  const endDate = getSimpleDate(new Date(Date.now() + days*24*60*60*1000));

  const info = db.prepare(`INSERT INTO users (username,password,email) VALUES (?,?,?)`).run(username,password,email);
  db.prepare(`INSERT INTO subscriptions (userId,planType,startDate,endDate,status) VALUES (?,?,?,?,?)`)
    .run(info.lastInsertRowid, planType, startDate, endDate, "active");
  res.json({ success: true });
});

// Edit user
app.post("/admin/edit-user", adminAuth, (req,res)=>{
  const { userId,username,password,email } = req.body;
  db.prepare(`UPDATE users SET username=?, password=?, email=? WHERE id=?`).run(username,password,email,userId);
  res.json({ success: true });
});

// Delete user
app.post("/admin/delete-user", adminAuth, (req,res)=>{
  const { userId } = req.body;
  if(!userId) return res.status(400).json({ error: "Missing userId" });

  db.prepare(`DELETE FROM subscriptions WHERE userId=?`).run(userId);
  db.prepare(`DELETE FROM renewal_requests WHERE userId=?`).run(userId);
  db.prepare(`DELETE FROM users WHERE id=?`).run(userId);

  // also remove in-memory sessions
  for (let t in sessions) if (sessions[t].userId===userId) delete sessions[t];
  res.json({ success: true });
});

// Delete subscription
app.post("/admin/delete-subscription", adminAuth, (req,res)=>{
  const { subscriptionId } = req.body;
  if(!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });
  db.prepare(`DELETE FROM subscriptions WHERE id=?`).run(subscriptionId);
  res.json({ success: true });
});

// Manual renew
app.post("/admin/manual-renew", adminAuth, (req,res)=>{
  const { userId,planType } = req.body;
  if(!userId||!planType) return res.status(400).json({ error:"Missing userId or planType" });

  const extraDays = planType==='3d'?3:8;
  const sub = db.prepare(`SELECT * FROM subscriptions WHERE userId=? AND status='active' ORDER BY endDate DESC LIMIT 1`).get(userId);
  const startDate = sub ? sub.endDate : getSimpleDate();
  const newEndDate = getSimpleDate(new Date(new Date(startDate).getTime()+extraDays*24*60*60*1000));

  db.prepare(`INSERT INTO subscriptions (userId,planType,startDate,endDate,status) VALUES (?,?,?,?,?)`)
    .run(userId,planType,startDate,newEndDate,"active");
  res.json({ success:true,startDate,endDate:newEndDate });
});

// Force logout
app.post("/logout-auto", (req,res)=>{
  const { token, username } = req.body;

  if(token && sessions[token]){
    const userId = sessions[token].userId;
    db.prepare(`UPDATE users SET activeSession=0 WHERE id=?`).run(userId);
    delete sessions[token];
    return res.json({ success:true });
  }

  if(username){
    const row = db.prepare(`SELECT id FROM users WHERE username=?`).get(username);
    if(!row) return res.json({ success:false });
    const userId = row.id;
    db.prepare(`UPDATE users SET activeSession=0 WHERE id=?`).run(userId);
    for(let t in sessions) if(sessions[t].userId===userId) delete sessions[t];
    return res.json({ success:true });
  }
});

// Validate token
app.post("/validate-token",(req,res)=>{
  const { token } = req.body;
  if(!token || !sessions[token]) return res.json({ valid:false });
  const sessionUser = sessions[token];
  const row = db.prepare(`SELECT activeSession FROM users WHERE id=?`).get(sessionUser.userId);
  if(!row || row.activeSession===0){
    delete sessions[token];
    return res.json({ valid:false });
  }
  res.json({ valid:true });
});

// Get renewal requests
app.get("/admin/requests", adminAuth, (req,res)=>{
  const rows = db.prepare(`SELECT rr.id, rr.userId, u.username, rr.planType, rr.requestDate, rr.status
    FROM renewal_requests rr
    LEFT JOIN users u ON rr.userId=u.id
    ORDER BY rr.requestDate DESC`).all();
  res.json(rows);
});

// --- Start server ---
app.listen(PORT,()=>console.log(`Server running on port ${PORT}`));
