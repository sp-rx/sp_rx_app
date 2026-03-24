const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static("public"));

// --- SQLite DB ---
const db = new sqlite3.Database("./users.db", err => {
  if (err) console.error(err.message);
  else console.log("Connected to SQLite DB");
});

// --- Helper for YYYY-MM-DD ---
function getSimpleDate(date = new Date()) {
  return date.toISOString().split("T")[0];
}

// --- Tables ---
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT UNIQUE,
    activeSession INTEGER DEFAULT 0,
    lastLogin TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY,
    userId INTEGER,
    planType TEXT,
    startDate TEXT,
    endDate TEXT,
    status TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS renewal_requests (
    id INTEGER PRIMARY KEY,
    userId INTEGER,
    planType TEXT,
    requestDate TEXT,
    status TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
  )`);

  // default admin
db.run(`INSERT OR IGNORE INTO admins (username,password) VALUES (?,?)`, ["jay", "3911"], (err) => {
  if (err) console.error("Admin insert error:", err.message);
  else console.log("Default admin ensured: jay / 3911");
});
});

// --- Generate session token ---
function generateToken() {
  return crypto.randomBytes(16).toString("hex");
}


// --- In-memory sessions ---
const sessions = {};

// --- Auto logout at midnight server time ---
function scheduleMidnightLogout() {
  const now = new Date();
  const nextMidnight = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate() + 1, // tomorrow
    0, 0, 0, 0
  );
  const msUntilMidnight = nextMidnight - now;

  setTimeout(() => {
    // log out all users
    db.run(`UPDATE users SET activeSession=0`);
    for (let t in sessions) delete sessions[t];
    console.log("All users auto-logged out at midnight");

    // schedule the next midnight
    scheduleMidnightLogout();
  }, msUntilMidnight);
}

// start the scheduler
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

// --- User Login (username or email) ---
app.post("/login", (req, res) => {
  const { login, pass } = req.body; // login = username or email
  const now = getSimpleDate();

  db.get(`SELECT * FROM users WHERE (username=? OR email=?) AND password=?`, [login, login, pass], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: "Invalid login." });
    if (row.activeSession) return res.status(403).json({ error: "Logged in currently. Force Logout." });

    db.get(`SELECT * FROM subscriptions WHERE userId=? AND status='active' ORDER BY endDate DESC LIMIT 1`, [row.id], (err2, sub) => {
      if (err2) return res.status(500).json({ error: err2.message });
      if (!sub || new Date(sub.endDate) < new Date()) return res.status(403).json({ error: "Subscription expired" });

      const token = generateToken();
      sessions[token] = { userId: row.id, username: row.username };

      db.run(`UPDATE users SET activeSession=1, lastLogin=? WHERE id=?`, [now, row.id]);

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
  });
});

// --- Logout ---
app.post("/logout", authMiddleware, (req, res) => {
  const userId = req.user.userId;
  db.run(`UPDATE users SET activeSession=0 WHERE id=?`, [userId]);
  for (let t in sessions) if (sessions[t].userId === userId) delete sessions[t];
  res.json({ success: true });
});

// --- Admin login ---
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM admins WHERE username=? AND password=?`, [username, password], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(401).json({ error: "Invalid admin login" });
    const token = generateToken();
    sessions[token] = { username: row.username, isAdmin: true };
    res.json({ success: true, token });
  });
});

// --- Admin APIs ---

// List all users
app.get("/admin/users", adminAuth, (req, res) => {
  db.all(`
    SELECT u.id AS userId, u.username, u.password, u.email, u.activeSession,
           s.id AS subscriptionId, s.planType, s.startDate, s.endDate, s.status
    FROM users u
    LEFT JOIN subscriptions s ON u.id=s.userId
    ORDER BY u.id, s.startDate DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Add user
app.post("/admin/add-user", adminAuth, (req, res) => {
  const { username, password, email, planType, planDays } = req.body;
  const days = Number(planDays) || (planType === "3d" ? 3 : 8);
  const startDate = getSimpleDate();
  const endDate = getSimpleDate(new Date(Date.now() + days * 24*60*60*1000));

  db.run(`INSERT INTO users (username,password,email) VALUES (?,?,?)`, [username, password, email], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    const userId = this.lastID;
    db.run(`INSERT INTO subscriptions (userId, planType, startDate, endDate, status) VALUES (?,?,?,?,?)`,
      [userId, planType, startDate, endDate, "active"], err2 => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true });
      });
  });
});

// Edit user
app.post("/admin/edit-user", adminAuth, (req, res) => {
  const { userId, username, password, email } = req.body;
  db.run(`UPDATE users SET username=?, password=?, email=? WHERE id=?`, [username, password, email, userId], err => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Delete user
app.post("/admin/delete-user", adminAuth, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  db.serialize(() => {
    db.run(`DELETE FROM subscriptions WHERE userId=?`, [userId], err1 => {
      if (err1) return res.status(500).json({ error: err1.message });
      db.run(`DELETE FROM renewal_requests WHERE userId=?`, [userId], err2 => {
        if (err2) return res.status(500).json({ error: err2.message });
        db.run(`DELETE FROM users WHERE id=?`, [userId], err3 => {
          if (err3) return res.status(500).json({ error: err3.message });
          res.json({ success: true });
        });
      });
    });
  });
});

// Delete subscription
app.post("/admin/delete-subscription", adminAuth, (req, res) => {
  const { subscriptionId } = req.body;
  if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

  db.run(`DELETE FROM subscriptions WHERE id=?`, [subscriptionId], err => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Manual renew
app.post("/admin/manual-renew", adminAuth, (req, res) => {
  const { userId, planType } = req.body;
  if (!userId || !planType) return res.status(400).json({ error: "Missing userId or planType" });

  const extraDays = planType === "3d" ? 3 : 8;
  db.get(`SELECT * FROM subscriptions WHERE userId=? AND status='active' ORDER BY endDate DESC LIMIT 1`, [userId], (err, sub) => {
    if (err) return res.status(500).json({ error: err.message });
    const startDate = sub ? sub.endDate : getSimpleDate();
    const newEndDate = getSimpleDate(new Date(new Date(startDate).getTime() + extraDays * 24*60*60*1000));

    db.run(`INSERT INTO subscriptions (userId, planType, startDate, endDate, status) VALUES (?,?,?,?,?)`,
      [userId, planType, startDate, newEndDate, "active"], err2 => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true, startDate, endDate: newEndDate });
      });
  });
});


// --- Force logout by username ---
app.post("/logout-auto", async (req, res) => {
  const { token, username } = req.body;

  if (token && sessions[token]) {
    const userId = sessions[token].userId;
    db.run(`UPDATE users SET activeSession=0 WHERE id=?`, [userId]);
    delete sessions[token];
    return res.json({ success: true });
  }

  if (username) {
    db.get(`SELECT id FROM users WHERE username=?`, [username], (err, row) => {
      if (err || !row) return res.json({ success: false });
      const userId = row.id;
      db.run(`UPDATE users SET activeSession=0 WHERE id=?`, [userId], () => {
        for (let t in sessions) {
          if (sessions[t].userId === userId) delete sessions[t];
        }
        return res.json({ success: true });
      });
    });
  }
});


app.post("/validate-token", (req, res) => {
  const { token } = req.body;

  if (!token || !sessions[token]) {
    return res.json({ valid: false });
  }

  const sessionUser = sessions[token];

  // Check activeSession in DB
  db.get(`SELECT activeSession FROM users WHERE id=?`, [sessionUser.userId], (err, row) => {
    if (err || !row) return res.json({ valid: false });
    if (row.activeSession === 0) {
      // session is invalid, remove from memory
      delete sessions[token];
      return res.json({ valid: false });
    }
    res.json({ valid: true });
  });
});



// Get renewal requests
app.get("/admin/requests", adminAuth, (req, res) => {
  db.all(`SELECT rr.id, rr.userId, u.username, rr.planType, rr.requestDate, rr.status
          FROM renewal_requests rr
          LEFT JOIN users u ON rr.userId=u.id
          ORDER BY rr.requestDate DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// --- Start server ---
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
