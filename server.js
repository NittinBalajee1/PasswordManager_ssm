const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const validator = require("validator");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

const db = new sqlite3.Database("db.sqlite");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    phone TEXT,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    website TEXT,
    encrypted_password TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

const usersFile = path.join(__dirname, "users.json");
const loadUsers = () =>
  fs.existsSync(usersFile) ? JSON.parse(fs.readFileSync(usersFile)) : {};
const saveUsers = (users) =>
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));

// Register
app.post("/register", (req, res) => {
  const { email, phone, password } = req.body;

  if (!validator.isEmail(email)) return res.status(400).send("Invalid email.");
  if (!validator.isMobilePhone(phone))
    return res.status(400).send("Invalid phone.");
  const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$/;
  if (!passRegex.test(password))
    return res.status(400).send("Password not strong enough.");

  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run(
    `INSERT INTO users (email, phone, password) VALUES (?, ?, ?)`,
    [email, phone, hashedPassword],
    function (err) {
      if (err) return res.status(400).send("User already exists.");
      res.send("User registered successfully!");
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).send("Invalid credentials.");
    }

    const users = loadUsers();
    if (!users[user.email]) {
      const secret = speakeasy.generateSecret({
        name: `PasswordManager (${user.email})`,
      });
      users[user.email] = { secret: secret.base32 };
      saveUsers(users);
      qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        res.send({ step: "setup-2fa", qr: data_url, email: user.email });
      });
    } else {
      res.send({ step: "verify-2fa", email: user.email, userId: user.id });
    }
  });
});

// Verify 2FA
app.post("/verify-2fa", (req, res) => {
  const { email, token } = req.body;
  const users = loadUsers();
  const user = users[email];

  if (!user) return res.status(404).send("2FA not setup for this user.");

  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: "base32",
    token,
    window: 1,
  });

  if (verified) {
    db.get(`SELECT id FROM users WHERE email = ?`, [email], (err, row) => {
      res.send({ verified: true, userId: row.id });
    });
  } else {
    res.send({ verified: false });
  }
});

// Save password
app.post("/save-password", (req, res) => {
  const { userId, website, encryptedPassword } = req.body;
  if (!validator.isURL(website))
    return res.status(400).send("Invalid website URL.");

  db.get(
    `SELECT * FROM passwords WHERE user_id = ? AND website = ?`,
    [userId, website],
    (err, row) => {
      if (row) {
        db.run(
          `UPDATE passwords SET encrypted_password = ? WHERE id = ?`,
          [encryptedPassword, row.id],
          () => {
            res.send("Password updated.");
          }
        );
      } else {
        db.run(
          `INSERT INTO passwords (user_id, website, encrypted_password) VALUES (?, ?, ?)`,
          [userId, website, encryptedPassword],
          () => {
            res.send("Password saved.");
          }
        );
      }
    }
  );
});

// Get passwords
app.get("/get-passwords/:userId", (req, res) => {
  db.all(
    `SELECT website, encrypted_password FROM passwords WHERE user_id = ?`,
    [req.params.userId],
    (err, rows) => {
      res.send(rows);
    }
  );
});

app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});
