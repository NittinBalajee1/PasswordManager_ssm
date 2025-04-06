const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const validator = require("validator");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

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
    res.send({ message: "Login successful!", userId: user.id });
  });
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
