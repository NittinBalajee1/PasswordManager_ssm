const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./passwords.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      phone TEXT,
      passwordHash TEXT
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS passwords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      site TEXT,
      encryptedPassword TEXT,
      rsaEncryptedKey TEXT,
      iv TEXT,
      passwordHash TEXT,
      FOREIGN KEY(userId) REFERENCES users(id)
    );
  `);
});

module.exports = db;
