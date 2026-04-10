const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        symptoms TEXT,
        role TEXT DEFAULT 'patient'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        file_path TEXT
    )`);

    db.get("SELECT * FROM users WHERE email = 'admin@medivibe.com'", (err, row) => {
        if (!row) {
            const crypto = require('crypto');
            const pwd = crypto.createHash('md5').update('admin123').digest('hex');
            db.run(`INSERT INTO users (name, email, password, role) VALUES ('Admin', 'admin@medivibe.com', '${pwd}', 'admin')`);
        }
    });
});

module.exports = db;
