const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
require('dotenv').config();

const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT,
        symptoms TEXT,
        doctor_id INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        file_path TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    const adminPass = process.env.DEFAULT_ADMIN_PASSWORD || 'ChangeMe123!';
    const docPass = process.env.DEFAULT_DOCTOR_PASSWORD || 'ChangeMeDoc!';

    db.get("SELECT id FROM users WHERE email = 'admin@medivibe.com'", async (err, row) => {
        if (!row) {
            const hashedAdmin = await bcrypt.hash(adminPass, 10);
            db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
                ['Admin', 'admin@medivibe.com', hashedAdmin, 'admin']);
        }
    });

    db.get("SELECT id FROM users WHERE email = 'bianchi@medivibe.com'", async (err, row) => {
        if (!row) {
            const hashedDoc = await bcrypt.hash(docPass, 10);
            db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
                ['Dottor Bianchi', 'bianchi@medivibe.com', hashedDoc, 'doctor']);
        }
    });
});

module.exports = db;