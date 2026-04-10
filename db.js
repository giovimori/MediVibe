const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        symptoms TEXT,
        role TEXT DEFAULT 'patient',
        doctor_id INTEGER
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
            const pwd = crypto.createHash('md5').update('admin123').digest('hex');
            db.run(`INSERT INTO users (name, email, password, role) VALUES ('Amministrazione', 'admin@medivibe.com', '${pwd}', 'admin')`);
        }
    });

    // Inseriamo di default i 3 medici
    const defaultDoctors = [
        { name: "Dr. Rossi", email: "dr.rossi@medivibe.com" },
        { name: "Dr. Verdi", email: "dr.verdi@medivibe.com" },
        { name: "Dott.ssa Bianchi", email: "dr.bianchi@medivibe.com" }
    ];

    defaultDoctors.forEach(doc => {
        db.get(`SELECT * FROM users WHERE email = '${doc.email}'`, (err, row) => {
            if (!row) {
                const docPwd = crypto.createHash('md5').update('doc123').digest('hex');
                db.run(`INSERT INTO users (name, email, password, role) VALUES ('${doc.name}', '${doc.email}', '${docPwd}', 'doctor')`);
            }
        });
    });
});

module.exports = db;
