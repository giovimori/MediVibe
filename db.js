const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
//libreria per la gestione delle variabili d'ambiente (security misconfiguration)
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
        doctor_id INTEGER,
        active_session_id TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        file_path TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Sicurezza: Le password di seeding vengono caricate in modo sicuro dalle variabili d'ambiente
    // e memorizzate nel database esclusivamente dopo essere state hashate tramite bcrypt (cost factor 10).
    //Security misconfiguration 
    //legge password di default nel caso in cui non sia configurata una password di default nel file .env
    const adminPass = process.env.DEFAULT_ADMIN_PASSWORD || 'ChangeMe123!';
    const docPass = process.env.DEFAULT_DOCTOR_PASSWORD || 'ChangeMeDoc!';

    //Security misconfiguration 
    //hash sicuro per le password con inserimento nel db
    db.get("SELECT id FROM users WHERE email = 'admin@medivibe.com'", async (err, row) => {
        if (!row) {
            const pwd = bcrypt.hashSync(adminPass, 10);
            db.run(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`, ['Amministrazione', 'admin@medivibe.com', pwd, 'admin']);
        }
    });

    // Inseriamo di default i 3 medici
    const defaultDoctors = [
        { name: "Dr. Rossi", email: "dr.rossi@medivibe.com" },
        { name: "Dr. Verdi", email: "dr.verdi@medivibe.com" },
        { name: "Dott.ssa Bianchi", email: "dr.bianchi@medivibe.com" }
    ];

    //Security misconfiguration 
    //hash sicuro per le password con inserimento nel db dei medici default
    defaultDoctors.forEach(doc => {
        db.get(`SELECT * FROM users WHERE email = ?`, [doc.email], (err, row) => {
            if (!row) {
                const docPwd = bcrypt.hashSync(docPass, 10);
                db.run(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`, [doc.name, doc.email, docPwd, 'doctor']);
            }
        });
    });
});

module.exports = db;