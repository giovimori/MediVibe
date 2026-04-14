require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const multer = require('multer');
const db = require('./db');

const app = express();
const port = 3000;

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;

const uploadDir = path.join(__dirname, 'public', 'uploads');
const storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, uploadDir) },
    filename: function (req, file, cb) { cb(null, file.originalname) }
});
const upload = multer({ storage: storage });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-non-sicuro',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        httpOnly: true,
        secure: false,  
        sameSite: 'lax' 
    }
}));


app.listen(port, () => {
    console.log(`[+] MediVibe attivo su http://localhost:${port}`);
    console.log(`[+] API Key caricata correttamente: ${SENDGRID_API_KEY ? 'SÌ' : 'NO'}`);
});