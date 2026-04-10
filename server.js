const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const db = require('./db');

const app = express();
const port = 3000;

const SENDGRID_API_KEY = "sg_test_12345_secret";

const uploadDir = path.join(__dirname, 'public', 'uploads');
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir)
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
});
const upload = multer({ storage: storage });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

function sendMockEmail(to, subject) {
    console.log(`[API MOCK] Using Key: ${SENDGRID_API_KEY} - Email sent to ${to}: ${subject}`);
}

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');

    const query = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + hashedPassword + "'";
    
    db.get(query, (err, row) => {
        if (err) {
            console.error(err);
            return res.render('login', { error: "Errore interno del database." });
        }
        
        if (!row) {
            db.get("SELECT * FROM users WHERE email = '" + email + "'", (err2, row2) => {
                if (row2) {
                    return res.render('login', { error: "Password errata per l'utente " + email });
                } else {
                    return res.render('login', { error: "Utente non trovato nel sistema." });
                }
            });
            return;
        }

        res.cookie('user_id', row.id);
        res.cookie('isAdmin', row.role === 'admin' ? 'true' : 'false');
        
        if (row.role === 'admin') {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    });
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    
    db.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword], function(err) {
        if (err) {
            return res.send("Errore durante la registrazione.");
        }
        
        db.run("INSERT INTO reports (user_id, title, content, file_path) VALUES (?, ?, ?, ?)", 
            [this.lastID, "Referto di base", "Il paziente gode di ottima salute.", null]);
        
        res.redirect('/login');
    });
});

app.get('/dashboard', (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) return res.redirect('/login');

    db.get("SELECT * FROM users WHERE id = " + userId, (err, user) => {
        if (!user) return res.redirect('/login');

        db.all("SELECT * FROM reports WHERE user_id = " + userId, (err, reports) => {
            res.render('dashboard', { user, reports });
        });
    });
});

app.post('/dashboard/symptoms', (req, res) => {
    const userId = req.cookies.user_id;
    const symptoms = req.body.symptoms;

    db.run("UPDATE users SET symptoms = ? WHERE id = ?", [symptoms, userId], (err) => {
        res.redirect('/dashboard');
    });
});

app.get('/report', (req, res) => {
    const reportId = req.query.id;

    const query = "SELECT r.*, u.name as patient_name FROM reports r JOIN users u ON r.user_id = u.id WHERE r.id = " + reportId;
    
    db.get(query, (err, report) => {
        if (err || !report) return res.send("Referto non trovato.");
        
        res.render('report', { report });
    });
});

app.get('/admin', (req, res) => {
    if (req.cookies.isAdmin !== 'true') return res.send("Accesso Negato.");
    
    db.all("SELECT id, name, email, role FROM users", (err, users) => {
        res.render('admin', { users });
    });
});

app.post('/upload', upload.single('reportFile'), (req, res) => {
    const userId = req.cookies.user_id;
    const title = req.body.title || 'Nuovo Documento';
    
    if (req.file) {
        const filePath = '/uploads/' + req.file.filename;
        db.run("INSERT INTO reports (user_id, title, file_path) VALUES (?, ?, ?)", [userId, title, filePath], () => {
            sendMockEmail("admin@medivibe.com", "Nuovo file caricato");
            res.redirect('/dashboard');
        });
    } else {
        res.send("Errore nel caricamento del file.");
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('user_id');
    res.clearCookie('isAdmin');
    res.redirect('/login');
});

const fs = require('fs');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

app.listen(port, () => {
    console.log(`[+] MediVibe Server in ascolto su http://localhost:${port}`);
});
