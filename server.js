const express = require('express');
const session = require('express-session');
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

app.use(session({
    secret: 'Chiave_Segreta_MediVibe_Super_Sicura_2026', 
    resave: false,
    saveUninitialized: false,
    cookie: { 
        httpOnly: true,
        secure: false,  
        sameSite: 'lax' 
    }
}));

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

    const query = "SELECT * FROM users WHERE email = ? AND password = ?";
    
    db.get(query, [email, hashedPassword], (err, row) => {
        if (err) {
            console.error(err);
            return res.render('login', { error: "Errore interno del database." });
        }
        
        if (!row) {
            db.get("SELECT * FROM users WHERE email = ?", [email], (err2, row2) => {
                if (row2) {
                    return res.render('login', { error: "Password errata per l'utente " + email });
                } else {
                    return res.render('login', { error: "Utente non trovato nel sistema." });
                }
            });
            return;
        }

        req.session.userId = row.id;
        req.session.role = row.role;
        
        if (row.role === 'admin') {
            res.redirect('/admin');
        } else if (row.role === 'doctor') {
            res.redirect('/doctor');
        } else {
            res.redirect('/dashboard');
        }
    });
});

app.get('/register', (req, res) => {
    db.all("SELECT id, name FROM users WHERE role = 'doctor'", (err, doctors) => {
         res.render('register', { doctors: doctors || [] });
    });
});

app.post('/register', (req, res) => {
    const { name, email, password, doctor_id } = req.body;
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    
    db.run("INSERT INTO users (name, email, password, role, doctor_id) VALUES (?, ?, ?, 'patient', ?)", 
    [name, email, hashedPassword, doctor_id || null], function(err) {
        if (err) {
            return res.send("Errore durante la registrazione.");
        }
        
        db.run("INSERT INTO reports (user_id, title, content, file_path) VALUES (?, ?, ?, ?)", 
            [this.lastID, "Referto di base", "Il paziente gode di ottima salute.", null]);
        
        res.redirect('/login');
    });
});

app.get('/dashboard', (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

    if (req.session.role !== 'patient') return res.status(403).send("Accesso non autorizzato. Area riservata ai pazienti.");

    const query = `
        SELECT u.*, d.name as doctor_name 
        FROM users u 
        LEFT JOIN users d ON u.doctor_id = d.id 
        WHERE u.id = ?
    `;

    db.get(query, [userId], (err, user) => {
        if (!user) return res.redirect('/login');

        const needsDoctor = !user.doctor_id;

        db.all("SELECT * FROM reports WHERE user_id = ?", [userId], (err, reports) => {
            if (needsDoctor) {
                db.all("SELECT id, name FROM users WHERE role = 'doctor'", (err, doctors) => {
                    res.render('dashboard', { 
                        user: user, 
                        reports: reports || [], 
                        needsDoctor: true, 
                        doctorsList: doctors || [] 
                    });
                });
            } else {
                res.render('dashboard', { 
                    user: user, 
                    reports: reports || [], 
                    needsDoctor: false, 
                    doctorsList: [] 
                });
            }
        });
    });
});

app.post('/dashboard/select-doctor', (req, res) => {
    const userId = req.session.userId;
    const doctorId = req.body.doctor_id;

    if (!userId || req.session.role !== 'patient') return res.status(403).send("Non autorizzato");

    db.run("UPDATE users SET doctor_id = ? WHERE id = ?", [doctorId, userId], (err) => {
        res.redirect('/dashboard');
    });
});

app.post('/dashboard/symptoms', (req, res) => {
    const userId = req.session.userId;
    if (!userId || req.session.role !== 'patient') return res.status(403).send("Non autorizzato");
    
    const symptoms = req.body.symptoms;

    db.run("UPDATE users SET symptoms = ? WHERE id = ?", [symptoms, userId], (err) => {
        res.redirect('/dashboard');
    });
});

app.get('/doctor', (req, res) => {
    const doctorId = req.session.userId;
    if (!doctorId) return res.redirect('/login');

    if (req.session.role !== 'doctor') return res.status(403).send("Accesso Negato. Area medica riservata.");

    db.get("SELECT * FROM users WHERE id = ?", [doctorId], (err, doctor) => {
        if (!doctor) return res.redirect('/login');

        // Mostriamo solo i pazienti associati a questo dottore specifico
        db.all("SELECT id, name, email, symptoms FROM users WHERE role = 'patient' AND doctor_id = ?", [doctorId], (err, patients) => {
            if (!patients || patients.length === 0) {
                return res.render('doctor', { doctor, patients: [] });
            }
            
            const patientIds = patients.map(p => p.id);
            const placeholders = patientIds.map(() => '?').join(',');
            db.all("SELECT id, user_id, title, file_path FROM reports WHERE user_id IN (" + placeholders + ")", patientIds, (err, reports) => {
                patients.forEach(p => {
                    p.reports = reports ? reports.filter(r => r.user_id === p.id) : [];
                });
                res.render('doctor', { doctor, patients });
            });
        });
    });
});

app.get('/report', (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');
    
    const reportId = req.query.id;

    const query = "SELECT r.*, u.name as patient_name FROM reports r JOIN users u ON r.user_id = u.id WHERE r.id = ?";
    
    db.get(query, [reportId], (err, report) => {
        if (err || !report) return res.send("Referto non trovato.");
        res.render('report', { report });
    });
});

app.get('/admin', (req, res) => {
    if (!req.session.userId || req.session.role !== 'admin') {
        return res.status(403).send("Accesso Negato. Violazione dei privilegi rilevata.");
    }
    
    db.all("SELECT id, name, email, role FROM users", (err, users) => {
        res.render('admin', { users });
    });
});

app.post('/upload', upload.single('reportFile'), (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');

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
    req.session.destroy((err) => {
        res.clearCookie('connect.sid'); 
        res.redirect('/login');
    });
});

const fs = require('fs');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

app.listen(port, () => {
    console.log(`[+] MediVibe Server in ascolto su http://localhost:${port}`);
});