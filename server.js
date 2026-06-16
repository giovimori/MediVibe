require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const multer = require('multer');
const db = require('./db');

const app = express();
app.use(helmet()); // Aggiunge difesa in profondità e header HTTP sicuri
const port = 3000;

//Security misconfiguration (in produzione usiamo delle API KEY per l'invio delle mail)
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;

const uploadDir = path.join(__dirname, 'public', 'uploads');
// 5. Caricamento di File Insicuro
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir)
    },
    filename: function (req, file, cb) {
        // Ridenominazione con hash casuale
        const uniqueSuffix = crypto.randomBytes(16).toString('hex');
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, uniqueSuffix + ext);
    }
});

// Whitelist estensioni
const fileFilter = (req, file, cb) => {
    const allowedExtensions = ['.pdf', '.png', '.jpg', '.jpeg'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (allowedExtensions.includes(ext)) {
        cb(null, true);
    } else {
        cb(null, false);
    }
};

const upload = multer({ storage: storage, fileFilter: fileFilter });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configurazione crittografia per la memorizzazione della sessione at-rest
const SESSION_ALGORITHM = 'aes-256-cbc';
const SESSION_ENCRYPTION_KEY = process.env.SESSION_ENCRYPTION_KEY 
    ? crypto.scryptSync(process.env.SESSION_ENCRYPTION_KEY, 'salt-session', 32)
    : crypto.scryptSync('fallback-encryption-key-for-sessions-at-rest', 'salt-session', 32);

function encryptSession(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(SESSION_ALGORITHM, SESSION_ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptSession(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(SESSION_ALGORITHM, SESSION_ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

const sessionStore = new session.MemoryStore();
const originalGet = sessionStore.get.bind(sessionStore);
const originalSet = sessionStore.set.bind(sessionStore);

// Sicurezza (Cifratura At-Rest): Effettuiamo l'override dei metodi set e get dello store delle sessioni
// per cifrare in scrittura e decifrare in lettura i dati di sessione (AES-256-CBC) in modo trasparente.
//override del metodo set per la cifratura dei dati di sessione
sessionStore.set = (sid, sessionData, callback) => {
    try {
        const serialized = JSON.stringify(sessionData);
        const encrypted = encryptSession(serialized);
        originalSet(sid, { encryptedPayload: encrypted }, callback);
    } catch (err) {
        if (callback) callback(err);
    }
};

//override del metodo get per la decifratura dei dati di sessione
sessionStore.get = (sid, callback) => {
    originalGet(sid, (err, sessionData) => {
        if (err) return callback(err);
        if (!sessionData) return callback(null, null);
        try {
            if (sessionData.encryptedPayload) {
                const decrypted = decryptSession(sessionData.encryptedPayload);
                const deserialized = JSON.parse(decrypted);
                return callback(null, deserialized);
            }
            //se non c'e un payload cifrato, restituiamo la sessione così com'è
            return callback(null, sessionData);
        } catch (decryptionErr) {
            return callback(decryptionErr);
        }
    });
};

//broken access control: inilializzazione della sessione
app.use(session({
    store: sessionStore,
    //firma della sessione
    secret: process.env.SESSION_SECRET || 'fallback-secret-non-sicuro',
    resave: false,
    saveUninitialized: false,
    //applicazione flag sulla configurazione dei cookie
    cookie: { 
        httpOnly: true, // Impedisce a script client-side (JS) di accedere al cookie di sessione (mitiga XSS)
        secure: false,  // In produzione va impostato a true per obbligare l'invio solo su HTTPS
        sameSite: 'lax' // Impedisce l'invio automatico del cookie per richieste di terze parti (mitiga CSRF)
    }
}));

// Middleware: controllo concorrenza sessioni
const sessionConcurrencyCheck = (req, res, next) => {
    // autenticato
    if (req.session && req.session.userId) {
        // recupero ID sessione valida
        db.get("SELECT active_session_id FROM users WHERE id = ?", [req.session.userId], (err, row) => {
            if (err) {
                console.error("Errore nel controllo di concorrenza della sessione:", err);
                return next();
            }
            // se ID sessione corrente !== ID sessione memorizzato sul DB allora login più recente da un altro dispositivo
            if (row && row.active_session_id && row.active_session_id !== req.sessionID) {
                console.log(`[CONCURRENCY CONTROL] Sessione ${req.sessionID} invalidata per l'utente ID ${req.session.userId} (nuova sessione attiva: ${row.active_session_id}).`);
                // distruggo sessione non valida + rimuovo cookie su browser + logout
                req.session.destroy((err) => {
                    if (err) console.error("Errore nella distruzione della sessione concorrente:", err);
                    res.clearCookie('connect.sid');
                    return res.render('login', { error: "Sessione terminata: è stato rilevato un accesso da un'altra postazione." });
                });
            } else {
                // se ID == allora sessione valida
                next();
            }
        });
    } else {
        // non autenticato
        next();
    }
};

app.use(sessionConcurrencyCheck);

// Middleware per impedire il Session Hijacking legando la sessione al fingerprint del client
const sessionFingerprintCheck = (req, res, next) => {
    if (req.session && req.session.userId) {
        const currentIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const currentUserAgent = req.headers['user-agent'] || '';

        // Associa dati fingerprint se la sessione e attiva
        if (!req.session.clientIp) {
            req.session.clientIp = currentIp;
        }
        if (!req.session.clientUserAgent) {
            req.session.clientUserAgent = currentUserAgent;
        }

        // Se viene rilevata una discrepanza tra il client attuale e quello che ha avviato la sessione
        if (req.session.clientIp !== currentIp || req.session.clientUserAgent !== currentUserAgent) {
            console.warn(`[SECURITY WARNING] Session hijacking attempt detected: mismatch in fingerprint for user ID ${req.session.userId}. Expected IP: ${req.session.clientIp}, Actual IP: ${currentIp}. Expected UA: ${req.session.clientUserAgent}, Actual UA: ${currentUserAgent}`);
            
            // Eliminiamo la sessione anche sul database per invalidarla del tutto
            db.run("UPDATE users SET active_session_id = NULL WHERE id = ?", [req.session.userId], (dbErr) => {
                if (dbErr) {
                    console.error("Errore nell'annullamento della sessione nel DB:", dbErr);
                }
                req.session.destroy((err) => {
                    if (err) console.error("Errore nella distruzione della sessione per fingerprint non corrispondente:", err);
                    res.clearCookie('connect.sid');
                    return res.status(403).send("Forbidden: session binding violation.");
                });
            });
            return;
        }
    }
    next();
};

app.use(sessionFingerprintCheck);


function sendMockEmail(to, subject) {
    console.log(`[API MOCK] Using Key: ${SENDGRID_API_KEY} - Email sent to ${to}: ${subject}`);
}

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// 1. SQLI
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    //hashing password con algoritmo bcrypt
    // Sicurezza (SQL Injection): Utilizziamo una query parametrizzata per impedire SQL Injection.
    const query = "SELECT * FROM users WHERE email = ?";
    
    db.get(query, [email], async (err, row) => {
        if (err) {
            console.error(err);
            return res.render('login', { error: "Errore interno del database." });
        }
        
        // Sicurezza (Bcrypt): Confrontiamo l'hash della password con bcrypt anziché MD5 in chiaro.
        if (row && await bcrypt.compare(password, row.password)) {
            // Sicurezza (broken access control): Memorizziamo l'identità e il ruolo lato server nella sessione.
            req.session.userId = row.id;
            req.session.role = row.role;
            
            // Sicurezza (Fingerprint Binding): Legiamo l'IP e lo User-Agent alla sessione corrente.
            req.session.clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            req.session.clientUserAgent = req.headers['user-agent'] || '';
            
            // Sicurezza (Session Concurrency): Salviamo il sessionID nel DB per invalidare eventuali accessi concorrenti.
            const sessionId = req.sessionID;
            db.run("UPDATE users SET active_session_id = ? WHERE id = ?", [sessionId, row.id], (dbErr) => {
                if (dbErr) {
                    console.error("Errore nell'aggiornamento della sessione attiva:", dbErr);
                }
                
                if (row.role === 'admin') {
                    res.redirect('/admin');
                } else if (row.role === 'doctor') {
                    res.redirect('/doctor');
                } else {
                    res.redirect('/dashboard');
                }
            });
        } else {
            return res.render('login', { error: "Credenziali non valide." });
        }
    });
});

app.get('/register', (req, res) => {
    db.all("SELECT id, name FROM users WHERE role = 'doctor'", (err, doctors) => {
         res.render('register', { doctors: doctors || [], error: null });
    });
});

app.post('/register', async (req, res) => {
    const { name, email, password, doctor_id } = req.body;
    
    // Validazione email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || typeof email !== 'string' || !email.includes('@') || !emailRegex.test(email)) {
        return db.all("SELECT id, name FROM users WHERE role = 'doctor'", (err, doctors) => {
             res.render('register', { 
                 doctors: doctors || [], 
                 error: "L'indirizzo email inserito non è valido o non contiene la @." 
             });
        });
    }

    // Validazione pwd
    if (!password || typeof password !== 'string' || password.length < 8 || !/[A-Z]/.test(password)) {
        return db.all("SELECT id, name FROM users WHERE role = 'doctor'", (err, doctors) => {
             res.render('register', { 
                 doctors: doctors || [], 
                 error: "La password deve essere lunga almeno 8 caratteri e contenere almeno una lettera maiuscola." 
             });
        });
    }

    //hashing password con algoritmo bcrypt
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run("INSERT INTO users (name, email, password, role, doctor_id) VALUES (?, ?, ?, 'patient', ?)", 
        [name, email, hashedPassword, doctor_id || null], function(err) {
            if (err) {
                return db.all("SELECT id, name FROM users WHERE role = 'doctor'", (err2, doctors) => {
                     res.render('register', { 
                         doctors: doctors || [], 
                         error: "Errore durante la registrazione (l'email potrebbe essere già registrata)." 
                     });
                });
            }
            
            db.run("INSERT INTO reports (user_id, title, content, file_path) VALUES (?, ?, ?, ?)", 
                [this.lastID, "Referto di base", "Il paziente gode di ottima salute.", null]);
            
            res.redirect('/login');
        });
    } catch (e) {
        res.status(500).send("Errore nella cifratura della password.");
    }
});

app.get('/dashboard', (req, res) => {
    const userId = req.session.userId;
    if (!userId) return res.redirect('/login');
    if (req.session.role !== 'patient') return res.status(403).send("Non autorizzato.");


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
            db.all("SELECT id, name FROM users WHERE role = 'doctor'", (err, doctors) => {
                res.render('dashboard', { 
                    user: user, 
                    reports: reports || [], 
                    needsDoctor: needsDoctor, 
                    doctorsList: doctors || [] 
                });
            });
        });
    });
});

app.post('/dashboard/select-doctor', (req, res) => {
    const userId = req.session.userId;
    const doctorId = req.body.doctor_id;
    if (!userId || req.session.role !== 'patient') return res.status(403).send("Non autorizzato");
    db.run("UPDATE users SET doctor_id = ? WHERE id = ?", [doctorId, userId], () => {
        res.redirect('/dashboard');
    });
});

app.post('/dashboard/symptoms', (req, res) => {
    const userId = req.session.userId;
    if (!userId || req.session.role !== 'patient') return res.status(403).send("Non autorizzato");
    db.run("UPDATE users SET symptoms = ? WHERE id = ?", [req.body.symptoms, userId], () => {
        res.redirect('/dashboard');
    });
});

app.get('/doctor', (req, res) => {
    const doctorId = req.session.userId;
    if (!doctorId) return res.redirect('/login');

    if (req.session.role !== 'doctor') return res.status(403).send("Accesso Negato. Area medica riservata.");

    db.get("SELECT * FROM users WHERE id = ?", [doctorId], (err, doctor) => {
        if (!doctor) return res.redirect('/login');

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

// 6. IDOR
app.get('/report', (req, res) => {
    // recupero identità utente memorizzata in sessione
    const userId = req.session.userId;
    const role = req.session.role;

    if (!userId) return res.redirect('/login');

    const query = "SELECT r.*, u.name as patient_name, u.doctor_id FROM reports r JOIN users u ON r.user_id = u.id WHERE r.id = ?";
    
    db.get(query, [req.query.id], (err, report) => {
        if (err || !report) return res.send("Referto non trovato.");
        
        // verifica dei privilegi di accesso
        if (role === 'admin' || report.user_id == userId || report.doctor_id == userId) {
            res.render('report', { report });
        } else {
            res.status(403).send("Accesso Negato: Non possiedi i permessi per visualizzare questo referto.");
        }
    });
});

//broken access control: controllo del ruolo admin
//verifica privilegi per broken access control
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

    if (req.file) {
        const filePath = '/uploads/' + req.file.filename;
        db.run("INSERT INTO reports (user_id, title, file_path) VALUES (?, ?, ?)", [userId, req.body.title || 'Nuovo Documento', filePath], () => {
            sendMockEmail("admin@medivibe.com", "Nuovo file caricato");
            res.redirect('/dashboard');
        });
    } else {
        res.send("Errore nel caricamento del file.");
    }
});

//distruzione sessione
app.get('/logout', (req, res) => {
    const userId = req.session ? req.session.userId : null;
    if (userId) {
        db.run("UPDATE users SET active_session_id = NULL WHERE id = ?", [userId], () => {
            req.session.destroy(() => {
                res.clearCookie('connect.sid'); 
                res.redirect('/login');
            });
        });
    } else {
        res.redirect('/login');
    }
});

if (process.env.NODE_ENV === 'test') {
    app.get('/debug/raw-session/:sid', (req, res) => {
        const sid = req.params.sid;
        if (sessionStore && sessionStore.sessions && sessionStore.sessions[sid]) {
            return res.json({
                raw: sessionStore.sessions[sid]
            });
        }
        return res.status(404).json({ error: "Session not found" });
    });
}

const fs = require('fs');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

app.listen(port, () => {
    console.log(`[+] MediVibe attivo su http://localhost:${port}`);
    console.log(`[+] API Key caricata correttamente: ${SENDGRID_API_KEY ? 'SÌ' : 'NO'}`);
});