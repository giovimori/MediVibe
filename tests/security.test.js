const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// Load .env
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

// Detect if we are running on the vulnerable branch
const dbJsPath = path.resolve(__dirname, '../db.js');
const dbContent = fs.readFileSync(dbJsPath, 'utf8');
const isVulnerableBranch = dbContent.includes('admin123');

const adminEmail = 'admin@medivibe.com';
const adminPassword = isVulnerableBranch ? 'admin123' : (process.env.DEFAULT_ADMIN_PASSWORD || 'AdminPassword2026!');

const doctorEmail = 'dr.rossi@medivibe.com';
const doctorPassword = isVulnerableBranch ? 'doc123' : (process.env.DEFAULT_DOCTOR_PASSWORD || 'DoctorPassword2026!');

let serverProcess;

// Helper to wait for server to start
function startServer() {
    return new Promise((resolve, reject) => {
        // Remove DB file beforehand to ensure clean state
        const dbPath = path.resolve(__dirname, '../database.sqlite');
        if (fs.existsSync(dbPath)) {
            try {
                fs.unlinkSync(dbPath);
            } catch (err) {
                console.warn("Could not delete sqlite database file:", err.message);
            }
        }

        // Spawn server
        serverProcess = spawn('node', ['server.js'], {
            cwd: path.resolve(__dirname, '..'),
            env: { ...process.env, PORT: '3000' }
        });

        let resolved = false;

        serverProcess.stdout.on('data', (data) => {
            const output = data.toString();
            if (output.includes('MediVibe')) {
                if (!resolved) {
                    resolved = true;
                    setTimeout(resolve, 1000); // Allow server to bind to port
                }
            }
        });

        serverProcess.stderr.on('data', (data) => {
            // Log errors but do not reject immediately if it is normal output
            const output = data.toString();
            if (output.includes('Error: listen EADDRINUSE')) {
                if (!resolved) {
                    resolved = true;
                    reject(new Error("Port 3000 already in use"));
                }
            }
        });

        serverProcess.on('error', (err) => {
            if (!resolved) {
                resolved = true;
                reject(err);
            }
        });

        serverProcess.on('close', (code) => {
            if (!resolved) {
                resolved = true;
                reject(new Error(`Server closed with code ${code}`));
            }
        });
    });
}

function stopServer() {
    if (serverProcess) {
        serverProcess.kill('SIGKILL');
    }
}

// Helper to log in and return cookie string
async function loginAndGetCookies(email, password) {
    const res = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ email, password }).toString(),
        redirect: 'manual'
    });
    const cookies = res.headers.getSetCookie();
    return cookies.map(c => c.split(';')[0]).join('; ');
}

// Helper to register a new patient user
async function registerUser(name, email, password, doctorId = '') {
    const params = new URLSearchParams({ name, email, password });
    if (doctorId) {
        params.append('doctor_id', doctorId);
    }
    const res = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
        redirect: 'manual'
    });
    return res;
}

before(async () => {
    console.log(`[TEST SETUP] Starting server... Branch is detected as: ${isVulnerableBranch ? 'VULNERABLE' : 'SECURE'}`);
    await startServer();
});

after(() => {
    console.log('[TEST TEARDOWN] Stopping server...');
    stopServer();
});

// A03:2025 - Injection
test('A03:2025 - Injection: SQL Injection in login (email field)', async () => {
    const sqlInjectionPayload = "admin@medivibe.com' --";
    const res = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            email: sqlInjectionPayload,
            password: 'arbitrary_password'
        }).toString(),
        redirect: 'manual'
    });

    const cookies = res.headers.getSetCookie();
    const hasAuthCookie = cookies.some(cookie => cookie.includes('user_id') || cookie.includes('connect.sid'));
    
    // Assert SQL Injection bypass fails
    assert.strictEqual(hasAuthCookie, false, "SQL Injection bypass succeeded: login was bypassed and cookies were set!");
    
    const location = res.headers.get('location');
    const isRedirectedToAuth = location && (location.includes('admin') || location.includes('dashboard'));
    assert.strictEqual(!!isRedirectedToAuth, false, "SQL Injection bypass succeeded: redirected to authenticated page: " + location);
});

test('A03:2025 - Injection: SQL Injection in /report (id query parameter)', async () => {
    // Register and login to bypass basic checks if running on secure branch
    const email = `sqli_rep_${Date.now()}@test.com`;
    await registerUser('SQLi Rep User', email, 'Password123!');
    const cookieHeader = await loginAndGetCookies(email, 'Password123!');

    const payload = "-1 UNION SELECT 999, 999, 'SQLi Title', 'SQLi Content', 'SQLi Path', 'SQLi Patient'";
    const res = await fetch(`http://localhost:3000/report?id=${encodeURIComponent(payload)}`, {
        headers: {
            'Cookie': cookieHeader
        }
    });

    const body = await res.text();
    assert.strictEqual(body.includes('SQLi Title'), false, "SQL Injection succeeded: page rendered SQL-injected 'SQLi Title'");
});

// A01:2025 - Broken Access Control & Session Management
test('A01:2025 - Broken Access Control: Cookie manipulation bypass attempts', async () => {
    // Forging isAdmin=true cookie
    const adminRes = await fetch('http://localhost:3000/admin', {
        headers: {
            'Cookie': 'isAdmin=true; user_id=1'
        },
        redirect: 'manual'
    });
    const adminBody = await adminRes.text();
    const isAdminBlocked = adminRes.status === 403 || adminRes.status === 302 || adminBody.includes('Accesso Negato');
    assert.strictEqual(isAdminBlocked, true, "Broken Access Control: Accessed /admin page by forging isAdmin=true cookie!");

    // Forging isDoctor=true cookie
    const doctorRes = await fetch('http://localhost:3000/doctor', {
        headers: {
            'Cookie': 'isDoctor=true; user_id=2'
        },
        redirect: 'manual'
    });
    const doctorBody = await doctorRes.text();
    const isDoctorBlocked = doctorRes.status === 403 || doctorRes.status === 302 || doctorBody.includes('Accesso Negato');
    assert.strictEqual(isDoctorBlocked, true, "Broken Access Control: Accessed /doctor page by forging isDoctor=true cookie!");
});

// A02:2025 - Cryptographic Failures
test('A02:2025 - Cryptographic Failures: Insecure MD5 Password Hashing', async () => {
    const dbPath = path.resolve(__dirname, '../database.sqlite');
    assert.strictEqual(fs.existsSync(dbPath), true, "SQLite database file must exist");

    const db = new sqlite3.Database(dbPath);
    const getAdminHash = () => {
        return new Promise((resolve, reject) => {
            db.get("SELECT password FROM users WHERE email = 'admin@medivibe.com'", (err, row) => {
                if (err) reject(err);
                else resolve(row ? row.password : null);
            });
        });
    };

    const passwordHash = await getAdminHash();
    db.close();

    assert.ok(passwordHash, "Admin password hash must be present in the database");
    
    // Check if it is MD5
    const isMD5 = /^[a-f0-9]{32}$/i.test(passwordHash);
    const isBcrypt = passwordHash.startsWith('$2') && passwordHash.length >= 60;

    assert.strictEqual(isMD5, false, `Cryptographic Failure: Password hash is in insecure MD5 format: ${passwordHash}`);
    assert.strictEqual(isBcrypt, true, `Password hash should be secure bcrypt format but got: ${passwordHash}`);
});

// A05:2025 - Security Misconfiguration (Hardcoded Secrets)
test('A05:2025 - Security Misconfiguration: Hardcoded credentials and API keys in codebase', () => {
    const serverJsPath = path.resolve(__dirname, '../server.js');
    const dbJsPath = path.resolve(__dirname, '../db.js');
    
    const serverContent = fs.readFileSync(serverJsPath, 'utf8');
    const dbContent = fs.readFileSync(dbJsPath, 'utf8');

    const hasSendGridKey = serverContent.includes('sg_test_12345_secret');
    assert.strictEqual(hasSendGridKey, false, "Security Misconfiguration: Hardcoded SendGrid API Key found in server.js!");

    const hasAdminSeed = dbContent.includes('admin123');
    assert.strictEqual(hasAdminSeed, false, "Security Misconfiguration: Hardcoded admin password seed 'admin123' found in db.js!");

    const hasDoctorSeed = dbContent.includes('doc123');
    assert.strictEqual(hasDoctorSeed, false, "Security Misconfiguration: Hardcoded doctor password seed 'doc123' found in db.js!");
});

// A04:2025 - Insecure File Upload & Path Traversal
test('A04:2025 - Insecure File Upload: Arbitrary file upload (HTML webshell)', async () => {
    const email = `upload_user_${Date.now()}@test.com`;
    await registerUser('Upload User', email, 'Password123!');
    const cookieHeader = await loginAndGetCookies(email, 'Password123!');

    const uploadUrl = 'http://localhost:3000/upload';
    const boundary = '----TestBoundary' + Math.random().toString(36).substring(2);
    const fileContent = '<h1>Malicious File Uploaded</h1>';
    const filename = 'security_test.html';

    const multipartBody = [
        `--${boundary}\r\n`,
        `Content-Disposition: form-data; name="reportFile"; filename="${filename}"\r\n`,
        `Content-Type: text/html\r\n\r\n`,
        `${fileContent}\r\n`,
        `--${boundary}\r\n`,
        `Content-Disposition: form-data; name="title"\r\n\r\n`,
        `Test Upload\r\n`,
        `--${boundary}--\r\n`
    ].join('');

    await fetch(uploadUrl, {
        method: 'POST',
        headers: {
            'Cookie': cookieHeader,
            'Content-Type': `multipart/form-data; boundary=${boundary}`
        },
        body: multipartBody
    });

    const uploadedFilePath = path.resolve(__dirname, '../public/uploads', filename);
    const fileExists = fs.existsSync(uploadedFilePath);

    if (fileExists) {
        try {
            fs.unlinkSync(uploadedFilePath);
        } catch (err) {
            console.error("Cleanup error:", err);
        }
    }

    assert.strictEqual(fileExists, false, "Insecure File Upload: HTML file was uploaded and created on disk!");
});

// A01:2025 - IDOR (Insecure Direct Object Reference)
test('A01:2025 - IDOR: Accessing other patients reports', async () => {
    // Register Patient A
    const emailA = `patient_a_${Date.now()}@test.com`;
    await registerUser('Patient A', emailA, 'Password123!');
    const cookieA = await loginAndGetCookies(emailA, 'Password123!');

    // Register Patient B
    const emailB = `patient_b_${Date.now()}@test.com`;
    await registerUser('Patient B', emailB, 'Password123!');
    
    // Find Patient B's report ID from SQLite
    const dbPath = path.resolve(__dirname, '../database.sqlite');
    const db = new sqlite3.Database(dbPath);
    
    const getReportId = (email) => {
        return new Promise((resolve, reject) => {
            db.get(`
                SELECT r.id 
                FROM reports r 
                JOIN users u ON r.user_id = u.id 
                WHERE u.email = ?
            `, [email], (err, row) => {
                if (err) reject(err);
                else resolve(row ? row.id : null);
            });
        });
    };

    const reportIdB = await getReportId(emailB);
    db.close();

    assert.ok(reportIdB, "Patient B should have a report");

    // Patient A accesses Patient B's report
    const res = await fetch(`http://localhost:3000/report?id=${reportIdB}`, {
        headers: {
            'Cookie': cookieA
        }
    });

    const body = await res.text();
    const isIdorBlocked = res.status === 403 || res.status === 302 || body.includes('Accesso Negato');

    assert.strictEqual(isIdorBlocked, true, `IDOR Vulnerability: Patient A accessed Patient B's report (ID: ${reportIdB}) with status ${res.status}`);
});
