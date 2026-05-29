const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

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

module.exports = {
    isVulnerableBranch,
    adminEmail,
    adminPassword,
    doctorEmail,
    doctorPassword,
    startServer,
    stopServer,
    loginAndGetCookies,
    registerUser
};
