const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { Database } = require('sqlite3');
const path = require('path');
const { startServer, stopServer, registerUser, loginAndGetCookies } = require('./helper');

before(async () => {
    await startServer();
});

after(() => {
    stopServer();
});

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
    const db = new Database(dbPath);
    
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

    console.log(`\n[DEBUG IDOR] Eseguita registrazione di due pazienti (A e B).`);
    console.log(`[DEBUG IDOR] Paziente A loggato. Richiesta di visualizzazione referto del Paziente B (ID Referto: ${reportIdB}) con sessione di Paziente A.`);

    assert.ok(reportIdB, "Patient B should have a report");

    // Patient A accesses Patient B's report
    const res = await fetch(`http://localhost:3000/report?id=${reportIdB}`, {
        headers: {
            'Cookie': cookieA
        }
    });

    const body = await res.text();
    const isIdorBlocked = res.status === 403 || res.status === 302 || body.includes('Accesso Negato');

    console.log(`[DEBUG IDOR] Stato Risposta HTTP: ${res.status}`);
    console.log(`[DEBUG IDOR] Contenuto body parziale: "${body.substring(0, 50).replace(/\n/g, '')}..."`);
    console.log(`[DEBUG IDOR] Valore atteso (Accesso bloccato?): true`);
    console.log(`[DEBUG IDOR] Valore effettivo (Accesso bloccato?): ${isIdorBlocked}`);

    assert.strictEqual(isIdorBlocked, true, `IDOR Vulnerability: Patient A accessed Patient B's report (ID: ${reportIdB}) with status ${res.status}`);
});
