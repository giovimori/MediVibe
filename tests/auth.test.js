const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer } = require('./helper');

before(async () => {
    await startServer();
});

after(() => {
    stopServer();
});

test('A01:2025 - Broken Access Control: Cookie manipulation bypass attempts', async () => {
    // Forging isAdmin=true cookie
    console.log(`\n[DEBUG Broken Access Control] Tentativo accesso /admin con cookie forgiato: "isAdmin=true; user_id=1"`);
    const adminRes = await fetch('http://localhost:3000/admin', {
        headers: {
            'Cookie': 'isAdmin=true; user_id=1'
        },
        redirect: 'manual'
    });
    const adminBody = await adminRes.text();
    const isAdminBlocked = adminRes.status === 403 || adminRes.status === 302 || adminBody.includes('Accesso Negato');

    console.log(`[DEBUG Broken Access Control] Stato Risposta /admin: ${adminRes.status}`);
    console.log(`[DEBUG Broken Access Control] Contenuto body parziale: "${adminBody.substring(0, 50).replace(/\n/g, '')}..."`);
    console.log(`[DEBUG Broken Access Control] Valore atteso (Accesso ad /admin bloccato?): true`);
    console.log(`[DEBUG Broken Access Control] Valore effettivo (Accesso ad /admin bloccato?): ${isAdminBlocked}`);

    assert.strictEqual(isAdminBlocked, true, `Broken Access Control: Accessed /admin page by forging isAdmin=true cookie! Status: ${adminRes.status}`);

    // Forging isDoctor=true cookie
    console.log(`\n[DEBUG Broken Access Control] Tentativo accesso /doctor con cookie forgiato: "isDoctor=true; user_id=2"`);
    const doctorRes = await fetch('http://localhost:3000/doctor', {
        headers: {
            'Cookie': 'isDoctor=true; user_id=2'
        },
        redirect: 'manual'
    });
    const doctorBody = await doctorRes.text();
    const isDoctorBlocked = doctorRes.status === 403 || doctorRes.status === 302 || doctorBody.includes('Accesso Negato');

    console.log(`[DEBUG Broken Access Control] Stato Risposta /doctor: ${doctorRes.status}`);
    console.log(`[DEBUG Broken Access Control] Contenuto body parziale: "${doctorBody.substring(0, 50).replace(/\n/g, '')}..."`);
    console.log(`[DEBUG Broken Access Control] Valore atteso (Accesso ad /doctor bloccato?): true`);
    console.log(`[DEBUG Broken Access Control] Valore effettivo (Accesso ad /doctor bloccato?): ${isDoctorBlocked}`);

    assert.strictEqual(isDoctorBlocked, true, `Broken Access Control: Accessed /doctor page by forging isDoctor=true cookie! Status: ${doctorRes.status}`);
});
