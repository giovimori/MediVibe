const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, loginAndGetCookies, doctorEmail, doctorPassword } = require('./helper');

before(async () => {
    await startServer();
});

after(() => {
    stopServer();
});

test('Session Concurrency: Prevents simultaneous logins for the same doctor account', async () => {
    // 1. Log in the first time (Session A / Workstation A)
    console.log(`\n[DEBUG Concurrency] Effettuo il primo login per il medico (Sessione A)...`);
    const cookiesA = await loginAndGetCookies(doctorEmail, doctorPassword);
    console.log(`[DEBUG Concurrency] Sessione A ottenuta: ${cookiesA}`);

    // Verify Session A can access the doctor page
    const docResA1 = await fetch('http://localhost:3000/doctor', {
        headers: { 'Cookie': cookiesA },
        redirect: 'manual'
    });
    console.log(`[DEBUG Concurrency] Sessione A - Tentativo di accesso 1: HTTP ${docResA1.status}`);
    assert.strictEqual(docResA1.status, 200, "La Sessione A dovrebbe essere autorizzata prima del secondo login.");

    // 2. Log in a second time from a different workstation (Session B / Workstation B)
    console.log(`\n[DEBUG Concurrency] Effettuo il secondo login per lo stesso medico da altra postazione (Sessione B)...`);
    const cookiesB = await loginAndGetCookies(doctorEmail, doctorPassword);
    console.log(`[DEBUG Concurrency] Sessione B ottenuta: ${cookiesB}`);

    // Verify Session B can access the doctor page
    const docResB = await fetch('http://localhost:3000/doctor', {
        headers: { 'Cookie': cookiesB },
        redirect: 'manual'
    });
    console.log(`[DEBUG Concurrency] Sessione B - Tentativo di accesso: HTTP ${docResB.status}`);
    assert.strictEqual(docResB.status, 200, "La Sessione B dovrebbe essere attiva e autorizzata.");

    // 3. Now verify that Session A has been invalidated
    console.log(`\n[DEBUG Concurrency] Verifico se la Sessione A è stata correttamente invalidata...`);
    const docResA2 = await fetch('http://localhost:3000/doctor', {
        headers: { 'Cookie': cookiesA },
        redirect: 'manual'
    });
    console.log(`[DEBUG Concurrency] Sessione A - Tentativo di accesso 2 (post-Sessione B): HTTP ${docResA2.status}`);
    
    const bodyA2 = await docResA2.text();
    const isSessionAInvalidated = bodyA2.includes('Sessione terminata') || docResA2.status === 302 || docResA2.status === 403;
    
    console.log(`[DEBUG Concurrency] Presenza messaggio di disconnessione nel body della Sessione A? ${bodyA2.includes('Sessione terminata')}`);
    assert.strictEqual(isSessionAInvalidated, true, "La Sessione A dovrebbe essere disconnessa e invalidata dopo il login della Sessione B.");

    // 4. Verify Session B is still fully functional
    console.log(`\n[DEBUG Concurrency] Verifico che la Sessione B continui a funzionare senza problemi...`);
    const docResB2 = await fetch('http://localhost:3000/doctor', {
        headers: { 'Cookie': cookiesB },
        redirect: 'manual'
    });
    console.log(`[DEBUG Concurrency] Sessione B - Tentativo di accesso 2: HTTP ${docResB2.status}`);
    assert.strictEqual(docResB2.status, 200, "La Sessione B dovrebbe rimanere attiva e funzionante.");
});
