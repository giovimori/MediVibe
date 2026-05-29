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
