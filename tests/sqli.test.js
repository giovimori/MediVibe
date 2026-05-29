const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, registerUser, loginAndGetCookies } = require('./helper');

before(async () => {
    await startServer();
});

after(() => {
    stopServer();
});

test('A03:2025 - Injection: SQL Injection in login (email field)', async () => {
    const sqlInjectionPayload = "admin@medivibe.com' --";
    console.log(`\n[DEBUG SQLi Login] Payload inviato nel campo email: "${sqlInjectionPayload}"`);
    console.log(`[DEBUG SQLi Login] Password inviata: "arbitrary_password"`);
    
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
    const location = res.headers.get('location');
    const isRedirectedToAuth = location && (location.includes('admin') || location.includes('dashboard'));

    console.log(`[DEBUG SQLi Login] Stato Risposta HTTP: ${res.status}`);
    console.log(`[DEBUG SQLi Login] Cookie rilevati: ${JSON.stringify(cookies)}`);
    console.log(`[DEBUG SQLi Login] Header Location di reindirizzamento: ${location || 'nessuno'}`);
    console.log(`[DEBUG SQLi Login] Valore atteso (Auth bypassato?): false`);
    console.log(`[DEBUG SQLi Login] Valore effettivo (Auth bypassato?): ${hasAuthCookie || !!isRedirectedToAuth}`);

    assert.strictEqual(hasAuthCookie, false, `SQL Injection bypass succeeded! Expected no auth cookie, but got: ${JSON.stringify(cookies)}`);
    assert.strictEqual(!!isRedirectedToAuth, false, `SQL Injection bypass succeeded! Expected no redirect to auth page, but got: ${location}`);
});

test('A03:2025 - Injection: SQL Injection in /report (id query parameter)', async () => {
    const email = `sqli_rep_${Date.now()}@test.com`;
    await registerUser('SQLi Rep User', email, 'Password123!');
    const cookieHeader = await loginAndGetCookies(email, 'Password123!');

    const payload = "-1 UNION SELECT 999, 999, 'SQLi Title', 'SQLi Content', 'SQLi Path', 'SQLi Patient'";
    console.log(`\n[DEBUG SQLi Report] Payload inviato nel parametro id: "${payload}"`);

    const res = await fetch(`http://localhost:3000/report?id=${encodeURIComponent(payload)}`, {
        headers: {
            'Cookie': cookieHeader
        }
    });

    const body = await res.text();
    const includesInjectedTitle = body.includes('SQLi Title');

    console.log(`[DEBUG SQLi Report] Stato Risposta HTTP: ${res.status}`);
    console.log(`[DEBUG SQLi Report] Valore atteso (Presenza 'SQLi Title' nel body?): false`);
    console.log(`[DEBUG SQLi Report] Valore effettivo (Presenza 'SQLi Title' nel body?): ${includesInjectedTitle}`);

    assert.strictEqual(includesInjectedTitle, false, "SQL Injection succeeded! The page rendered the injected union select row.");
});
