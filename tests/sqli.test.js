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
    
    assert.strictEqual(hasAuthCookie, false, "SQL Injection bypass succeeded: login was bypassed and cookies were set!");
    
    const location = res.headers.get('location');
    const isRedirectedToAuth = location && (location.includes('admin') || location.includes('dashboard'));
    assert.strictEqual(!!isRedirectedToAuth, false, "SQL Injection bypass succeeded: redirected to authenticated page: " + location);
});

test('A03:2025 - Injection: SQL Injection in /report (id query parameter)', async () => {
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
