const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, registerUser, isVulnerableBranch } = require('./helper');

before(async () => {
    await startServer();
});

after(() => {
    stopServer();
});

test('Session Binding: Legare la sessione al fingerprint del client (IP e User-Agent)', async () => {
    const email = `session_user_${Date.now()}@test.com`;
    await registerUser('Session User', email, 'Password123!');
    
    // Configurazione dei fingerprint
    const originalUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
    const hijackedUserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36';
    
    const originalIp = '203.0.113.195';
    const hijackedIp = '198.51.100.42';

    // 1. Eseguiamo il login con il fingerprint originale
    console.log(`\n[DEBUG Session Binding] Eseguo login per l'utente con fingerprint originale (IP: ${originalIp}, UA: "${originalUserAgent}")...`);
    const resLogin = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': originalUserAgent,
            'X-Forwarded-For': originalIp
        },
        body: new URLSearchParams({ email, password: 'Password123!' }).toString(),
        redirect: 'manual'
    });
    
    const cookies = resLogin.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
    console.log(`[DEBUG Session Binding] Cookie di sessione ottenuti: ${cookies}`);

    // 2. Accesso autorizzato con lo stesso fingerprint (Normal user)
    console.log(`[DEBUG Session Binding] Accesso autorizzato alla dashboard con fingerprint originale...`);
    const resNormal = await fetch('http://localhost:3000/dashboard', {
        headers: {
            'Cookie': cookies,
            'User-Agent': originalUserAgent,
            'X-Forwarded-For': originalIp
        },
        redirect: 'manual'
    });
    console.log(`[DEBUG Session Binding] Risposta accesso normale: HTTP ${resNormal.status}`);
    assert.strictEqual(resNormal.status, 200, "L'utente con fingerprint valido dovrebbe accedere alla dashboard (HTTP 200).");

    // 3. Hijack - Tentativo con User-Agent modificato (ma stesso IP)
    console.log(`\n[DEBUG Session Binding] CASO 1: Tentativo di hijacking modificando solo l'User-Agent (IP invariato)...`);
    const resHijackedUA = await fetch('http://localhost:3000/dashboard', {
        headers: {
            'Cookie': cookies,
            'User-Agent': hijackedUserAgent,
            'X-Forwarded-For': originalIp
        },
        redirect: 'manual'
    });
    console.log(`[DEBUG Session Binding] Risposta hijacking UA: HTTP ${resHijackedUA.status}`);

    if (isVulnerableBranch) {
        // RAMO VULNERABILE
        console.log(`[DEBUG Session Binding] Valore atteso (Ramo vulnerabile - Accesso con UA modificato): 200`);
        console.log(`[DEBUG Session Binding] Valore effettivo: ${resHijackedUA.status}`);
        assert.strictEqual(resHijackedUA.status, 200, "Su branch vulnerabile, l'accesso dovrebbe riuscire nonostante il cambio di User-Agent.");
    } else {
        // RAMO SICURO
        console.log(`[DEBUG Session Binding] Valore atteso (Ramo sicuro - Accesso con UA modificato): 403`);
        console.log(`[DEBUG Session Binding] Valore effettivo: ${resHijackedUA.status}`);
        assert.strictEqual(resHijackedUA.status, 403, "Su branch sicuro, il cambio di User-Agent deve produrre un HTTP 403 Forbidden.");
    }

    // Per testare il cambio di IP, creiamo un nuovo login / nuova sessione pulita
    const email2 = `session_user2_${Date.now()}@test.com`;
    await registerUser('Session User 2', email2, 'Password123!');

    console.log(`\n[DEBUG Session Binding] Eseguo un secondo login per utente2 con fingerprint originale (IP: ${originalIp}, UA: "${originalUserAgent}")...`);
    const resLogin2 = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': originalUserAgent,
            'X-Forwarded-For': originalIp
        },
        body: new URLSearchParams({ email: email2, password: 'Password123!' }).toString(),
        redirect: 'manual'
    });
    
    const cookies2 = resLogin2.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');

    // 4. Hijack - Tentativo con IP modificato (ma stesso User-Agent)
    console.log(`\n[DEBUG Session Binding] CASO 2: Tentativo di hijacking modificando solo l'IP (UA invariato)...`);
    const resHijackedIP = await fetch('http://localhost:3000/dashboard', {
        headers: {
            'Cookie': cookies2,
            'User-Agent': originalUserAgent,
            'X-Forwarded-For': hijackedIp
        },
        redirect: 'manual'
    });
    console.log(`[DEBUG Session Binding] Risposta hijacking IP: HTTP ${resHijackedIP.status}`);

    if (isVulnerableBranch) {
        // RAMO VULNERABILE
        console.log(`[DEBUG Session Binding] Valore atteso (Ramo vulnerabile - Accesso con IP modificato): 200`);
        console.log(`[DEBUG Session Binding] Valore effettivo: ${resHijackedIP.status}`);
        assert.strictEqual(resHijackedIP.status, 200, "Su branch vulnerabile, l'accesso dovrebbe riuscire nonostante il cambio di IP.");
    } else {
        // RAMO SICURO
        console.log(`[DEBUG Session Binding] Valore atteso (Ramo sicuro - Accesso con IP modificato): 403`);
        console.log(`[DEBUG Session Binding] Valore effettivo: ${resHijackedIP.status}`);
        assert.strictEqual(resHijackedIP.status, 403, "Su branch sicuro, il cambio di IP deve produrre un HTTP 403 Forbidden.");

        // 5. Verifica invalidazione: L'utente originale prova a riaccedere con la sessione violata al punto 4
        console.log(`\n[DEBUG Session Binding] CASO 3: Verifica invalidazione sessione violata (l'utente originale tenta di rientrare)...`);
        const resOriginalRetry = await fetch('http://localhost:3000/dashboard', {
            headers: {
                'Cookie': cookies2,
                'User-Agent': originalUserAgent,
                'X-Forwarded-For': originalIp
            },
            redirect: 'manual'
        });
        console.log(`[DEBUG Session Binding] Risposta rientro utente originale: HTTP ${resOriginalRetry.status}`);
        
        // La sessione dovrebbe essere stata distrutta sul server, provocando un redirect a /login (HTTP 302)
        const isRedirect = resOriginalRetry.status === 302 || resOriginalRetry.status === 303;
        console.log(`[DEBUG Session Binding] Valore atteso (Sessione invalidata e utente reindirizzato a login): true`);
        console.log(`[DEBUG Session Binding] Valore effettivo: ${isRedirect}`);
        assert.strictEqual(isRedirect, true, "La sessione originale deve essere invalidata (reindirizzamento a /login) dopo che è stata rilevata una violazione.");
    }
});
