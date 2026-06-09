const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, registerUser } = require('./helper');

before(async () => {
    await startServer();
});

after(() => {
    stopServer();
});

test('Session Encryption At-Rest: Cifratura simmetrica AES-256 dei dati di sessione nello store', async () => {
    const email = `encrypt_user_${Date.now()}@test.com`;
    await registerUser('Encrypt User', email, 'Password123!');

    console.log(`\n[DEBUG Session Encryption] Eseguo login per ottenere una sessione attiva...`);
    const resLogin = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({ email, password: 'Password123!' }).toString(),
        redirect: 'manual'
    });

    const cookieHeader = resLogin.headers.getSetCookie().map(c => c.split(';')[0]).join('; ');
    console.log(`[DEBUG Session Encryption] Cookie di sessione rilevati: ${cookieHeader}`);

    const match = cookieHeader.match(/connect\.sid=s%3A([^.]+)/);
    const sid = match ? decodeURIComponent(match[1]) : null;
    console.log(`[DEBUG Session Encryption] Session ID (sid) estratto: ${sid}`);

    console.log(`[DEBUG Session Encryption] Valore atteso (Presenza Session ID server-side): true`);
    console.log(`[DEBUG Session Encryption] Valore effettivo: ${sid ? 'true' : 'false'}`);
    assert.ok(sid, "Non è stato possibile estrarre un Session ID valido. Sessioni server-side assenti o malconfigurate.");

    console.log(`[DEBUG Session Encryption] Richiedo il contenuto grezzo memorizzato nello store per sid: ${sid}`);
    const resDebug = await fetch(`http://localhost:3000/debug/raw-session/${sid}`);
    console.log(`[DEBUG Session Encryption] Stato HTTP risposta debug: ${resDebug.status}`);

    console.log(`[DEBUG Session Encryption] Valore atteso (Stato HTTP debug sessione): 200`);
    console.log(`[DEBUG Session Encryption] Valore effettivo: ${resDebug.status}`);
    assert.strictEqual(resDebug.status, 200, "L'endpoint di debug raw-session ha risposto con codice non previsto.");

    const data = await resDebug.json();
    const rawSessionStr = data.raw;
    console.log(`[DEBUG Session Encryption] Payload raw nello store: ${rawSessionStr}`);

    const isEncrypted = rawSessionStr.includes('encryptedPayload') && !rawSessionStr.includes('userId') && !rawSessionStr.includes(email);
    console.log(`[DEBUG Session Encryption] Valore atteso (Payload cifrato at-rest, senza segreti in chiaro): true`);
    console.log(`[DEBUG Session Encryption] Valore effettivo: ${isEncrypted}`);

    assert.strictEqual(isEncrypted, true, "I dati della sessione a riposo sono visibili in chiaro nello store!");
});
