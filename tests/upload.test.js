const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { startServer, stopServer, registerUser, loginAndGetCookies } = require('./helper');

before(async () => {
    await startServer();
});

after(() => {
    stopServer();
});

test('A04:2025 - Insecure File Upload: Arbitrary file upload (HTML webshell)', async () => {
    const email = `upload_user_${Date.now()}@test.com`;
    await registerUser('Upload User', email, 'Password123!');
    const cookieHeader = await loginAndGetCookies(email, 'Password123!');

    const uploadUrl = 'http://localhost:3000/upload';
    const boundary = '----TestBoundary' + Math.random().toString(36).substring(2);
    const fileContent = '<h1>Malicious File Uploaded</h1>';
    const filename = 'security_test.html';

    console.log(`\n[DEBUG Insecure File Upload] Tentativo di upload file con nome: "${filename}"`);
    console.log(`[DEBUG Insecure File Upload] Content-Type: "text/html"`);

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

    const res = await fetch(uploadUrl, {
        method: 'POST',
        headers: {
            'Cookie': cookieHeader,
            'Content-Type': `multipart/form-data; boundary=${boundary}`
        },
        body: multipartBody
    });

    const uploadedFilePath = path.resolve(__dirname, '../public/uploads', filename);
    const fileExists = fs.existsSync(uploadedFilePath);

    console.log(`[DEBUG Insecure File Upload] Stato Risposta HTTP: ${res.status}`);
    console.log(`[DEBUG Insecure File Upload] File creato sul server in public/uploads/${filename}? ${fileExists}`);
    console.log(`[DEBUG Insecure File Upload] Valore atteso (File creato?): false`);
    console.log(`[DEBUG Insecure File Upload] Valore effettivo (File creato?): ${fileExists}`);

    if (fileExists) {
        try {
            fs.unlinkSync(uploadedFilePath);
            console.log(`[DEBUG Insecure File Upload] Cleanup: file rimosso con successo.`);
        } catch (err) {
            console.error("Cleanup error:", err);
        }
    }

    assert.strictEqual(fileExists, false, "Insecure File Upload: HTML file was uploaded and created on disk!");
});
