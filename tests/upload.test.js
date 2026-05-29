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

    await fetch(uploadUrl, {
        method: 'POST',
        headers: {
            'Cookie': cookieHeader,
            'Content-Type': `multipart/form-data; boundary=${boundary}`
        },
        body: multipartBody
    });

    const uploadedFilePath = path.resolve(__dirname, '../public/uploads', filename);
    const fileExists = fs.existsSync(uploadedFilePath);

    if (fileExists) {
        try {
            fs.unlinkSync(uploadedFilePath);
        } catch (err) {
            console.error("Cleanup error:", err);
        }
    }

    assert.strictEqual(fileExists, false, "Insecure File Upload: HTML file was uploaded and created on disk!");
});
