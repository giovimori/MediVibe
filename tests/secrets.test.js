const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

test('A05:2025 - Security Misconfiguration: Hardcoded credentials and API keys in codebase', () => {
    const serverJsPath = path.resolve(__dirname, '../server.js');
    const dbJsPath = path.resolve(__dirname, '../db.js');
    
    const serverContent = fs.readFileSync(serverJsPath, 'utf8');
    const dbContent = fs.readFileSync(dbJsPath, 'utf8');

    const hasSendGridKey = serverContent.includes('sg_test_12345_secret');
    const hasAdminSeed = dbContent.includes('admin123');
    const hasDoctorSeed = dbContent.includes('doc123');

    console.log(`\n[DEBUG Hardcoded Secrets] Scansione dei file sorgente per verificare la presenza di segreti in chiaro...`);
    console.log(`[DEBUG Hardcoded Secrets] API Key SendGrid hardcodata ("sg_test_12345_secret") in server.js? Rilevata: ${hasSendGridKey}`);
    console.log(`[DEBUG Hardcoded Secrets] Password di seed admin hardcodata ("admin123") in db.js? Rilevata: ${hasAdminSeed}`);
    console.log(`[DEBUG Hardcoded Secrets] Password di seed medico hardcodata ("doc123") in db.js? Rilevata: ${hasDoctorSeed}`);
    console.log(`[DEBUG Hardcoded Secrets] Valore atteso (Rilevamenti di segreti): false`);
    console.log(`[DEBUG Hardcoded Secrets] Valore effettivo (Qualche segreto rilevato?): ${hasSendGridKey || hasAdminSeed || hasDoctorSeed}`);

    assert.strictEqual(hasSendGridKey, false, "Security Misconfiguration: Hardcoded SendGrid API Key found in server.js!");
    assert.strictEqual(hasAdminSeed, false, "Security Misconfiguration: Hardcoded admin password seed 'admin123' found in db.js!");
    assert.strictEqual(hasDoctorSeed, false, "Security Misconfiguration: Hardcoded doctor password seed 'doc123' found in db.js!");
});
