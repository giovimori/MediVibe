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
    assert.strictEqual(hasSendGridKey, false, "Security Misconfiguration: Hardcoded SendGrid API Key found in server.js!");

    const hasAdminSeed = dbContent.includes('admin123');
    assert.strictEqual(hasAdminSeed, false, "Security Misconfiguration: Hardcoded admin password seed 'admin123' found in db.js!");

    const hasDoctorSeed = dbContent.includes('doc123');
    assert.strictEqual(hasDoctorSeed, false, "Security Misconfiguration: Hardcoded doctor password seed 'doc123' found in db.js!");
});
