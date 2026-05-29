const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { startServer, stopServer } = require('./helper');

before(async () => {
    await startServer();
});

after(() => {
    stopServer();
});

test('A02:2025 - Cryptographic Failures: Insecure MD5 Password Hashing', async () => {
    const dbPath = path.resolve(__dirname, '../database.sqlite');
    assert.strictEqual(fs.existsSync(dbPath), true, "SQLite database file must exist");

    const db = new sqlite3.Database(dbPath);
    const getAdminHash = () => {
        return new Promise((resolve, reject) => {
            db.get("SELECT password FROM users WHERE email = 'admin@medivibe.com'", (err, row) => {
                if (err) reject(err);
                else resolve(row ? row.password : null);
            });
        });
    };

    const passwordHash = await getAdminHash();
    db.close();

    assert.ok(passwordHash, "Admin password hash must be present in the database");
    
    // Check if it is MD5
    const isMD5 = /^[a-f0-9]{32}$/i.test(passwordHash);
    const isBcrypt = passwordHash.startsWith('$2') && passwordHash.length >= 60;

    assert.strictEqual(isMD5, false, `Cryptographic Failure: Password hash is in insecure MD5 format: ${passwordHash}`);
    assert.strictEqual(isBcrypt, true, `Password hash should be secure bcrypt format but got: ${passwordHash}`);
});
