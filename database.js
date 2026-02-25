const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
require('dotenv').config();

const dbPath = path.resolve(__dirname, 'wagarda.db');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database ' + dbPath + ': ' + err.message);
    } else {
        console.log('Connected to the SQLite database.');
        createTables();
    }
});

function createTables() {
    db.run(`CREATE TABLE IF NOT EXISTS message_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        sender TEXT,
        recipient TEXT,
        message TEXT,
        status TEXT
    )`, (err) => {
        if (err) console.error('Error creating table message_logs: ' + err.message);
    });

    db.run(`CREATE TABLE IF NOT EXISTS login_audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        success BOOLEAN,
        ip_address TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) console.error('Error creating table login_audits: ' + err.message);
    });

    db.run(`CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) console.error('Error creating table api_keys: ' + err.message);
        else {
            db.get("SELECT count(*) as count FROM api_keys", [], (err, row) => {
                if (err) return console.error(err.message);
                if (row.count === 0) {
                    const defaultKey = process.env.DEFAULT_API_KEY;
                    if (defaultKey) {
                        createApiKey(defaultKey, 'Default API Key');
                        console.log(`Default API Key created from .env: ${defaultKey}`);
                    } else {
                        console.error('ERROR: DEFAULT_API_KEY is not set in .env. No default API key created.');
                    }
                }
            });
        }
    });

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) console.error('Error creating table users: ' + err.message);
        else {
            db.get("SELECT count(*) as count FROM users", [], (err, row) => {
                if (err) return console.error(err.message);
                if (row.count === 0) {
                    const defaultUser = process.env.DEFAULT_ADMIN_USER;
                    const defaultPass = process.env.DEFAULT_ADMIN_PASS;

                    if (defaultUser && defaultPass) {
                        bcrypt.hash(defaultPass, 10, (err, hash) => {
                            if (err) return console.error(err);
                            db.run("INSERT INTO users (username, password) VALUES (?, ?)", [defaultUser, hash]);
                            console.log(`Default Admin User created from .env: ${defaultUser}`);
                        });
                    } else {
                        console.error('ERROR: DEFAULT_ADMIN_USER or DEFAULT_ADMIN_PASS is not set in .env. No default admin user created.');
                    }
                }
            });
        }
    });
}

function logMessage(sender, recipient, message, status) {
    const sql = `INSERT INTO message_logs (sender, recipient, message, status) VALUES (?, ?, ?, ?)`;
    db.run(sql, [sender, recipient, message, status], function (err) {
        if (err) {
            return console.error(err.message);
        }
        console.log(`A row has been inserted with rowid ${this.lastID}`);
    });
}

function getLogs(limit = 100, callback) {
    const sql = `SELECT * FROM message_logs ORDER BY timestamp DESC LIMIT ?`;
    db.all(sql, [limit], (err, rows) => {
        if (err) {
            console.error(err.message);
            callback(err, null);
        } else {
            callback(null, rows);
        }
    });
}

function getApiKeys() {
    return new Promise((resolve, reject) => {
        const sql = `SELECT id, key, description, created_at FROM api_keys ORDER BY created_at DESC`;
        db.all(sql, [], (err, rows) => {
            if (err) reject(err);
            resolve(rows);
        });
    });
}

function deleteApiKey(id) {
    return new Promise((resolve, reject) => {
        const sql = `DELETE FROM api_keys WHERE id = ?`;
        db.run(sql, [id], function (err) {
            if (err) reject(err);
            resolve(this.changes > 0);
        });
    });
}

function createApiKey(key, description) {
    const sql = `INSERT INTO api_keys (key, description) VALUES (?, ?)`;
    db.run(sql, [key, description], function (err) {
        if (err) return console.error(err.message);
        console.log(`API Key created: ${key}`);
    });
}

function validateApiKey(key) {
    return new Promise((resolve, reject) => {
        const sql = `SELECT * FROM api_keys WHERE key = ?`;
        db.get(sql, [key], (err, row) => {
            if (err) reject(err);
            resolve(row);
        });
    });
}

function authenticateUser(username, password, ipAddress = 'unknown') {
    return new Promise((resolve, reject) => {
        // Step 1: Check if account is locked out (>= 5 consecutive fails in the last 30 minutes)
        const checkLockoutSql = `
            SELECT success 
            FROM login_audits 
            WHERE username = ? 
              AND timestamp > datetime('now', '-30 minutes') 
            ORDER BY timestamp DESC
        `;

        db.all(checkLockoutSql, [username], (err, rows) => {
            if (err) return reject(err);

            let consecutiveFails = 0;
            for (let row of rows) {
                if (row.success) break; // Stop counting if there's a success
                consecutiveFails++;
            }

            if (consecutiveFails >= 5) {
                console.warn(`[SECURITY] Account '${username}' is locked out due to too many failed attempts.`);
                return reject(new Error('Account locked. Please try again after 30 minutes.'));
            }

            // Step 2: Proceed with normal authentication
            db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
                if (err) {
                    reject(err);
                } else if (row) {
                    bcrypt.compare(password, row.password, (err, res) => {
                        if (res) {
                            // Hit: Successful login
                            db.run("INSERT INTO login_audits (username, success, ip_address) VALUES (?, 1, ?)", [username, ipAddress]);
                            resolve({ id: row.id, username: row.username });
                        } else {
                            // Miss: Wrong password
                            db.run("INSERT INTO login_audits (username, success, ip_address) VALUES (?, 0, ?)", [username, ipAddress]);
                            resolve(null);
                        }
                    });
                } else {
                    // Miss: User not found (still log it to prevent timing/username enumeration)
                    db.run("INSERT INTO login_audits (username, success, ip_address) VALUES (?, 0, ?)", [username, ipAddress]);
                    resolve(null);
                }
            });
        });
    });
}

module.exports = {
    db, logMessage, getLogs, createApiKey,
    validateApiKey,
    authenticateUser,
    getApiKeys,
    deleteApiKey
};
