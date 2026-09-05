const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const app = express();

// VULNERABILITY 1: Hardcoded JWT secret
const JWT_SECRET = "super_secret_jwt_key_987654";

app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    // VULNERABILITY 2: OS Command Injection via exec string concatenation
    exec("ping -c 1 " + host, (err, stdout) => {
        if (err) return res.status(500).send("Error");
        res.send(stdout);
    });
});

app.post('/api/hash', (req, res) => {
    // VULNERABILITY 3: Weak MD5 Hash for passwords
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
    res.json({ hash });
});

module.exports = app;
