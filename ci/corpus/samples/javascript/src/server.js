'use strict';

const crypto = require('crypto');
const { execFile, exec } = require('child_process');
const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');

const app = express();
const ALLOWED_REDIRECTS = new Set(['/', '/dashboard', '/settings']);

app.use(express.static('public', { dotfiles: 'ignore' }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: 'lax' },
  }),
);

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function digest(body) {
  return crypto.createHash('sha256').update(body).digest('hex');
}

app.get('/login/callback', (req, res) => {
  const next = String(req.query.next || '/');
  res.redirect(ALLOWED_REDIRECTS.has(next) ? next : '/');
});

app.get('/go', (req, res) => {
  res.redirect(req.query.url);
});

app.get('/hello', (req, res) => {
  res.type('text/plain').send(`hello ${req.query.name}`);
});

app.post('/thumbnail', (req, res, next) => {
  const name = String(req.body.name || '');
  if (!/^[a-z0-9_-]+\.png$/.test(name)) {
    res.status(400).end();
    return;
  }
  execFile('convert', [name, '-resize', '128x128', `thumbs/${name}`], (error) => {
    if (error) {
      next(error);
      return;
    }
    res.json({ ok: true, token: newToken() });
  });
});

app.post('/archive', (req, res) => {
  exec(`tar czf /tmp/export.tgz ${req.body.dir}`, () => res.end());
});

function verify(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
}

function legacyVerify(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY);
}

function cacheKey(value) {
  return crypto.createHash('md5').update(value).digest('hex');
}

module.exports = { app, digest, verify, legacyVerify, cacheKey };
