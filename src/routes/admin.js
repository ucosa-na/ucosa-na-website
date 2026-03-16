const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const db = require('../db');
const requireAdmin = require('../middleware/requireAdmin');

const router = express.Router();

function makeTransport() {
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
}

function generatePassword(length = 10) {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// POST /api/admin/users — create a member and send welcome email
router.post('/users', requireAdmin, async (req, res) => {
  const { fullName, email } = req.body;
  if (!fullName || !email) {
    return res.status(400).json({ error: 'Full name and email are required' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (existing) return res.status(409).json({ error: 'A member with this email already exists' });

  const tempPassword = generatePassword();
  const hash = bcrypt.hashSync(tempPassword, 10);

  db.prepare(
    'INSERT INTO users (full_name, email, password_hash, must_change_password, role) VALUES (?, ?, ?, 1, ?)'
  ).run(fullName.trim(), email.toLowerCase().trim(), hash, 'member');

  try {
    const transport = makeTransport();
    await transport.sendMail({
      from: `"UCOSA-NA" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Welcome to UCOSA-North America — Your Login Details',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:32px;background:#f4f6f9;border-radius:12px">
          <h2 style="color:#1a1a2e">Welcome to UCOSA-North America!</h2>
          <p>Dear <strong>${fullName}</strong>,</p>
          <p>Your member account has been created. Use the details below to log in:</p>
          <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #1a1a2e">
            <p><strong>Login URL:</strong> <a href="https://ucosa-na.org/login.html">https://ucosa-na.org/login.html</a></p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Temporary Password:</strong> <code style="background:#f0f4ff;padding:4px 8px;border-radius:4px;font-size:1.1em">${tempPassword}</code></p>
          </div>
          <p style="color:#e63946"><strong>You will be asked to change your password on first login.</strong></p>
          <p>Welcome back to your old friends and brothers and sisters!</p>
          <p style="color:#888;font-size:0.85em;margin-top:24px">UCOSA-North America &mdash; <a href="mailto:ucosa.northamerica@gmail.com">ucosa.northamerica@gmail.com</a></p>
        </div>
      `,
    });
  } catch (err) {
    console.error('Email error:', err.message);
    return res.status(500).json({ error: 'Member created but email failed to send. Check EMAIL_USER and EMAIL_PASS.' });
  }

  res.status(201).json({ message: `Member created and welcome email sent to ${email}` });
});

// GET /api/admin/users — list all members
router.get('/users', requireAdmin, (req, res) => {
  const users = db.prepare(
    'SELECT id, full_name, email, role, must_change_password, created_at FROM users ORDER BY created_at DESC'
  ).all();
  res.json(users);
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ message: 'Member removed' });
});

module.exports = router;
