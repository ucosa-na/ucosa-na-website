const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const pool = require('../db');
const requireAdmin = require('../middleware/requireAdmin');

const router = express.Router();

function makeTransport() {
  return nodemailer.createTransport({
    host: 'smtp.sendgrid.net',
    port: 587,
    secure: false,
    auth: {
      user: 'apikey',
      pass: process.env.SENDGRID_API_KEY,
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

  try {
    const { rows: existing } = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'A member with this email already exists' });
    }

    const tempPassword = generatePassword();
    const hash = await bcrypt.hash(tempPassword, 10);

    await pool.query(
      'INSERT INTO users (full_name, email, password_hash, must_change_password, role) VALUES ($1, $2, $3, TRUE, $4)',
      [fullName.trim(), email.toLowerCase().trim(), hash, 'member']
    );

    // Respond immediately with temp password — admin can share it manually if email fails.
    // Email is sent in the background so a slow/failing SMTP connection never
    // causes a client-side "Network error".
    res.status(201).json({
      message: `Member created. Welcome email will be sent to ${email}`,
      tempPassword,
    });

    // Fire-and-forget email
    const transport = makeTransport();
    transport.sendMail({
      from: `"UCOSA-NA" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Welcome to UCOSA-North America — Your Login Details',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:32px;background:#fdf6ec;border-radius:12px">
          <h2 style="color:#7b2152">Welcome to UCOSA-North America!</h2>
          <p>Dear <strong>${fullName}</strong>,</p>
          <p>Your member account has been created. Use the details below to log in:</p>
          <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #c8a96e">
            <p><strong>Login URL:</strong> <a href="https://ucosa-na.org">https://ucosa-na.org</a></p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Temporary Password:</strong> <code style="background:#f5ede0;padding:4px 10px;border-radius:4px;font-size:1.1em">${tempPassword}</code></p>
          </div>
          <p style="color:#7b2152"><strong>You will be asked to change your password on first login.</strong></p>
          <p>Welcome back to your old friends and brothers and sisters!</p>
          <p style="color:#888;font-size:0.85em;margin-top:24px">
            UCOSA-North America &mdash;
            <a href="mailto:ucosa.northamerica@gmail.com">ucosa.northamerica@gmail.com</a>
          </p>
        </div>
      `,
    }).catch(err => console.error('Welcome email failed for', email, ':', err.message));

  } catch (err) {
    console.error('Create member error:', err.message);
    res.status(500).json({ error: 'Failed to create member. ' + err.message });
  }
});

// POST /api/admin/test-email — send a test email to verify SMTP config
router.post('/test-email', requireAdmin, async (req, res) => {
  const { to } = req.body;
  if (!to) return res.status(400).json({ error: 'Recipient email required' });
  try {
    const transport = makeTransport();
    await transport.sendMail({
      from: `"UCOSA-NA" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'UCOSA-NA — Email Test',
      html: '<p>This is a test email from the UCOSA-NA admin panel. If you received this, email delivery is working correctly.</p>',
    });
    res.json({ message: `Test email sent to ${to}` });
  } catch (err) {
    res.status(500).json({ error: 'Email failed: ' + err.message });
  }
});

// GET /api/admin/users — list all members
router.get('/users', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, full_name, email, role, must_change_password, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    console.error('List users error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'Member removed' });
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
