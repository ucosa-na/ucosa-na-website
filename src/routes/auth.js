const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const pool = require('../db');
const requireAuth = require('../middleware/requireAuth');
const log = require('../logger');

const router = express.Router();

const ALERT_TO = 'ucosa.northamerica@gmail.com';

function sendAdminLoginAlert(type, email, ip) {
  const isSuccess = type === 'success';
  const subject   = isSuccess
    ? '✅ Admin Login — UCOSA-NA'
    : '⚠️ Failed Admin Login Attempt — UCOSA-NA';
  const color  = isSuccess ? '#2e7d32' : '#c62828';
  const label  = isSuccess ? 'SUCCESSFUL LOGIN' : 'FAILED LOGIN ATTEMPT';
  const ts     = new Date().toLocaleString('en-US', { timeZone: 'UTC', dateStyle: 'full', timeStyle: 'long' });

  const transport = nodemailer.createTransport({
    host: 'smtp.sendgrid.net', port: 465, secure: true,
    auth: { user: 'apikey', pass: process.env.SENDGRID_API_KEY },
  });

  transport.sendMail({
    from: `"UCOSA-NA Security" <${process.env.EMAIL_USER}>`,
    to: ALERT_TO,
    subject,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9f9f9;border-radius:12px">
        <h2 style="color:${color};margin-bottom:8px">${label}</h2>
        <table style="width:100%;border-collapse:collapse;margin-top:16px">
          <tr><td style="padding:10px 0;color:#555;font-weight:600;width:130px">Account</td><td style="padding:10px 0;color:#111">${email}</td></tr>
          <tr style="background:#f0f0f0"><td style="padding:10px 0;color:#555;font-weight:600">IP Address</td><td style="padding:10px 0;color:#111">${ip}</td></tr>
          <tr><td style="padding:10px 0;color:#555;font-weight:600">Time (UTC)</td><td style="padding:10px 0;color:#111">${ts}</td></tr>
        </table>
        <p style="margin-top:20px;font-size:0.85rem;color:#888">This is an automated security alert from UCOSA-NA.</p>
      </div>`,
  }).catch(err => log.error(`Admin login alert email failed: ${err.message}`));
}

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    const user = rows[0];
    if (!user) {
      log.warn(`Failed login — unknown email: ${email.toLowerCase().trim()} from IP ${req.ip}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      log.warn(`Failed login — wrong password for: ${user.email} from IP ${req.ip}`);
      if (user.role === 'admin') sendAdminLoginAlert('failed', user.email, req.ip);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Record last login timestamp
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    log.info(`Login successful: ${user.email} (role: ${user.role}) from IP ${req.ip}`);
    if (user.role === 'admin') sendAdminLoginAlert('success', user.email, req.ip);

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, mustChangePassword: user.must_change_password },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      token,
      user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role },
      mustChangePassword: user.must_change_password,
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Both current and new password required' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (!/[A-Z]/.test(newPassword)) {
    return res.status(400).json({ error: 'Password must contain at least one uppercase letter' });
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword)) {
    return res.status(400).json({ error: 'Password must contain at least one special character' });
  }

  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE id = $2',
      [hash, user.id]
    );

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change-password error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/me
router.get('/me', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.full_name, u.email, u.role, u.must_change_password,
             p.first_name, p.last_name, p.address, p.phone, p.year_joined, p.graduation_year
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE u.id = $1
    `, [req.user.id]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      id: user.id,
      fullName: user.full_name,
      firstName: user.first_name || '',
      lastName: user.last_name || '',
      email: user.email,
      role: user.role,
      mustChangePassword: user.must_change_password,
      address: user.address || '',
      phone: user.phone || '',
      yearJoined: user.year_joined || '',
      graduationYear: user.graduation_year || '',
    });
  } catch (err) {
    console.error('Me error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/auth/profile — update contact info
router.put('/profile', requireAuth, async (req, res) => {
  const { address, phone } = req.body;
  try {
    await pool.query(
      'UPDATE users SET address = $1, phone = $2 WHERE id = $3',
      [address || null, phone || null, req.user.id]
    );
    await pool.query(`
      INSERT INTO member_profiles (user_id, address, phone)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id) DO UPDATE SET address = EXCLUDED.address, phone = EXCLUDED.phone, updated_at = NOW()
    `, [req.user.id, address || null, phone || null]);
    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('Profile update error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/member-count — public, returns total member count
router.get('/member-count', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT COUNT(*) AS count FROM users WHERE role = $1', ['member']);
    res.json({ count: parseInt(rows[0].count, 10) });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
