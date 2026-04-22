const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const requireAuth = require('../middleware/requireAuth');
const log = require('../logger');
const { sendEmail } = require('../mailer');

const router = express.Router();

const ALERT_TO = 'ucosa.northamerica@gmail.com';

// Per-email login attempt tracking: email → { count, lockedUntil }
const loginAttempts = new Map();
const MAX_ATTEMPTS  = 3;
const LOCK_MS       = 10 * 60 * 1000; // 10 minutes

function checkLock(email) {
  const entry = loginAttempts.get(email);
  if (!entry) return null;
  if (entry.lockedUntil && entry.lockedUntil > Date.now()) {
    const remaining = Math.ceil((entry.lockedUntil - Date.now()) / 60000);
    return `Too many failed attempts. Please wait ${remaining} minute${remaining !== 1 ? 's' : ''} and try again.`;
  }
  // Lock expired — reset
  if (entry.lockedUntil && entry.lockedUntil <= Date.now()) {
    loginAttempts.delete(email);
  }
  return null;
}

function recordFailure(email) {
  const entry = loginAttempts.get(email) || { count: 0, lockedUntil: null };
  entry.count += 1;
  if (entry.count >= MAX_ATTEMPTS) {
    entry.lockedUntil = Date.now() + LOCK_MS;
  }
  loginAttempts.set(email, entry);
}

function clearAttempts(email) {
  loginAttempts.delete(email);
}

async function getLocation(ip) {
  if (!ip || ip === '::1' || ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.')) {
    return 'Local / Private Network';
  }
  try {
    const res  = await fetch(`http://ip-api.com/json/${ip}?fields=status,city,regionName,country`);
    const data = await res.json();
    if (data.status === 'success') {
      return [data.city, data.regionName, data.country].filter(Boolean).join(', ');
    }
  } catch (_) {}
  return 'Unknown location';
}

async function sendMemberFailedLoginAlert(user, ip, location) {
  const ts = new Date().toLocaleString('en-US', { timeZone: 'UTC', dateStyle: 'full', timeStyle: 'long' });
  const phone = user.phone;

  // Email alert
  sendEmail({
    from: `"UCOSA-NA Security" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: '⚠️ Failed Login Attempt — UCOSA-NA',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
        <div style="background:#7b2152;text-align:center;padding:24px 32px">
          <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:80px;height:80px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 10px">
          <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
        </div>
        <div style="background:#f9f9f9;padding:32px">
          <h2 style="color:#c62828;margin-top:0;margin-bottom:8px">Failed Login Attempt</h2>
          <p style="color:#333;margin-bottom:16px">Someone tried to log in to your UCOSA-NA account and failed. Details below:</p>
          <table style="width:100%;border-collapse:collapse">
            <tr><td style="padding:10px 0;color:#555;font-weight:600;width:130px">Account</td><td style="padding:10px 0;color:#111">${user.email}</td></tr>
            <tr style="background:#f0f0f0"><td style="padding:10px 0;color:#555;font-weight:600">IP Address</td><td style="padding:10px 0;color:#111">${ip}</td></tr>
            <tr><td style="padding:10px 0;color:#555;font-weight:600">Location</td><td style="padding:10px 0;color:#111">${location}</td></tr>
            <tr style="background:#f0f0f0"><td style="padding:10px 0;color:#555;font-weight:600">Time (UTC)</td><td style="padding:10px 0;color:#111">${ts}</td></tr>
          </table>
          <p style="margin-top:20px;color:#555">If this was you, you may have mistyped your password. If not, please <strong>change your password immediately</strong> at <a href="https://ucosa-na.org/change-password.html">ucosa-na.org</a>.</p>
          <p style="margin-top:12px;font-size:0.85rem;color:#888">This is an automated security alert from UCOSA-NA.</p>
        </div>
      </div>`,
  }).catch(err => log.error(`Failed login email to ${user.email}: ${err.message}`));

  // SMS alert
  if (phone) {
    const sid  = process.env.TWILIO_ACCOUNT_SID;
    const token = process.env.TWILIO_AUTH_TOKEN;
    const from  = process.env.TWILIO_PHONE_NUMBER;
    if (sid && token && from) {
      require('twilio')(sid, token).messages.create({
        to: phone, from,
        body: `UCOSA-NA Security Alert: A failed login was attempted on your account from ${ip} (${location}) at ${ts}. If this wasn't you, change your password immediately at ucosa-na.org`,
      }).catch(err => log.error(`Failed login SMS to ${phone}: ${err.message}`));
    }
  }
}

function sendAdminLoginAlert(type, email, ip) {
  const isSuccess = type === 'success';
  const subject   = isSuccess
    ? '✅ Admin Login — UCOSA-NA'
    : '⚠️ Failed Admin Login Attempt — UCOSA-NA';
  const color  = isSuccess ? '#2e7d32' : '#c62828';
  const label  = isSuccess ? 'SUCCESSFUL LOGIN' : 'FAILED LOGIN ATTEMPT';
  const ts     = new Date().toLocaleString('en-US', { timeZone: 'UTC', dateStyle: 'full', timeStyle: 'long' });

  sendEmail({
    from: `"UCOSA-NA Security" <${process.env.EMAIL_USER}>`,
    to: ALERT_TO,
    subject,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
        <div style="background:#7b2152;text-align:center;padding:24px 32px">
          <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:80px;height:80px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 10px">
          <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
        </div>
        <div style="background:#f9f9f9;padding:32px">
          <h2 style="color:${color};margin-top:0;margin-bottom:8px">${label}</h2>
          <table style="width:100%;border-collapse:collapse;margin-top:16px">
            <tr><td style="padding:10px 0;color:#555;font-weight:600;width:130px">Account</td><td style="padding:10px 0;color:#111">${email}</td></tr>
            <tr style="background:#f0f0f0"><td style="padding:10px 0;color:#555;font-weight:600">IP Address</td><td style="padding:10px 0;color:#111">${ip}</td></tr>
            <tr><td style="padding:10px 0;color:#555;font-weight:600">Time (UTC)</td><td style="padding:10px 0;color:#111">${ts}</td></tr>
          </table>
          <p style="margin-top:20px;font-size:0.85rem;color:#888">This is an automated security alert from UCOSA-NA.</p>
        </div>
      </div>`,
  }).catch(err => log.error(`Admin login alert email failed: ${err.message}`));
}

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  // Check lockout before hitting the DB
  const lockMsg = checkLock(normalizedEmail);
  if (lockMsg) {
    log.warn(`Locked account login attempt: ${normalizedEmail} from IP ${req.ip}`);
    return res.status(429).json({ error: lockMsg });
  }

  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [normalizedEmail]
    );
    const user = rows[0];
    if (!user) {
      log.warn(`Failed login — unknown email: ${normalizedEmail} from IP ${req.ip}`);
      // Still record against the email to prevent enumeration timing attacks
      recordFailure(normalizedEmail);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      recordFailure(normalizedEmail);
      const entry = loginAttempts.get(normalizedEmail);
      const attemptsLeft = MAX_ATTEMPTS - (entry ? entry.count : 0);

      log.warn(`Failed login — wrong password for: ${user.email} from IP ${req.ip} (attempt ${entry ? entry.count : 1}/${MAX_ATTEMPTS})`);

      if (entry && entry.lockedUntil) {
        // Just got locked on this attempt
        if (user.role === 'admin') sendAdminLoginAlert('failed', user.email, req.ip);
        getLocation(req.ip).then(loc => sendMemberFailedLoginAlert(user, req.ip, loc));
        return res.status(429).json({ error: 'After 3 failed attempts, please wait 10 minutes and try again.' });
      }

      if (user.role === 'admin') sendAdminLoginAlert('failed', user.email, req.ip);
      getLocation(req.ip).then(loc => sendMemberFailedLoginAlert(user, req.ip, loc));

      return res.status(401).json({
        error: attemptsLeft > 0
          ? `Invalid email or password. ${attemptsLeft} attempt${attemptsLeft !== 1 ? 's' : ''} remaining before account is locked.`
          : 'Invalid email or password.',
      });
    }

    // Successful login — clear any failed attempt counter
    clearAttempts(normalizedEmail);

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
  // On a forced first-login change the member has just authenticated via JWT —
  // skip the current-password check to avoid temp-password copy/type errors.
  const isFirstLogin = !!req.user.mustChangePassword;

  if (!isFirstLogin && !currentPassword) {
    return res.status(400).json({ error: 'Current password is required' });
  }
  if (!newPassword) {
    return res.status(400).json({ error: 'New password is required' });
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

    // Only verify current password for voluntary (non-forced) changes
    if (!isFirstLogin) {
      const valid = await bcrypt.compare(currentPassword, user.password_hash);
      if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE id = $2',
      [hash, user.id]
    );

    const ts = new Date().toLocaleString('en-US', { timeZone: 'UTC', dateStyle: 'full', timeStyle: 'long' });
    sendEmail({
      from: `"UCOSA-NA Security" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: '🔑 Your UCOSA-NA Password Was Changed',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          <div style="background:#7b2152;text-align:center;padding:24px 32px">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:80px;height:80px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 10px">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
          </div>
          <div style="background:#f9f9f9;padding:32px">
            <h2 style="color:#1a1a2e;margin-top:0;margin-bottom:8px">Password Changed</h2>
            <p style="color:#333;margin-bottom:16px">Your UCOSA-NA account password was successfully changed.</p>
            <table style="width:100%;border-collapse:collapse">
              <tr><td style="padding:10px 0;color:#555;font-weight:600;width:130px">Account</td><td style="padding:10px 0;color:#111">${user.email}</td></tr>
              <tr style="background:#f0f0f0"><td style="padding:10px 0;color:#555;font-weight:600">Time (UTC)</td><td style="padding:10px 0;color:#111">${ts}</td></tr>
            </table>
            <p style="margin-top:20px;color:#555">If you did not make this change, please contact us immediately at <a href="mailto:ucosa.northamerica@gmail.com">ucosa.northamerica@gmail.com</a>.</p>
            <p style="margin-top:12px;font-size:0.85rem;color:#888">This is an automated security alert from UCOSA-NA.</p>
          </div>
        </div>`,
    }).catch(err => log.error(`Password change email to ${user.email}: ${err.message}`));

    // SMS alert
    if (user.phone) {
      const sid  = process.env.TWILIO_ACCOUNT_SID;
      const token = process.env.TWILIO_AUTH_TOKEN;
      const from  = process.env.TWILIO_PHONE_NUMBER;
      if (sid && token && from) {
        require('twilio')(sid, token).messages.create({
          to: user.phone, from,
          body: `UCOSA-NA: Your password was changed on ${ts}. If you did not do this, contact us immediately at ucosa.northamerica@gmail.com`,
        }).catch(err => log.error(`Password change SMS to ${user.phone}: ${err.message}`));
      }
    }

    log.info(`Password changed for: ${user.email} (role: ${user.role})`);

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
