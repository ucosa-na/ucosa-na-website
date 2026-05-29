const express = require('express');
const bcrypt = require('bcryptjs');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const multer = require('multer');
const pool = require('../db');
const requireRole = require('../middleware/requireRole');
const requireAuth = require('../middleware/requireAuth');
const log = require('../logger');
const { sendEmail } = require('../mailer');

const csvUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// Role shorthand helpers
const adminOnly       = requireRole('admin');
const finOrAdmin      = requireRole('admin', 'fin-role');
const secOrAdmin      = requireRole('admin', 'security-role');
const anyPriv         = requireRole('admin', 'fin-role', 'security-role', 'pro-role', 'welfare');
const proOrAdmin      = requireRole('admin', 'pro-role');
const welfareOrAdmin  = requireRole('admin', 'welfare');

const router = express.Router();

// ── Shared payment receipt email ──────────────────────────────────────────────
function paymentReceiptHtml(memberName, items, ref) {
  const total = items.reduce((sum, i) => sum + parseFloat(i.amount), 0).toFixed(2);
  const rows = items.map(i =>
    `<tr><td style="padding:6px 12px;">${i.label}</td><td style="padding:6px 12px;font-weight:700;color:#1b5e20;">$${parseFloat(i.amount).toFixed(2)}</td></tr>`
  ).join('');
  return `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#333;">
      <div style="background:#1a1a2e;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;">
        <h1 style="color:#fff;margin:0;font-size:22px;">Payment Receipt</h1>
      </div>
      <div style="background:#f9f9f9;padding:28px 32px;border-radius:0 0 10px 10px;">
        <p>Dear <strong>${memberName}</strong>,</p>
        <p>Your payment has been recorded. Here is your receipt:</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
          <thead><tr style="background:#1a1a2e;color:#fff;">
            <th style="padding:10px 12px;text-align:left;">Description</th>
            <th style="padding:10px 12px;text-align:left;">Amount</th>
          </tr></thead>
          <tbody>${rows}</tbody>
          <tfoot><tr style="border-top:2px solid #eee;">
            <td style="padding:10px 12px;font-weight:700;">Total</td>
            <td style="padding:10px 12px;font-weight:700;color:#1b5e20;">$${total}</td>
          </tr></tfoot>
        </table>
        <p style="font-size:13px;color:#888;">Reference: ${ref}</p>
        <p style="font-size:13px;color:#888;">Date: ${new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})}</p>
        <p style="margin-top:20px;">Thank you for your continued support of UCOSA-NA and Ugbeka College.</p>
        <p style="color:#888;font-size:13px;">— UCOSA-North America</p>
      </div>
    </div>`;
}

// ── AUDIT HELPER ──────────────────────────────────────────────────────────────
async function logAudit(performedById, performedByName, action, entityType, entityId, entityName, details) {
  try {
    await pool.query(
      `INSERT INTO audit_log (action, entity_type, entity_id, entity_name, performed_by, performed_by_name, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [action, entityType, entityId || null, entityName || null,
       performedById || null, performedByName || null,
       details ? JSON.stringify(details) : null]
    );
  } catch (err) {
    log.error(`Audit log insert failed: ${err.message}`);
  }
}

// ── DUES REMINDER EMAIL HELPER ────────────────────────────────────────────────
function duesReminderHtml(name, year, dueDate, amount, status) {
  const statusLabel = status
    ? status.charAt(0).toUpperCase() + status.slice(1)
    : 'Unpaid';
  return `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#333;">
      <div style="background:#1a1a2e;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;">
        <h1 style="color:#fff;margin:0;font-size:20px;">Annual Dues Reminder</h1>
      </div>
      <div style="background:#f9f9f9;padding:28px 32px;border-radius:0 0 10px 10px;">
        <p>Dear <strong>${name}</strong>,</p>
        <p>This is a friendly reminder that your <strong>${year} annual dues</strong> are due on <strong>${dueDate}</strong>.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
          <tbody>
            <tr><td style="padding:10px 16px;font-weight:600;color:#555;width:140px;">Due Date</td><td style="padding:10px 16px;">${dueDate}</td></tr>
            <tr style="background:#f4f4f4;"><td style="padding:10px 16px;font-weight:600;color:#555;">Amount</td><td style="padding:10px 16px;">${amount}</td></tr>
            <tr><td style="padding:10px 16px;font-weight:600;color:#555;">Status</td><td style="padding:10px 16px;">${statusLabel}</td></tr>
            <tr style="background:#f4f4f4;"><td style="padding:10px 16px;font-weight:600;color:#555;">Payment Info</td><td style="padding:10px 16px;">Zelle to &mdash; ucosa.northamerica@gmail.com</td></tr>
          </tbody>
        </table>
        <p><em>If you've already made your payment, please ignore this message &mdash; and thank you!</em></p>
        <p style="color:#888;font-size:13px;">— UCOSA-North America</p>
      </div>
    </div>`;
}

// ── SMS HELPER — tries Twilio first, falls back to Vonage ─────────────────────
async function sendSMS(to, body) {
  // ── Try Twilio first ──
  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from  = process.env.TWILIO_PHONE_NUMBER;
  if (sid && token && from) {
    try {
      await require('twilio')(sid, token).messages.create({ to, from, body });
      log.info(`SMS sent via Twilio to ${to}`);
      return true;
    } catch (err) {
      log.warn(`Twilio SMS failed for ${to}: ${err.message} — trying Vonage`);
    }
  }

  // ── Fall back to Vonage ──
  const vonageKey    = process.env.VONAGE_API_KEY;
  const vonageSecret = process.env.VONAGE_API_SECRET;
  const vonageFrom   = process.env.VONAGE_PHONE_NUMBER || 'UCOSA-NA';
  if (!vonageKey || !vonageSecret) { log.warn('SMS skipped: neither Twilio nor Vonage configured'); return false; }
  try {
    const { Vonage } = require('@vonage/server-sdk');
    const vonage = new Vonage({ apiKey: vonageKey, apiSecret: vonageSecret });
    const result = await vonage.sms.send({ to, from: vonageFrom, text: body });
    const msg = result?.messages?.[0];
    const status = msg?.status;
    if (status === '0') {
      log.info(`SMS sent via Vonage to ${to}`);
      return true;
    } else {
      log.warn(`Vonage SMS rejected for ${to}: status=${status} error="${msg?.['error-text']}"`);
      return false;
    }
  } catch (err) {
    log.warn(`Vonage SMS failed for ${to}: ${err.message}`);
    return false;
  }
}


function checkEmailConfig() {
  const missing = [];
  if (!process.env.SENDGRID_API_KEY) missing.push('SENDGRID_API_KEY');
  if (!process.env.EMAIL_USER)        missing.push('EMAIL_USER');
  return missing;
}

function generatePassword(length = 10) {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$';
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// Seed annual_dues records from memberSinceYear up to the current year
async function seedDuesForMember(userId, memberSinceYear, recordedById) {
  const currentYear = new Date().getFullYear();
  const startYear   = parseInt(memberSinceYear);
  if (!startYear || startYear > currentYear) return;
  for (let year = startYear; year <= currentYear; year++) {
    await pool.query(`
      INSERT INTO annual_dues (user_id, year, amount, status, due_date, paid_date, payment_method, recorded_by)
      SELECT $1, $2, 100.00, 'unpaid', $3, NULL, NULL, $4
      WHERE NOT EXISTS (SELECT 1 FROM annual_dues WHERE user_id = $1 AND year = $2)
    `, [userId, year, `${year}-06-01`, recordedById]);
  }
}

// Seed endowment_fund records from max(memberSinceYear, 2024) up to the current year
async function seedEndowmentForMember(userId, memberSinceYear, recordedById) {
  const currentYear = new Date().getFullYear();
  const startYear   = Math.max(parseInt(memberSinceYear) || 2024, 2024);
  for (let year = startYear; year <= currentYear; year++) {
    await pool.query(`
      INSERT INTO endowment_fund (user_id, year, amount, status, contribution_date, payment_method, recorded_by)
      SELECT $1, $2, 0, 'pending', NULL, NULL, $3
      WHERE NOT EXISTS (SELECT 1 FROM endowment_fund WHERE user_id = $1 AND year = $2)
    `, [userId, year, recordedById]);
  }
}

// POST /api/admin/users — create a member and send welcome email
router.post('/users', secOrAdmin, async (req, res) => {
  const { firstName, lastName, email, address, phone, yearJoined, graduationYear, role } = req.body;
  if (!firstName || !lastName || !email || !phone) {
    return res.status(400).json({ error: 'First name, last name, email, and phone number are required' });
  }

  const validRoles = ['member', 'fin-role', 'security-role', 'pro-role', 'welfare', 'admin'];
  const assignedRole = role && validRoles.includes(role) ? role : 'member';

  // Only admins can create admin accounts
  if (assignedRole === 'admin' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only admins can assign the admin role' });
  }

  const fullName = `${firstName.trim()} ${lastName.trim()}`;
  const emailVal = email.toLowerCase().trim();

  try {
    const { rows: existing } = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [emailVal]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'A member with this email already exists' });
    }

    const tempPassword = generatePassword();
    const hash = await bcrypt.hash(tempPassword, 10);

    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
    const { rows: inserted } = await pool.query(
      'INSERT INTO users (full_name, email, password_hash, must_change_password, password_expires_at, role, created_by) VALUES ($1, $2, $3, TRUE, $4, $5, $6) RETURNING id',
      [fullName, emailVal, hash, expiresAt, assignedRole, req.user.id]
    );
    const userId = inserted[0].id;

    await pool.query(
      `INSERT INTO member_profiles (user_id, first_name, last_name, address, phone, year_joined, graduation_year)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, firstName.trim(), lastName.trim(), address || null, phone || null,
       yearJoined ? parseInt(yearJoined) : null, graduationYear ? parseInt(graduationYear) : null]
    );

    // Also mirror address/phone to users table for backward compatibility
    if (address || phone) {
      await pool.query(
        'UPDATE users SET address = $1, phone = $2 WHERE id = $3',
        [address || null, phone || null, userId]
      );
    }

    // Seed annual dues and endowment records from member_since (year_joined) through current year
    if (yearJoined) await seedDuesForMember(userId, yearJoined, req.user.id);
    await seedEndowmentForMember(userId, yearJoined, req.user.id);

    log.info(`Member created: ${fullName} (${emailVal}) by user ${req.user.id}`);
    await logAudit(req.user.id, req.user.email, 'MEMBER_CREATED', 'MEMBER', userId, fullName, { email: emailVal, role: assignedRole });

    // Send welcome SMS (awaited so we can report status in the response)
    let smsSent = false;
    if (phone) {
      try {
        await sendSMS(phone,
          `Welcome to UCOSA-NA, ${fullName}!\n` +
          `Login: https://ucosa-na.org\n` +
          `Email: ${emailVal}\n` +
          `Temp password: ${tempPassword}\n` +
          `This password expires in 48 hours. Please change it on first login.`
        );
        smsSent = true;
        log.info(`Welcome SMS sent to ${phone} for ${fullName}`);
      } catch (err) {
        log.error(`Welcome SMS failed for ${phone} (${fullName}): ${err.message}`);
      }
    }

    // Respond with SMS status included
    const smsNote = phone
      ? (smsSent ? ` Welcome SMS sent to ${phone}.` : ` SMS to ${phone} failed — check Twilio config.`)
      : ' No phone number provided — SMS skipped.';

    res.status(201).json({
      message: `Member ${fullName} created.${smsNote}`,
      tempPassword,
      smsSent,
    });

    // Fire-and-forget welcome email
    sendEmail({
      to: emailVal,
      subject: 'Welcome to UCOSA-North America — Your Login Details',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          <div style="background:#7b2152;text-align:center;padding:28px 32px">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
          </div>
          <div style="background:#fdf6ec;padding:32px">
            <h2 style="color:#7b2152;margin-top:0">Welcome to UCOSA-North America!</h2>
            <p>Dear <strong>${fullName}</strong>,</p>
            <p>Your member account has been created. Use the details below to log in:</p>
            <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #c8a96e">
              <p><strong>Login URL:</strong> <a href="https://ucosa-na.org">https://ucosa-na.org</a></p>
              <p><strong>Email:</strong> ${emailVal}</p>
              <p><strong>Temporary Password:</strong> <code style="background:#f5ede0;padding:4px 10px;border-radius:4px;font-size:1.1em">${tempPassword}</code></p>
              <p style="color:#c0392b;font-size:0.9em">⚠️ This password expires in <strong>48 hours</strong>. Please log in and change it before it expires.</p>
            </div>
            <p style="color:#7b2152"><strong>You will be asked to change your password on first login.</strong></p>
            <p>Welcome back to your old friends and brothers and sisters!</p>
            <p style="color:#888;font-size:0.85em;margin-top:24px">
              UCOSA-North America &mdash;
              <a href="mailto:admin@ucosa-na.org">admin@ucosa-na.org</a>
            </p>
          </div>
        </div>
      `,
    })
      .then(() => log.info(`Welcome email sent to ${emailVal}`))
      .catch(err => log.error(`Welcome email failed for ${emailVal}: ${err.message}`));

  } catch (err) {
    log.error(`Create member error: ${err.message}`);
    res.status(500).json({ error: 'Failed to create member. ' + err.message });
  }
});

// POST /api/admin/test-email — send a test email to verify SMTP config
router.post('/test-email', adminOnly, async (req, res) => {
  const { to } = req.body;
  if (!to) return res.status(400).json({ error: 'Recipient email required' });

  const missing = checkEmailConfig();
  if (missing.length) {
    return res.status(500).json({
      error: `Missing server environment variable(s): ${missing.join(', ')}. Set these in /opt/ucosa-na/.env on the server and restart the container.`
    });
  }

  const senderEmail = process.env.EMAIL_USER;

  try {
    await sendEmail({
      to,
      subject: 'UCOSA-NA — Email Test',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          <div style="background:#7b2152;text-align:center;padding:28px 32px">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
          </div>
          <div style="background:#fdf6ec;padding:32px">
            <p style="color:#333;margin:0">This is a test email from the UCOSA-NA admin panel. If you received this, email delivery is working correctly.</p>
          </div>
        </div>
      `,
    });
    res.json({ message: `Test email sent to ${to} (from: ${senderEmail})` });
  } catch (err) {
    console.error('Test email error:', err.message);
    res.status(500).json({ error: `Email failed (from: ${senderEmail}): ${err.message}` });
  }
});

// GET /api/admin/users — list all members with profile data
router.get('/users', anyPriv, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.full_name, u.email, u.role, u.must_change_password, u.is_active, u.is_locked, u.created_at, u.last_login,
             COALESCE(p.first_name, split_part(u.full_name, ' ', 1))  AS first_name,
             COALESCE(p.last_name,  NULLIF(substring(u.full_name FROM position(' ' IN u.full_name) + 1), '')) AS last_name,
             p.address, p.phone, p.year_joined, p.graduation_year
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE u.id != 1
      ORDER BY u.full_name ASC
    `);
    res.json(rows);
  } catch (err) {
    console.error('List users error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/admin/users/export-csv — download all members as CSV
router.get('/users/export-csv', secOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.full_name, u.email, u.role,
             p.first_name, p.last_name,
             COALESCE(p.phone, u.phone) AS phone,
             COALESCE(p.address, u.address) AS address,
             p.year_joined, p.graduation_year,
             u.is_active, u.is_locked, u.created_at, u.last_login
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE u.id != 1
      ORDER BY u.full_name ASC
    `);

    const headers = ['full_name','email','role','first_name','last_name','phone','address','year_joined','graduation_year','is_active','is_locked','created_at','last_login'];
    const escape  = v => v == null ? '' : `"${String(v).replace(/"/g, '""')}"`;
    const csv     = [headers.join(','), ...rows.map(r => headers.map(h => escape(r[h])).join(','))].join('\r\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="ucosa-members-${new Date().toISOString().slice(0,10)}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('Export CSV error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/admin/users/bulk-import — create members from uploaded CSV/TXT file
router.post('/users/bulk-import', secOrAdmin, csvUpload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const text = req.file.buffer.toString('utf-8');
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (lines.length < 2) return res.status(400).json({ error: 'File must have a header row and at least one data row' });

  // Parse CSV line respecting quoted fields
  function parseCSVLine(line) {
    const result = [];
    let cur = '', inQuote = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') { inQuote = !inQuote; continue; }
      if (ch === ',' && !inQuote) { result.push(cur.trim()); cur = ''; continue; }
      cur += ch;
    }
    result.push(cur.trim());
    return result;
  }

  const headers = parseCSVLine(lines[0]).map(h => h.toLowerCase().replace(/\s+/g,'_'));
  const col = (row, name) => {
    const idx = headers.indexOf(name);
    return idx !== -1 ? (row[idx] || '').trim() : '';
  };

  const validRoles = ['member', 'fin-role', 'security-role', 'pro-role', 'welfare'];
  const created = [], skipped = [], failed = [];

  for (let i = 1; i < lines.length; i++) {
    const row = parseCSVLine(lines[i]);
    const firstName     = col(row, 'first_name');
    const lastName      = col(row, 'last_name');
    const email         = col(row, 'email').toLowerCase();
    const phone         = col(row, 'phone');
    const address       = col(row, 'address');
    const yearJoined    = col(row, 'year_joined');
    const gradYear      = col(row, 'graduation_year');
    const role          = validRoles.includes(col(row, 'role')) ? col(row, 'role') : 'member';
    const fullName      = `${firstName} ${lastName}`.trim();

    if (!firstName || !lastName || !email) {
      skipped.push({ row: i + 1, reason: 'Missing first_name, last_name or email', email: email || '—' });
      continue;
    }

    try {
      const { rows: existing } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      if (existing.length > 0) {
        skipped.push({ row: i + 1, reason: 'Email already exists', email });
        continue;
      }

      const tempPassword = generatePassword();
      const hash = await bcrypt.hash(tempPassword, 10);
      const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);

      const { rows: inserted } = await pool.query(
        'INSERT INTO users (full_name, email, password_hash, must_change_password, password_expires_at, role, created_by) VALUES ($1,$2,$3,TRUE,$4,$5,$6) RETURNING id',
        [fullName, email, hash, expiresAt, role, req.user.id]
      );
      const userId = inserted[0].id;

      await pool.query(
        `INSERT INTO member_profiles (user_id, first_name, last_name, address, phone, year_joined, graduation_year) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [userId, firstName, lastName, address || null, phone || null,
         yearJoined ? parseInt(yearJoined) : null, gradYear ? parseInt(gradYear) : null]
      );

      if (address || phone) {
        await pool.query('UPDATE users SET address=$1, phone=$2 WHERE id=$3', [address || null, phone || null, userId]);
      }

      // Seed annual dues and endowment records from year_joined through current year
      if (yearJoined) await seedDuesForMember(userId, yearJoined, req.user.id);
      await seedEndowmentForMember(userId, yearJoined, req.user.id);

      await logAudit(req.user.id, req.user.email, 'MEMBER_CREATED', 'MEMBER', userId, fullName, { email, role, source: 'bulk-import' });
      log.info(`Bulk import: created ${fullName} (${email})`);

      // Send welcome SMS
      let smsSent = false;
      if (phone) {
        try {
          await sendSMS(phone,
            `Welcome to UCOSA-NA, ${fullName}!\n` +
            `Login: https://ucosa-na.org\n` +
            `Email: ${email}\n` +
            `Temp password: ${tempPassword}\n` +
            `Expires in 48 hours. Please change it on first login.`
          );
          smsSent = true;
        } catch (e) { log.error(`Bulk SMS failed for ${phone}: ${e.message}`); }
      }

      // Send welcome email (fire and forget)
      sendEmail({
        to: email,
        subject: 'Welcome to UCOSA-North America — Your Login Details',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
            <div style="background:#7b2152;text-align:center;padding:28px 32px">
              <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
              <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
            </div>
            <div style="background:#fdf6ec;padding:32px">
              <h2 style="color:#7b2152;margin-top:0">Welcome to UCOSA-North America!</h2>
              <p>Dear <strong>${fullName}</strong>,</p>
              <p>Your member account has been created. Use the details below to log in:</p>
              <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #c8a96e">
                <p><strong>Login URL:</strong> <a href="https://ucosa-na.org">https://ucosa-na.org</a></p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Temporary Password:</strong> <code style="background:#f5ede0;padding:4px 10px;border-radius:4px;font-size:1.1em">${tempPassword}</code></p>
                <p style="color:#c0392b;font-size:0.9em">⚠️ This password expires in <strong>48 hours</strong>. Please log in and change it before it expires.</p>
              </div>
              <p style="color:#7b2152"><strong>You will be asked to change your password on first login.</strong></p>
              <p>Welcome back to your old friends and brothers and sisters!</p>
              <p style="color:#888;font-size:0.85em;margin-top:24px">UCOSA-North America &mdash; <a href="mailto:admin@ucosa-na.org">admin@ucosa-na.org</a></p>
            </div>
          </div>`,
      }).then(() => log.info(`Bulk welcome email sent to ${email}`))
        .catch(e => log.error(`Bulk welcome email failed for ${email}: ${e.message}`));

      created.push({ row: i + 1, name: fullName, email, smsSent });

    } catch (err) {
      log.error(`Bulk import row ${i + 1} error: ${err.message}`);
      failed.push({ row: i + 1, email: email || '—', reason: err.message });
    }
  }

  res.json({
    message: `Import complete. Created: ${created.length}, Skipped: ${skipped.length}, Failed: ${failed.length}`,
    created, skipped, failed,
  });
});

// GET /api/admin/welfare/members — member directory for welfare role (name, phone, email only)
router.get('/welfare/members', welfareOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.full_name, u.email,
             COALESCE(p.phone, u.phone) AS phone
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE u.id != 1
      ORDER BY u.full_name ASC
    `);
    res.json(rows);
  } catch (err) {
    console.error('Welfare members error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/admin/users/:id — update member info
router.put('/users/:id', secOrAdmin, async (req, res) => {
  const { firstName, lastName, email, address, phone, yearJoined, graduationYear } = req.body;
  if (!firstName || !lastName || !email) {
    return res.status(400).json({ error: 'First name, last name, and email are required' });
  }
  const fullName = `${firstName.trim()} ${lastName.trim()}`;
  const emailVal = email.toLowerCase().trim();
  try {
    const { rows: existing } = await pool.query(
      'SELECT id FROM users WHERE email = $1 AND id != $2',
      [emailVal, req.params.id]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Email already in use by another member' });
    }
    await pool.query(
      'UPDATE users SET full_name=$1, email=$2, address=$3, phone=$4, updated_by=$5, updated_at=NOW() WHERE id=$6',
      [fullName, emailVal, address || null, phone || null, req.user.id, req.params.id]
    );
    await pool.query(`
      INSERT INTO member_profiles (user_id, first_name, last_name, address, phone, year_joined, graduation_year)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (user_id) DO UPDATE SET
        first_name=$2, last_name=$3, address=$4, phone=$5,
        year_joined=$6, graduation_year=$7, updated_at=NOW()
    `, [req.params.id, firstName.trim(), lastName.trim(), address || null, phone || null,
        yearJoined ? parseInt(yearJoined) : null, graduationYear ? parseInt(graduationYear) : null]);
    await logAudit(req.user.id, req.user.email, 'MEMBER_UPDATED', 'MEMBER', parseInt(req.params.id), fullName, { email: emailVal, address, phone, yearJoined, graduationYear });
    res.json({ message: 'Member updated' });
  } catch (err) {
    console.error('Update member error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/admin/users/:id/role — change a member's role (admin only)
router.put('/users/:id/role', adminOnly, async (req, res) => {
  const { role } = req.body;
  const validRoles = ['admin', 'member', 'fin-role', 'security-role', 'pro-role', 'welfare'];
  if (!role || !validRoles.includes(role)) {
    return res.status(400).json({ error: 'Valid role required: admin, member, fin-role, security-role, pro-role' });
  }
  try {
    const { rows: before } = await pool.query('SELECT full_name, role FROM users WHERE id = $1', [req.params.id]);
    if (!before.length) return res.status(404).json({ error: 'User not found' });
    const oldRole = before[0].role;
    await pool.query('UPDATE users SET role=$1, updated_by=$2, updated_at=NOW() WHERE id=$3', [role, req.user.id, req.params.id]);
    await logAudit(req.user.id, req.user.email, 'ROLE_CHANGED', 'MEMBER', parseInt(req.params.id), before[0].full_name, { from: oldRole, to: role });
    res.json({ message: 'Role updated' });
  } catch (err) {
    console.error('Change role error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/admin/users/:id/status — suspend or reinstate an account (admin + security-role)
router.put('/users/:id/status', secOrAdmin, async (req, res) => {
  const { isActive } = req.body;
  if (typeof isActive !== 'boolean') {
    return res.status(400).json({ error: 'isActive (boolean) is required' });
  }
  try {
    const { rows } = await pool.query('SELECT id, full_name, email, role FROM users WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const member = rows[0];

    // Prevent suspending admin accounts unless requester is also admin
    if (member.role === 'admin' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can suspend admin accounts' });
    }

    await pool.query('UPDATE users SET is_active = $1, updated_by = $2, updated_at = NOW() WHERE id = $3', [isActive, req.user.id, req.params.id]);
    const action = isActive ? 'MEMBER_REINSTATED' : 'MEMBER_SUSPENDED';
    log.info(`Account ${isActive ? 'reinstated' : 'suspended'}: ${member.full_name} (id:${req.params.id}) by user ${req.user.id}`);
    await logAudit(req.user.id, req.user.email, action, 'MEMBER', parseInt(req.params.id), member.full_name, { isActive });

    // Send suspension email
    if (!isActive) {
      sendEmail({
        to: member.email,
        subject: '⚠️ Your UCOSA-NA Account Has Been Suspended',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
            <div style="background:#7b2152;text-align:center;padding:28px 32px">
              <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
              <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
            </div>
            <div style="background:#fdf6ec;padding:32px">
              <h2 style="color:#c62828;margin-top:0;margin-bottom:8px">Account Suspended</h2>
              <p>Dear <strong>${member.full_name}</strong>,</p>
              <p style="color:#333;line-height:1.7;">
                Your UCOSA-NA member account has been <strong>suspended</strong> by an administrator.
                You will not be able to log in until your account is reinstated.
              </p>
              <div style="background:#fff3f3;border-left:4px solid #c62828;border-radius:6px;padding:16px 20px;margin:20px 0;">
                <p style="margin:0;color:#c62828;font-weight:600;">What to do next</p>
                <p style="margin:8px 0 0;color:#555;">
                  Please contact the UCOSA-NA administration to resolve this matter and have your account reinstated.
                </p>
              </div>
              <p style="margin-top:20px;color:#555;">
                You can reach us at:
                <a href="mailto:admin@ucosa-na.org" style="color:#7b2152;font-weight:600;">admin@ucosa-na.org</a>
              </p>
              <p style="margin-top:24px;font-size:0.85rem;color:#888;">
                UCOSA-North America &mdash; <a href="https://ucosa-na.org">ucosa-na.org</a>
              </p>
            </div>
          </div>`,
      }).catch(err => log.error(`Suspension email failed for ${member.email}: ${err.message}`));
    }

    res.json({ message: `Account ${isActive ? 'reinstated' : 'suspended'} successfully` });
  } catch (err) {
    console.error('Toggle status error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/admin/users/:id/lock — lock or unlock an account (admin + security-role, no email)
router.put('/users/:id/lock', secOrAdmin, async (req, res) => {
  const { isLocked } = req.body;
  if (typeof isLocked !== 'boolean') {
    return res.status(400).json({ error: 'isLocked (boolean) is required' });
  }
  try {
    const { rows } = await pool.query('SELECT id, full_name, role FROM users WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    if (rows[0].role === 'admin' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only admins can lock admin accounts' });
    }
    await pool.query('UPDATE users SET is_locked = $1, updated_by = $2, updated_at = NOW() WHERE id = $3', [isLocked, req.user.id, req.params.id]);
    log.info(`Account ${isLocked ? 'locked' : 'unlocked'}: ${rows[0].full_name} (id:${req.params.id}) by user ${req.user.id}`);
    await logAudit(req.user.id, req.user.email, isLocked ? 'MEMBER_LOCKED' : 'MEMBER_UNLOCKED', 'MEMBER', parseInt(req.params.id), rows[0].full_name, { isLocked });
    res.json({ message: `Account ${isLocked ? 'locked' : 'unlocked'} successfully` });
  } catch (err) {
    console.error('Lock account error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', secOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT full_name, email FROM users WHERE id = $1', [req.params.id]);
    const memberName = rows[0]?.full_name || 'Unknown';
    const memberEmail = rows[0]?.email || '';
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    await logAudit(req.user.id, req.user.email, 'MEMBER_DELETED', 'MEMBER', parseInt(req.params.id), memberName, { email: memberEmail });
    res.json({ message: 'Member removed' });
  } catch (err) {
    console.error('Delete user error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/admin/users/:id/reset-password — generate new temp password and email it
router.post('/users/:id/reset-password', secOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, full_name, email, phone FROM users WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const { full_name, email, phone } = rows[0];

    const tempPassword = generatePassword();
    const hash = await bcrypt.hash(tempPassword, 10);
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
    await pool.query(
      'UPDATE users SET password_hash=$1, must_change_password=TRUE, password_expires_at=$2 WHERE id=$3',
      [hash, expiresAt, req.params.id]
    );

    sendEmail({
      to: email,
      subject: '🔑 Your UCOSA-NA Password Has Been Reset',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          <div style="background:#7b2152;text-align:center;padding:28px 32px">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
          </div>
          <div style="background:#fdf6ec;padding:32px">
            <h2 style="color:#7b2152;margin-top:0">Password Reset</h2>
            <p>Dear <strong>${full_name}</strong>,</p>
            <p>Your UCOSA-NA account password has been reset by an administrator. Use the temporary password below to log in:</p>
            <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #c8a96e">
              <p><strong>Login URL:</strong> <a href="https://ucosa-na.org">https://ucosa-na.org</a></p>
              <p><strong>Email:</strong> ${email}</p>
              <p><strong>Temporary Password:</strong> <code style="background:#f5ede0;padding:4px 10px;border-radius:4px;font-size:1.2em;letter-spacing:1px">${tempPassword}</code></p>
              <p style="color:#c0392b;font-size:0.9em">⚠️ This password expires in <strong>48 hours</strong>. Please log in and change it before it expires.</p>
            </div>
            <p style="color:#7b2152"><strong>You will be asked to change this password after logging in.</strong></p>
            <p style="color:#888;font-size:0.85em;margin-top:24px">
              If you did not request this reset, contact us at
              <a href="mailto:admin@ucosa-na.org">admin@ucosa-na.org</a>.
            </p>
          </div>
        </div>
      `,
    })
      .then(() => log.info(`Password reset email sent to ${email}`))
      .catch(err => log.error(`Password reset email failed for ${email}: ${err.message}`));

    if (phone) {
      const sid  = process.env.TWILIO_ACCOUNT_SID;
      const tok  = process.env.TWILIO_AUTH_TOKEN;
      const from = process.env.TWILIO_PHONE_NUMBER;
      if (sid && tok && from) {
        require('twilio')(sid, tok).messages.create({
          to: phone, from,
          body: `UCOSA-NA: Your password has been reset. Temp password: ${tempPassword}. This password expires in 48 hours. Log in at ucosa-na.org and change it immediately.`,
        }).catch(err => log.error(`Password reset SMS failed for ${phone}: ${err.message}`));
      }
    }

    await logAudit(req.user.id, req.user.email, 'PASSWORD_RESET', 'MEMBER', parseInt(req.params.id), full_name, { email });
    res.json({ message: `Password reset. New temp password emailed to ${email}.`, tempPassword });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/admin/metrics — live server metrics
router.get('/metrics', adminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT role, COUNT(*) AS count FROM users GROUP BY role`
    );
    const users = { total: 0, members: 0, admins: 0, pending: 0 };
    rows.forEach(r => {
      users.total += parseInt(r.count);
      if (r.role === 'member') users.members = parseInt(r.count);
      if (r.role === 'admin')  users.admins  = parseInt(r.count);
    });
    const { rows: pending } = await pool.query(
      `SELECT COUNT(*) AS count FROM users WHERE must_change_password = TRUE`
    );
    users.pending = parseInt(pending[0].count);

    const totalMem = os.totalmem();
    const freeMem  = os.freemem();
    const usedMem  = totalMem - freeMem;
    const mem      = process.memoryUsage();

    res.json({
      status:  'running',
      uptime:  Math.floor(process.uptime()),
      cpu: {
        cores:    os.cpus().length,
        model:    os.cpus()[0]?.model || 'N/A',
        loadAvg1: os.loadavg()[0].toFixed(2),
        loadAvg5: os.loadavg()[1].toFixed(2),
      },
      memory: {
        totalMB:     Math.round(totalMem / 1048576),
        usedMB:      Math.round(usedMem  / 1048576),
        freeMB:      Math.round(freeMem  / 1048576),
        usedPercent: Math.round((usedMem / totalMem) * 100),
      },
      process: {
        heapUsedMB:  Math.round(mem.heapUsed  / 1048576),
        heapTotalMB: Math.round(mem.heapTotal / 1048576),
        rssMB:       Math.round(mem.rss       / 1048576),
      },
      users,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/backup — stream pg_dump as a downloadable SQL file
router.get('/backup', adminOnly, (req, res) => {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    return res.status(500).json({ error: 'DATABASE_URL not configured' });
  }

  const date = new Date().toISOString().slice(0, 10);
  const filename = `ucosa_backup_${date}.sql`;

  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/octet-stream');

  const dump = spawn('pg_dump', [dbUrl]);

  dump.stdout.pipe(res);

  dump.stderr.on('data', data => {
    console.error('pg_dump stderr:', data.toString());
  });

  dump.on('error', err => {
    console.error('pg_dump spawn error:', err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'pg_dump not available: ' + err.message });
    } else {
      res.end();
    }
  });

  dump.on('close', code => {
    if (code !== 0) console.error('pg_dump exited with code', code);
  });
});

// ── ANNUAL DUES ──────────────────────────────────────────────────────────────

// GET /api/admin/dues — all dues records with member names
router.get('/dues', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT d.id, d.year, d.amount, d.paid_date, d.payment_method, d.status, d.notes, d.created_at,
             u.full_name, u.id AS user_id,
             rb.full_name AS recorded_by_name
      FROM users u
      LEFT JOIN annual_dues d ON d.user_id = u.id
      LEFT JOIN users rb ON rb.id = d.recorded_by
      WHERE u.id != 1
      ORDER BY d.year DESC NULLS LAST, u.full_name ASC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/dues — add a dues record
router.post('/dues', finOrAdmin, async (req, res) => {
  const { userId, year, amount, paidDate, paymentMethod, status, notes } = req.body;
  if (!userId || !year) return res.status(400).json({ error: 'Member and year are required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO annual_dues (user_id, year, amount, paid_date, payment_method, status, notes, recorded_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
    `, [userId, year, amount || 0, paidDate || null, paymentMethod || null,
        status || 'unpaid', notes || null, req.user.id]);
    const { rows: member } = await pool.query('SELECT full_name, email FROM users WHERE id = $1', [userId]);
    await logAudit(req.user.id, req.user.email, 'DUES_CREATED', 'DUES', rows[0].id, member[0]?.full_name, { year, amount, status: status || 'unpaid' });
    if ((status || 'unpaid') === 'paid' && member[0]?.email) {
      sendEmail({
        to: member[0].email,
        subject: `Payment Receipt — Annual Dues ${year} — UCOSA-NA`,
        html: paymentReceiptHtml(member[0].full_name,
          [{ label: `Annual Dues (${year})`, amount: amount || 0 }],
          `DUES-${rows[0].id}`)
      }).catch(() => {});
    }
    res.status(201).json({ message: 'Dues record added', id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/dues/:id — update a dues record
router.put('/dues/:id', finOrAdmin, async (req, res) => {
  const { year, amount, paidDate, paymentMethod, status, notes } = req.body;
  try {
    const { rows: before } = await pool.query(`
      SELECT d.year, d.amount, d.status, u.full_name, u.email FROM annual_dues d
      JOIN users u ON u.id = d.user_id WHERE d.id = $1`, [req.params.id]);
    await pool.query(`
      UPDATE annual_dues SET year=$1, amount=$2, paid_date=$3, payment_method=$4,
        status=$5, notes=$6, updated_at=NOW(), updated_by=$7, recorded_by=$7 WHERE id=$8
    `, [year, amount || 0, paidDate || null, paymentMethod || null,
        status || 'unpaid', notes || null, req.user.id, req.params.id]);
    if (before.length) {
      await logAudit(req.user.id, req.user.email, 'DUES_UPDATED', 'DUES', parseInt(req.params.id), before[0].full_name,
        { year, amount, status, prev_status: before[0].status, prev_amount: before[0].amount });
      if (status === 'paid' && before[0].email) {
        sendEmail({
          to: before[0].email,
          subject: `Payment Receipt — Annual Dues ${year} — UCOSA-NA`,
          html: paymentReceiptHtml(before[0].full_name,
            [{ label: `Annual Dues (${year})`, amount: amount || 0 }],
            `DUES-${req.params.id}`)
        }).catch(() => {});
      }
    }
    res.json({ message: 'Dues record updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/dues/:id
router.delete('/dues/:id', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT d.year, d.amount, d.status, u.full_name FROM annual_dues d
      JOIN users u ON u.id = d.user_id WHERE d.id = $1`, [req.params.id]);
    await pool.query('DELETE FROM annual_dues WHERE id=$1', [req.params.id]);
    if (rows.length) {
      await logAudit(req.user.id, req.user.email, 'DUES_DELETED', 'DUES', parseInt(req.params.id), rows[0].full_name, { year: rows[0].year, amount: rows[0].amount, status: rows[0].status });
    }
    res.json({ message: 'Dues record deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ENDOWMENT FUND ────────────────────────────────────────────────────────────

// GET /api/admin/endowment — all endowment records with member names
router.get('/endowment', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT e.id, e.amount, e.contribution_date, e.year, e.status, e.payment_method, e.notes, e.created_at,
             u.full_name, u.id AS user_id,
             rb.full_name AS recorded_by_name
      FROM users u
      LEFT JOIN endowment_fund e ON e.user_id = u.id
      LEFT JOIN users rb ON rb.id = e.recorded_by
      WHERE u.id != 1
      ORDER BY e.year DESC NULLS LAST, u.full_name ASC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/endowment — add an endowment record
router.post('/endowment', finOrAdmin, async (req, res) => {
  const { userId, amount, contributionDate, year, status, paymentMethod, notes } = req.body;
  if (!userId || amount === undefined || amount === null || amount === '') return res.status(400).json({ error: 'Member and amount are required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO endowment_fund (user_id, amount, contribution_date, year, status, payment_method, notes, recorded_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
    `, [userId, amount, contributionDate || null, year || null, status || 'paid', paymentMethod || null, notes || null, req.user.id]);
    const { rows: member } = await pool.query('SELECT full_name, email FROM users WHERE id = $1', [userId]);
    await logAudit(req.user.id, req.user.email, 'ENDOWMENT_CREATED', 'ENDOWMENT', rows[0].id, member[0]?.full_name, { year, amount, status: status || 'paid' });
    if ((status || 'paid') === 'paid' && member[0]?.email) {
      sendEmail({
        to: member[0].email,
        subject: `Payment Receipt — Endowment Fund ${year || ''} — UCOSA-NA`,
        html: paymentReceiptHtml(member[0].full_name,
          [{ label: `Endowment Fund${year ? ` (${year})` : ''}`, amount: amount || 0 }],
          `ENDOW-${rows[0].id}`)
      }).catch(() => {});
    }
    res.status(201).json({ message: 'Endowment record added', id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/endowment/:id — update an endowment record
router.put('/endowment/:id', finOrAdmin, async (req, res) => {
  const { amount, year, status, contributionDate, paymentMethod, notes } = req.body;
  if (amount === undefined || amount === null || amount === '') return res.status(400).json({ error: 'Amount is required' });
  try {
    const { rows: before } = await pool.query(`
      SELECT e.amount, e.year, e.status, u.full_name, u.email FROM endowment_fund e
      JOIN users u ON u.id = e.user_id WHERE e.id = $1`, [req.params.id]);
    await pool.query(`
      UPDATE endowment_fund
      SET amount=$1, year=$2, status=$3, contribution_date=$4, payment_method=$5, notes=$6,
          updated_at=NOW(), updated_by=$7, recorded_by=$7
      WHERE id=$8
    `, [amount, year || null, status || 'paid', contributionDate || null, paymentMethod || null, notes || null, req.user.id, req.params.id]);
    if (before.length) {
      await logAudit(req.user.id, req.user.email, 'ENDOWMENT_UPDATED', 'ENDOWMENT', parseInt(req.params.id), before[0].full_name,
        { year, amount, status, prev_status: before[0].status, prev_amount: before[0].amount });
      if (status === 'paid' && before[0].email) {
        sendEmail({
          to: before[0].email,
          subject: `Payment Receipt — Endowment Fund ${year || ''} — UCOSA-NA`,
          html: paymentReceiptHtml(before[0].full_name,
            [{ label: `Endowment Fund${year ? ` (${year})` : ''}`, amount: amount || 0 }],
            `ENDOW-${req.params.id}`)
        }).catch(() => {});
      }
    }
    res.json({ message: 'Endowment record updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/endowment/:id
router.delete('/endowment/:id', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT e.amount, e.year, e.status, u.full_name FROM endowment_fund e
      JOIN users u ON u.id = e.user_id WHERE e.id = $1`, [req.params.id]);
    await pool.query('DELETE FROM endowment_fund WHERE id=$1', [req.params.id]);
    if (rows.length) {
      await logAudit(req.user.id, req.user.email, 'ENDOWMENT_DELETED', 'ENDOWMENT', parseInt(req.params.id), rows[0].full_name, { year: rows[0].year, amount: rows[0].amount, status: rows[0].status });
    }
    res.json({ message: 'Endowment record deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/endowment/:id/remind — send reminder to member via SMS + email
router.post('/endowment/:id/remind', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT e.id, e.amount, e.year, e.status,
             u.full_name, u.email, COALESCE(p.phone, u.phone) AS phone
      FROM endowment_fund e
      JOIN users u ON u.id = e.user_id
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE e.id = $1
    `, [req.params.id]);

    if (!rows.length) return res.status(404).json({ error: 'Endowment record not found' });
    const r = rows[0];
    const yearLabel  = r.year ? `${r.year} ` : '';
    const amountFmt  = `$${parseFloat(r.amount).toFixed(2)}`;
    const statusUp   = (r.status || 'pending').toUpperCase();

    // SMS
    let smsSent = false;
    if (r.phone) {
      smsSent = await sendSMS(r.phone,
        `UCOSA-NA Endowment Fund Reminder\n` +
        `Dear ${r.full_name},\n` +
        `Your ${yearLabel}endowment fund contribution of ${amountFmt} is currently: ${statusUp}.\n` +
        `Payment Info: Zelle to — ucosa.northamerica@gmail.com\nIf you've already made your payment, please ignore this message — and thank you!`
      );
    }

    // Email
    sendEmail({
      to: r.email,
      subject: `⏰ UCOSA-NA Endowment Fund Reminder`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          <div style="background:#7b2152;text-align:center;padding:28px 32px">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
          </div>
          <div style="background:#fdf6ec;padding:32px">
            <h2 style="color:#7b2152;margin-top:0">Endowment Fund Reminder</h2>
            <p>Dear <strong>${r.full_name}</strong>,</p>
            <p>This is a friendly reminder about your ${yearLabel}endowment fund contribution:</p>
            <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #c8a96e">
              ${r.year ? `<p><strong>Year:</strong> ${r.year}</p>` : ''}
              <p><strong>Amount:</strong> ${amountFmt}</p>
              <p><strong>Status:</strong> ${r.status ? r.status.charAt(0).toUpperCase() + r.status.slice(1) : '—'}</p>
              <p><strong>Payment Info:</strong> Zelle to — ucosa.northamerica@gmail.com</p>
            </div>
            <p><em>If you've already made your payment, please ignore this message — and thank you!</em></p>
            <p style="color:#888;font-size:0.85em;margin-top:24px">UCOSA-North America &mdash; <a href="mailto:admin@ucosa-na.org">admin@ucosa-na.org</a></p>
          </div>
        </div>`,
    }).catch(err => log.error(`Endowment reminder email failed for ${r.email}: ${err.message}`));

    res.json({ message: smsSent ? `Reminder sent to ${r.full_name} via SMS and email` : `Email reminder sent to ${r.full_name}${r.phone ? ' (SMS not configured)' : ' (no phone on record)'}` });
  } catch (err) {
    console.error('Endowment reminder error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/financials — upsert a financial record for a member
router.post('/financials', finOrAdmin, async (req, res) => {
  const { userId, year, annualDues, endowmentFund, notes } = req.body;
  if (!userId || !year) return res.status(400).json({ error: 'userId and year are required' });
  try {
    await pool.query(`
      INSERT INTO financial_records (user_id, year, annual_dues, endowment_fund, notes, updated_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT (user_id, year) DO UPDATE
        SET annual_dues    = EXCLUDED.annual_dues,
            endowment_fund = EXCLUDED.endowment_fund,
            notes          = EXCLUDED.notes,
            updated_at     = NOW()
    `, [userId, year, annualDues || 0, endowmentFund || 0, notes || null]);
    res.json({ message: 'Financial record saved' });
  } catch (err) {
    console.error('Financials upsert error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/admin/financials/:userId — get all financial records for a member
router.get('/financials/:userId', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT year, annual_dues, endowment_fund, notes FROM financial_records WHERE user_id = $1 ORDER BY year DESC',
      [req.params.userId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── SMS BROADCAST ─────────────────────────────────────────────────────────────

// POST /api/admin/sms/broadcast — send SMS to all members with phone numbers
router.post('/sms/broadcast', proOrAdmin, async (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message is required' });

  try {
    const { rows } = await pool.query(
      `SELECT u.full_name, COALESCE(p.phone, u.phone) AS phone
       FROM users u
       LEFT JOIN member_profiles p ON p.user_id = u.id
       WHERE COALESCE(p.phone, u.phone) IS NOT NULL AND u.id != 1`
    );

    if (!rows.length) return res.status(400).json({ error: 'No members with phone numbers found' });

    const results = await Promise.allSettled(
      rows.map(m => sendSMS(m.phone, message.trim()))
    );

    const sent   = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    res.json({ message: `SMS sent to ${sent} member(s).${failed ? ` ${failed} failed.` : ''}`, sent, failed });
  } catch (err) {
    console.error('Broadcast SMS error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/email/broadcast — send email to all members
router.post('/email/broadcast', proOrAdmin, async (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !subject.trim()) return res.status(400).json({ error: 'Subject is required' });
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message is required' });

  try {
    const { rows } = await pool.query(
      `SELECT full_name, email FROM users WHERE id != 1 ORDER BY full_name ASC`
    );
    if (!rows.length) return res.status(400).json({ error: 'No members found' });

    const results = await Promise.allSettled(
      rows.map(m => sendEmail({
        to: m.email,
        subject: subject.trim(),
        html: `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
            <div style="background:#7b2152;text-align:center;padding:28px 32px">
              <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
              <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
            </div>
            <div style="background:#fdf6ec;padding:32px">
              <p>Dear <strong>${m.full_name}</strong>,</p>
              <div style="white-space:pre-wrap;font-size:1em;color:#333;line-height:1.7;">${message.trim().replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
              <p style="color:#888;font-size:0.85em;margin-top:32px">
                UCOSA-North America &mdash;
                <a href="mailto:admin@ucosa-na.org">admin@ucosa-na.org</a>
              </p>
            </div>
          </div>`,
      }))
    );

    const sent   = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    log.info(`Email broadcast "${subject}" sent to ${sent} member(s), ${failed} failed`);
    res.json({ message: `Email sent to ${sent} member(s).${failed ? ` ${failed} failed.` : ''}`, sent, failed });
  } catch (err) {
    console.error('Broadcast email error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/email/invite-broadcast — send personalised invitational email to a provided list
router.post('/email/invite-broadcast', proOrAdmin, async (req, res) => {
  const { list } = req.body;
  if (!list || !list.trim()) return res.status(400).json({ error: 'Recipient list is required' });

  const entries = list.split(',').map(s => s.trim()).filter(Boolean);
  const parsed  = [];
  const skipped = [];

  for (const entry of entries) {
    const colonIdx = entry.lastIndexOf(':');
    if (colonIdx === -1) { skipped.push(entry); continue; }
    const fullName = entry.slice(0, colonIdx).trim();
    const email    = entry.slice(colonIdx + 1).trim();
    if (!fullName || !email || !email.includes('@')) { skipped.push(entry); continue; }
    parsed.push({ fullName, email });
  }

  if (!parsed.length) return res.status(400).json({ error: 'No valid entries found. Use format: Full Name:email@example.com' });

  const buildHtml = (fullName) => `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#fdf6ec;margin:0;padding:0}
  .wrap{max-width:620px;margin:32px auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.08)}
  .hdr{background:#7b2152;padding:28px 36px;text-align:center}
  .hdr h1{color:#f5e6d0;font-size:22px;margin:0;letter-spacing:.08em}
  .hdr p{color:#d4a0b8;font-size:13px;margin:6px 0 0;letter-spacing:.1em;text-transform:uppercase}
  .body{padding:36px 40px;color:#333;font-size:15px;line-height:1.75}
  .body p{margin:0 0 16px}
  .body ul{margin:0 0 16px 20px}
  .body ul li{margin-bottom:8px}
  .cta{text-align:center;margin:28px 0}
  .cta a{background:#c8a96e;color:#fff;text-decoration:none;padding:14px 36px;border-radius:6px;font-weight:700;font-size:14px;letter-spacing:.08em;text-transform:uppercase;display:inline-block}
  .ftr{background:#1a1a2e;color:#aab4c8;text-align:center;padding:18px 20px;font-size:12px}
  .ftr a{color:#c8a96e;text-decoration:none}
  strong{color:#7b2152}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px"/>
    <h1>UCOSA-North America</h1>
    <p>Alumni United Across North America</p>
  </div>
  <div class="body">
    <p>Dear <strong>${fullName}</strong>,</p>
    <p>We hope this message finds you well.</p>
    <p>We are reaching out because you are part of something that does not fade with time — the bond of fellowship forged at Ugbeka College. That connection is exactly why <strong>UCOSA-North America</strong> exists: <em>Alumni United Across North America</em>, staying connected, supporting our alma mater, and uplifting one another.</p>
    <p>We have come a long way from our humble beginnings. We have grown, we have organized, and we are proud to say — <strong>we now have a home online.</strong> We warmly invite you to visit us at:</p>
    <p style="text-align:center;font-size:18px;font-weight:700;color:#7b2152"><a href="https://ucosa-na.org" style="color:#7b2152">www.ucosa-na.org</a></p>
    <p>We are a not-for-profit, non-political, charitable, and voluntary association of Ugbeka College alumni residing in the United States and Canada. We meet via <strong>Zoom video conferencing on the last Sunday of every month</strong>, so no matter where you are in North America, you can join from any internet-connected device.</p>
    <p>Our goals remain the same as the values we all share:</p>
    <ul>
      <li>To foster <strong>unity, brotherhood, and fellowship</strong> among fellow Ugbeka College alumni in North America</li>
      <li>To <strong>support the development and improvement</strong> of Ugbeka College and the Ugbeka community</li>
      <li>To organize cultural, social, and fundraising activities that benefit our association and the broader Ugbeka community</li>
    </ul>
    <p>We recognize our shared heritage and our collective responsibility to the institution that shaped us all. That responsibility does not expire — and neither does your place among us.</p>
    <p><strong>We would love to welcome you back.</strong> Visit <a href="https://ucosa-na.org">ucosa-na.org</a> to reconnect. While at the website, click on <strong>"Request To Join"</strong> so we can reconnect and get you back where you belong.</p>
    <div class="cta"><a href="https://ucosa-na.org">Visit ucosa-na.org</a></div>
    <p>With warmth and fellowship,</p>
    <p><strong>The Executive Committee</strong><br/>UCOSA-North America<br/><a href="https://ucosa-na.org">www.ucosa-na.org</a></p>
  </div>
  <div class="ftr">&copy; 2026 UCOSA-North America. All rights reserved. &mdash; <a href="https://ucosa-na.org">ucosa-na.org</a></div>
</div>
</body></html>`.trim();

  const results = await Promise.allSettled(
    parsed.map(({ fullName, email }) => sendEmail({
      to:      `"${fullName}" <${email}>`,
      subject: 'We Miss You — Come Back Home to UCOSA-NA',
      html:    buildHtml(fullName),
    }))
  );

  const sent   = results.filter(r => r.status === 'fulfilled').length;
  const failed = results.filter(r => r.status === 'rejected').length;
  log.info(`Invite broadcast sent to ${sent} recipient(s), ${failed} failed, ${skipped.length} skipped`);
  res.json({
    message: `Invitation sent to ${sent} recipient(s).${failed ? ` ${failed} failed.` : ''}${skipped.length ? ` ${skipped.length} skipped (bad format).` : ''}`,
    sent, failed, skipped: skipped.length,
  });
});

// POST /api/admin/sms/dues-reminder/:duesId — send dues reminder to a specific member
router.post('/sms/dues-reminder/:duesId', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT d.year, d.amount, d.status,
             u.full_name, u.email, COALESCE(p.phone, u.phone) AS phone
      FROM annual_dues d
      JOIN users u ON u.id = d.user_id
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE d.id = $1
    `, [req.params.duesId]);

    if (!rows.length) return res.status(404).json({ error: 'Dues record not found' });
    const r = rows[0];

    const dueDate   = `June 1, ${r.year}`;
    const amountFmt = `$${parseFloat(r.amount).toFixed(2)}`;

    // Email
    await sendEmail({
      to: r.email,
      subject: `Annual Dues Reminder`,
      html: duesReminderHtml(r.full_name, r.year, dueDate, amountFmt, r.status),
    });

    // SMS
    let smsSent = false;
    if (r.phone) {
      smsSent = await sendSMS(r.phone,
        `UCOSA-NA Dues Reminder\n` +
        `Dear ${r.full_name}, your ${r.year} annual dues (${amountFmt}) are due on ${dueDate}.\n` +
        `Payment Info: Zelle to — ucosa.northamerica@gmail.com\n` +
        `If you've already made your payment, please ignore this message — and thank you!`
      );
    }

    await pool.query('UPDATE annual_dues SET reminder_sent_at = NOW() WHERE id = $1', [req.params.duesId]);
    res.json({ message: smsSent
      ? `Reminder sent to ${r.full_name} via email and SMS`
      : `Email reminder sent to ${r.full_name}${r.phone ? ' (SMS not configured)' : ' (no phone on record)'}` });
  } catch (err) {
    log.error(`Dues reminder error: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/dues/remind-all — send dues reminder to all unpaid/partial members
router.post('/dues/remind-all', finOrAdmin, async (req, res) => {
  const year = new Date().getFullYear();
  const dueDate = `June 1, ${year}`;
  try {
    const { rows: members } = await pool.query(`
      SELECT u.id, u.full_name, u.email,
             COALESCE(p.phone, u.phone) AS phone,
             d.amount, d.status
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      LEFT JOIN annual_dues d ON d.user_id = u.id AND d.year = $1
      WHERE u.id != 1
        AND u.is_active = true
        AND (d.id IS NULL OR d.status != 'paid')
      ORDER BY u.full_name ASC
    `, [year]);

    if (!members.length) return res.json({ message: 'All members are paid — no reminders needed.', sent: 0 });

    let emailsSent = 0, smsSent = 0;

    for (const m of members) {
      const amountFmt = m.amount ? `$${parseFloat(m.amount).toFixed(2)}` : '$100.00';

      // Email
      sendEmail({
        to: m.email,
        subject: `Annual Dues Reminder`,
        html: duesReminderHtml(m.full_name, year, dueDate, amountFmt, m.status),
      }).then(() => { emailsSent++; }).catch(err => log.error(`Remind-all email failed for ${m.email}: ${err.message}`));

      // SMS
      if (m.phone) {
        const sent = await sendSMS(m.phone,
          `UCOSA-NA Dues Reminder\n` +
          `Dear ${m.full_name}, your ${year} annual dues (${amountFmt}) are due on ${dueDate}.\n` +
          `Payment Info: Zelle to — ucosa.northamerica@gmail.com\nIf you've already made your payment, please ignore this message — and thank you!`
        ).catch(err => { log.error(`Remind-all SMS failed for ${m.phone}: ${err.message}`); return false; });
        if (sent) smsSent++;
      }
    }

    log.info(`Remind-all: ${members.length} members notified (${smsSent} SMS, emails dispatched) for ${year} by ${req.user.email}`);
    res.json({
      message: `Reminders dispatched to ${members.length} member(s)${smsSent ? ` (${smsSent} SMS sent)` : ' (email only — SMS not configured)'}.`,
      total: members.length,
      smsSent,
    });
  } catch (err) {
    log.error(`Remind-all dues error: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// ── EXPENSE RECORDS ──────────────────────────────────────────────────────────

// GET /api/admin/expenses
router.get('/expenses', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT e.id, e.expense_date, e.category, e.description, e.amount, e.approved_by, e.created_at,
             u.full_name AS recorded_by_name
      FROM expense_records e
      LEFT JOIN users u ON u.id = e.recorded_by
      ORDER BY e.expense_date DESC, e.id DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/expenses
router.post('/expenses', finOrAdmin, async (req, res) => {
  const { expenseDate, category, description, amount, approvedBy } = req.body;
  if (!expenseDate || !category || amount === undefined || amount === null || amount === '') {
    return res.status(400).json({ error: 'Date, category, and amount are required' });
  }
  try {
    const { rows } = await pool.query(`
      INSERT INTO expense_records (expense_date, category, description, amount, approved_by, recorded_by)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
    `, [expenseDate, category.trim(), description?.trim() || null,
        parseFloat(amount) || 0, approvedBy?.trim() || null, req.user.id]);
    await logAudit(req.user.id, req.user.email, 'EXPENSE_CREATED', 'EXPENSE', rows[0].id, category,
      { expenseDate, category, amount, approvedBy });
    res.status(201).json({ message: 'Expense record added', id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/expenses/:id
router.put('/expenses/:id', finOrAdmin, async (req, res) => {
  const { expenseDate, category, description, amount, approvedBy } = req.body;
  try {
    const { rowCount } = await pool.query(`
      UPDATE expense_records
      SET expense_date = $1, category = $2, description = $3, amount = $4, approved_by = $5
      WHERE id = $6
    `, [expenseDate, category?.trim(), description?.trim() || null,
        parseFloat(amount) || 0, approvedBy?.trim() || null, req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Expense record not found' });
    await logAudit(req.user.id, req.user.email, 'EXPENSE_UPDATED', 'EXPENSE', parseInt(req.params.id), category,
      { expenseDate, category, amount, approvedBy });
    res.json({ message: 'Expense record updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/expenses/:id
router.delete('/expenses/:id', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT category, amount FROM expense_records WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Expense record not found' });
    await pool.query('DELETE FROM expense_records WHERE id = $1', [req.params.id]);
    await logAudit(req.user.id, req.user.email, 'EXPENSE_DELETED', 'EXPENSE', parseInt(req.params.id), rows[0].category,
      { amount: rows[0].amount });
    res.json({ message: 'Expense record deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── AUDIT LOG ────────────────────────────────────────────────────────────────

// GET /api/admin/audit — view audit log (admin only)
router.get('/audit', adminOnly, async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 500, 2000);
  const entity = req.query.entity || null;
  const action = req.query.action || null;
  try {
    const conditions = [];
    const params = [];
    if (entity) { params.push(entity.toUpperCase()); conditions.push(`entity_type = $${params.length}`); }
    if (action) { params.push(`%${action.toUpperCase()}%`); conditions.push(`action ILIKE $${params.length}`); }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    params.push(limit);
    const { rows } = await pool.query(`
      SELECT id, action, entity_type, entity_id, entity_name,
             performed_by_name, details, created_at
      FROM audit_log
      ${where}
      ORDER BY created_at DESC
      LIMIT $${params.length}
    `, params);
    res.json(rows);
  } catch (err) {
    console.error('Audit log error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── LOG VIEWER ────────────────────────────────────────────────────────────────

// GET /api/admin/logs — tail app.log (admin + security-role)
router.get('/logs', secOrAdmin, (req, res) => {
  const limit   = Math.min(parseInt(req.query.lines) || 200, 2000);
  const logPath = path.join(__dirname, '../../app.log');
  try {
    if (!fs.existsSync(logPath)) return res.json({ lines: [] });
    const content = fs.readFileSync(logPath, 'utf8');
    const lines   = content.split('\n').filter(Boolean);
    const filtered = lines.filter(l => !/\] INFO\s+GET /.test(l));
    res.json({ lines: filtered.slice(-limit), total: filtered.length });
  } catch (err) {
    res.status(500).json({ error: 'Could not read log file' });
  }
});

// ── SPECIAL LEVIES / VOLUNTARY CONTRIBUTIONS / DONATIONS ─────────────────────

const LEVY_TYPES = ['Special Levy', 'Voluntary Contribution', 'Member-Donation'];

// GET /api/admin/special-levies — readable by all authenticated members
router.get('/special-levies', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT sl.id, sl.type, sl.year, sl.amount, sl.paid_date, sl.notes,
             u.full_name AS member_name,
             r.full_name AS recorded_by_name
      FROM special_levies sl
      JOIN users u ON u.id = sl.user_id
      LEFT JOIN users r ON r.id = sl.recorded_by
      ORDER BY sl.year DESC, sl.paid_date DESC, u.full_name ASC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/special-levies — fin/admin only
router.post('/special-levies', finOrAdmin, async (req, res) => {
  const { userId, type, year, amount, paidDate, notes } = req.body;
  if (!userId || !type || !year || amount === undefined) {
    return res.status(400).json({ error: 'Member, type, year, and amount are required.' });
  }
  if (!LEVY_TYPES.includes(type)) {
    return res.status(400).json({ error: 'Invalid type.' });
  }
  try {
    const { rows } = await pool.query(`
      INSERT INTO special_levies (user_id, type, year, amount, paid_date, notes, recorded_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id
    `, [userId, type, year, parseFloat(amount), paidDate || null, notes || null, req.user.id]);
    res.json({ ok: true, id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/special-levies/:id — fin/admin only
router.put('/special-levies/:id', finOrAdmin, async (req, res) => {
  const { type, year, amount, paidDate, notes } = req.body;
  if (!type || !year || amount === undefined) {
    return res.status(400).json({ error: 'Type, year, and amount are required.' });
  }
  if (!LEVY_TYPES.includes(type)) {
    return res.status(400).json({ error: 'Invalid type.' });
  }
  try {
    const { rowCount } = await pool.query(`
      UPDATE special_levies
      SET type=$1, year=$2, amount=$3, paid_date=$4, notes=$5, updated_at=NOW()
      WHERE id=$6
    `, [type, year, parseFloat(amount), paidDate || null, notes || null, req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Record not found.' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/special-levies/:id — fin/admin only
router.delete('/special-levies/:id', finOrAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM special_levies WHERE id=$1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Record not found.' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Donations ────────────────────────────────────────────────────────────────
router.get('/donations', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, donor_name, donor_email, donor_phone, amount, stripe_payment_intent_id, donated_at
       FROM donations ORDER BY donated_at DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/donations', finOrAdmin, async (req, res) => {
  const { donorName, donorEmail, donorPhone, amount, donatedAt } = req.body;
  if (!donorName || !donorEmail || amount === undefined) {
    return res.status(400).json({ error: 'Name, email, and amount are required.' });
  }
  const ref = `MANUAL-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const date = donatedAt || new Date().toISOString();
  try {
    const { rows } = await pool.query(
      `INSERT INTO donations (donor_name, donor_email, donor_phone, amount, stripe_payment_intent_id, donated_at)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [donorName, donorEmail, donorPhone || null, parseFloat(amount), ref, date]
    );
    res.json({ ok: true, id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/donations/:id', finOrAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM donations WHERE id=$1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Record not found.' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
