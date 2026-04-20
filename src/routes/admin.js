const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const pool = require('../db');
const requireRole = require('../middleware/requireRole');
const log = require('../logger');

// Role shorthand helpers
const adminOnly  = requireRole('admin');
const finOrAdmin = requireRole('admin', 'fin-role');
const secOrAdmin = requireRole('admin', 'security-role');
const anyPriv    = requireRole('admin', 'fin-role', 'security-role');

const router = express.Router();

// ── TWILIO SMS HELPER ─────────────────────────────────────────────────────────
function getTwilioClient() {
  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (!sid || !token) return null;
  return require('twilio')(sid, token);
}

async function sendSMS(to, body) {
  const client = getTwilioClient();
  if (!client) throw new Error('Twilio not configured (TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_PHONE_NUMBER missing)');
  const from = process.env.TWILIO_PHONE_NUMBER;
  if (!from) throw new Error('TWILIO_PHONE_NUMBER not set');
  return client.messages.create({ to, from, body });
}

function makeTransport() {
  return nodemailer.createTransport({
    host: 'smtp.sendgrid.net',
    port: 465,
    secure: true,
    auth: {
      user: 'apikey',
      pass: process.env.SENDGRID_API_KEY,
    },
  });
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

// POST /api/admin/users — create a member and send welcome email
router.post('/users', secOrAdmin, async (req, res) => {
  const { firstName, lastName, email, address, phone, yearJoined, graduationYear } = req.body;
  if (!firstName || !lastName || !email || !phone) {
    return res.status(400).json({ error: 'First name, last name, email, and phone number are required' });
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

    const { rows: inserted } = await pool.query(
      'INSERT INTO users (full_name, email, password_hash, must_change_password, role) VALUES ($1, $2, $3, TRUE, $4) RETURNING id',
      [fullName, emailVal, hash, 'member']
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

    log.info(`Member created: ${fullName} (${emailVal}) by user ${req.user.id}`);

    // Send welcome SMS (awaited so we can report status in the response)
    let smsSent = false;
    if (phone) {
      try {
        await sendSMS(phone,
          `Welcome to UCOSA-NA, ${fullName}!\n` +
          `Login: https://ucosa-na.org\n` +
          `Email: ${emailVal}\n` +
          `Temp password: ${tempPassword}\n` +
          `Please change your password on first login.`
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

    // Fire-and-forget email
    const transport = makeTransport();
    transport.sendMail({
      from: `"UCOSA-NA" <${process.env.EMAIL_USER}>`,
      to: emailVal,
      subject: 'Welcome to UCOSA-North America — Your Login Details',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:32px;background:#fdf6ec;border-radius:12px">
          <h2 style="color:#7b2152">Welcome to UCOSA-North America!</h2>
          <p>Dear <strong>${fullName}</strong>,</p>
          <p>Your member account has been created. Use the details below to log in:</p>
          <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #c8a96e">
            <p><strong>Login URL:</strong> <a href="https://ucosa-na.org">https://ucosa-na.org</a></p>
            <p><strong>Email:</strong> ${emailVal}</p>
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

  try {
    const transport = makeTransport();
    await transport.verify();   // confirm SMTP connection before sending
    await transport.sendMail({
      from: `"UCOSA-NA" <${process.env.EMAIL_USER}>`,
      to,
      subject: 'UCOSA-NA — Email Test',
      html: '<p>This is a test email from the UCOSA-NA admin panel. If you received this, email delivery is working correctly.</p>',
    });
    res.json({ message: `Test email sent to ${to}` });
  } catch (err) {
    console.error('Test email error:', err.message);
    res.status(500).json({ error: 'Email failed: ' + err.message });
  }
});

// GET /api/admin/users — list all members with profile data
router.get('/users', anyPriv, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.full_name, u.email, u.role, u.must_change_password, u.created_at, u.last_login,
             p.first_name, p.last_name, p.address, p.phone, p.year_joined, p.graduation_year
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      ORDER BY u.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('List users error:', err.message);
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
      'UPDATE users SET full_name=$1, email=$2, address=$3, phone=$4 WHERE id=$5',
      [fullName, emailVal, address || null, phone || null, req.params.id]
    );
    await pool.query(`
      INSERT INTO member_profiles (user_id, first_name, last_name, address, phone, year_joined, graduation_year)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (user_id) DO UPDATE SET
        first_name=$2, last_name=$3, address=$4, phone=$5,
        year_joined=$6, graduation_year=$7, updated_at=NOW()
    `, [req.params.id, firstName.trim(), lastName.trim(), address || null, phone || null,
        yearJoined ? parseInt(yearJoined) : null, graduationYear ? parseInt(graduationYear) : null]);
    res.json({ message: 'Member updated' });
  } catch (err) {
    console.error('Update member error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/admin/users/:id/role — change a member's role (admin only)
router.put('/users/:id/role', adminOnly, async (req, res) => {
  const { role } = req.body;
  const validRoles = ['admin', 'member', 'fin-role', 'security-role'];
  if (!role || !validRoles.includes(role)) {
    return res.status(400).json({ error: 'Valid role required: admin, member, fin-role, security-role' });
  }
  try {
    await pool.query('UPDATE users SET role=$1 WHERE id=$2', [role, req.params.id]);
    res.json({ message: 'Role updated' });
  } catch (err) {
    console.error('Change role error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', secOrAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'Member removed' });
  } catch (err) {
    console.error('Delete user error:', err.message);
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
             u.full_name, u.id AS user_id
      FROM annual_dues d
      JOIN users u ON u.id = d.user_id
      ORDER BY d.year DESC, u.full_name ASC
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
    res.status(201).json({ message: 'Dues record added', id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/dues/:id — update a dues record
router.put('/dues/:id', finOrAdmin, async (req, res) => {
  const { year, amount, paidDate, paymentMethod, status, notes } = req.body;
  try {
    await pool.query(`
      UPDATE annual_dues SET year=$1, amount=$2, paid_date=$3, payment_method=$4,
        status=$5, notes=$6, updated_at=NOW() WHERE id=$7
    `, [year, amount || 0, paidDate || null, paymentMethod || null,
        status || 'unpaid', notes || null, req.params.id]);
    res.json({ message: 'Dues record updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/dues/:id
router.delete('/dues/:id', finOrAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM annual_dues WHERE id=$1', [req.params.id]);
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
      SELECT e.id, e.amount, e.contribution_date, e.payment_method, e.notes, e.created_at,
             u.full_name, u.id AS user_id
      FROM endowment_fund e
      JOIN users u ON u.id = e.user_id
      ORDER BY e.contribution_date DESC, u.full_name ASC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/endowment — add an endowment record
router.post('/endowment', finOrAdmin, async (req, res) => {
  const { userId, amount, contributionDate, paymentMethod, notes } = req.body;
  if (!userId || !amount) return res.status(400).json({ error: 'Member and amount are required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO endowment_fund (user_id, amount, contribution_date, payment_method, notes, recorded_by)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
    `, [userId, amount, contributionDate || null, paymentMethod || null, notes || null, req.user.id]);
    res.status(201).json({ message: 'Endowment record added', id: rows[0].id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/endowment/:id
router.delete('/endowment/:id', finOrAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM endowment_fund WHERE id=$1', [req.params.id]);
    res.json({ message: 'Endowment record deleted' });
  } catch (err) {
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
router.post('/sms/broadcast', adminOnly, async (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message is required' });

  try {
    const { rows } = await pool.query(
      `SELECT u.full_name, COALESCE(p.phone, u.phone) AS phone
       FROM users u
       LEFT JOIN member_profiles p ON p.user_id = u.id
       WHERE COALESCE(p.phone, u.phone) IS NOT NULL AND u.role != 'admin'`
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

// POST /api/admin/sms/dues-reminder/:duesId — send dues reminder to a specific member
router.post('/sms/dues-reminder/:duesId', finOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT d.year, d.amount, d.status,
             u.full_name, COALESCE(p.phone, u.phone) AS phone
      FROM annual_dues d
      JOIN users u ON u.id = d.user_id
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE d.id = $1
    `, [req.params.duesId]);

    if (!rows.length) return res.status(404).json({ error: 'Dues record not found' });
    const r = rows[0];
    if (!r.phone) return res.status(400).json({ error: `${r.full_name} has no phone number on record` });

    const body =
      `UCOSA-NA Dues Reminder\n` +
      `Dear ${r.full_name},\n` +
      `Your ${r.year} annual dues of $${parseFloat(r.amount).toFixed(2)} are currently: ${r.status.toUpperCase()}.\n` +
      `Please log in at https://ucosa-na.org or contact the treasurer.\n` +
      `Thank you!`;

    await sendSMS(r.phone, body);
    res.json({ message: `Reminder sent to ${r.full_name} at ${r.phone}` });
  } catch (err) {
    console.error('Dues reminder SMS error:', err.message);
    res.status(500).json({ error: err.message });
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
    log.info(`Log viewer accessed by user ${req.user.id} (${req.user.role})`);
    res.json({ lines: lines.slice(-limit), total: lines.length });
  } catch (err) {
    res.status(500).json({ error: 'Could not read log file' });
  }
});

module.exports = router;
