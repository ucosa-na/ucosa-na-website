const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const os = require('os');
const { spawn } = require('child_process');
const pool = require('../db');
const requireAdmin = require('../middleware/requireAdmin');

const router = express.Router();

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
router.post('/users', requireAdmin, async (req, res) => {
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

    // Respond immediately with temp password
    res.status(201).json({
      message: `Member created. Welcome email will be sent to ${emailVal}`,
      tempPassword,
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
    }).catch(err => console.error('Welcome email failed for', emailVal, '— code:', err.code, '— message:', err.message));

  } catch (err) {
    console.error('Create member error:', err.message);
    res.status(500).json({ error: 'Failed to create member. ' + err.message });
  }
});

// POST /api/admin/test-email — send a test email to verify SMTP config
router.post('/test-email', requireAdmin, async (req, res) => {
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
router.get('/users', requireAdmin, async (req, res) => {
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

// GET /api/admin/metrics — live server metrics
router.get('/metrics', requireAdmin, async (req, res) => {
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
router.get('/backup', requireAdmin, (req, res) => {
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
router.get('/dues', requireAdmin, async (req, res) => {
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
router.post('/dues', requireAdmin, async (req, res) => {
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
router.put('/dues/:id', requireAdmin, async (req, res) => {
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
router.delete('/dues/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM annual_dues WHERE id=$1', [req.params.id]);
    res.json({ message: 'Dues record deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ENDOWMENT FUND ────────────────────────────────────────────────────────────

// GET /api/admin/endowment — all endowment records with member names
router.get('/endowment', requireAdmin, async (req, res) => {
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
router.post('/endowment', requireAdmin, async (req, res) => {
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
router.delete('/endowment/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM endowment_fund WHERE id=$1', [req.params.id]);
    res.json({ message: 'Endowment record deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/financials — upsert a financial record for a member
router.post('/financials', requireAdmin, async (req, res) => {
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
router.get('/financials/:userId', requireAdmin, async (req, res) => {
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

module.exports = router;
