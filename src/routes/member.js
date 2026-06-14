const express = require('express');
const pool = require('../db');
const requireAuth = require('../middleware/requireAuth');
const { sendEmail } = require('../mailer');
const { sendSMS, normalizePhone } = require('../sms');

const router = express.Router();

// Enrollment period: Jun 15–Aug 15 for 2026; Jan 1–Mar 15 from 2027 onward
function isEnrollmentOpen() {
  const now   = new Date();
  const year  = now.getFullYear();
  const month = now.getMonth(); // 0 = January, 2 = March, 5 = June, 7 = August
  const day   = now.getDate();

  if (year === 2026) {
    // Jun 15 – Aug 15
    if (month === 5 && day >= 15) return true;  // Jun 15–30
    if (month === 6) return true;               // Jul fully open
    if (month === 7 && day <= 15) return true;  // Aug 1–15
    return false;
  }

  // 2027 and beyond: January 1 – March 15
  if (month === 0) return true;                 // Jan fully open
  if (month === 1) return true;                 // Feb fully open
  if (month === 2 && day <= 15) return true;    // Mar 1–15
  return false;
}

// GET /api/member/financials — own financial records (from annual_dues + endowment_fund)
router.get('/financials', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        u.full_name,
        ad.year,
        ad.amount        AS annual_dues,
        COALESCE(ef.total_endowment, 0) AS endowment_dues,
        ad.status,
        ad.due_date,
        ad.reminder_sent_at IS NOT NULL AS reminder_sent
      FROM annual_dues ad
      JOIN users u ON u.id = ad.user_id
      LEFT JOIN (
        SELECT user_id,
               EXTRACT(YEAR FROM contribution_date)::INT AS year,
               SUM(amount) AS total_endowment
        FROM endowment_fund
        GROUP BY user_id, EXTRACT(YEAR FROM contribution_date)::INT
      ) ef ON ef.user_id = ad.user_id AND ef.year = ad.year
      WHERE ad.user_id = $1
      ORDER BY ad.year DESC
    `, [req.user.id]);
    res.json(rows);
  } catch (err) {
    console.error('Financials error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/member/endowment — own endowment fund contributions
router.get('/endowment', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, amount, contribution_date, year, status, payment_method, notes, created_at
      FROM endowment_fund
      WHERE user_id = $1
      ORDER BY contribution_date DESC
    `, [req.user.id]);
    res.json(rows);
  } catch (err) {
    console.error('Endowment fetch error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/member/endowment-submit — member self-submits an endowment contribution
router.post('/endowment-submit', requireAuth, async (req, res) => {
  try {
    const { year, amount, payment_method, contribution_date, notes } = req.body;
    if (!year || !amount || !payment_method || !contribution_date) {
      return res.status(400).json({ error: 'year, amount, payment_method and contribution_date are required.' });
    }
    const { rows } = await pool.query(`
      INSERT INTO endowment_fund (user_id, amount, contribution_date, payment_method, notes, year, status)
      VALUES ($1, $2, $3, $4, $5, $6, 'pending')
      RETURNING id, amount, year, status`,
      [req.user.id, amount, contribution_date, payment_method, notes || null, year]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error('Endowment submit error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/member/fund-application — check if member already submitted
router.get('/fund-application', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, status, admin_comment, submitted_at FROM member_fund_applications WHERE user_id = $1`,
      [req.user.id]
    );
    res.json(rows[0] || null);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/member/fund-application — submit the form
router.post('/fund-application', requireAuth, async (req, res) => {
  if (!isEnrollmentOpen()) {
    return res.status(403).json({ error: 'The enrollment period is closed. For 2026, applications are accepted June 15 – August 15. From 2027 onward, enrollment runs January 1 – March 15 each year.' });
  }
  try {
    // One submission per member
    const { rows: existing } = await pool.query(
      `SELECT id FROM member_fund_applications WHERE user_id = $1`, [req.user.id]
    );
    if (existing.length) return res.status(409).json({ error: 'You have already submitted an application.' });

    const f = req.body;
    const { rows } = await pool.query(`
      INSERT INTO member_fund_applications (
        user_id, applicant_name, sex, birth_date, commencement_date, ssn_last4,
        street_address, city, state, zip_code, email,
        alt_address, alt_city, alt_state, alt_zip, alt_phone, alt_email,
        ben1_name, ben1_relation, ben2_name, ben2_relation, ben3_name, ben3_relation,
        terms_accepted, applicant_signature, signature_date,
        president_name, president_signature, president_date
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
        $11,$12,$13,$14,$15,$16,$17,
        $18,$19,$20,$21,$22,$23,
        $24,$25,$26,$27,$28,$29
      ) RETURNING id, status`,
      [
        req.user.id, f.applicant_name, f.sex, f.birth_date || null, f.commencement_date || null, f.ssn_last4 || null,
        f.street_address, f.city, f.state || null, f.zip_code || null, f.email,
        f.alt_address || null, f.alt_city || null, f.alt_state || null, f.alt_zip || null,
        f.alt_phone || null, f.alt_email || null,
        f.ben1_name || null, f.ben1_relation || null,
        f.ben2_name || null, f.ben2_relation || null,
        f.ben3_name || null, f.ben3_relation || null,
        f.terms_accepted || false, f.applicant_signature, f.signature_date || null,
        f.president_name || null, f.president_signature || null, f.president_date || null
      ]
    );
    res.json(rows[0]);

    // Notify member by email + SMS
    try {
      const { rows: uRows } = await pool.query(`SELECT full_name, email, phone FROM users WHERE id = $1`, [req.user.id]);
      const u = uRows[0] || {};
      const name = f.applicant_name || u.full_name || 'Member';
      if (u.email) {
        sendEmail({
          to: u.email,
          subject: "Fund Application Received — UCOSA-NA",
          html: `<p>Dear ${name},</p>
                 <p>Your <strong>Member's Endowment Fund Application</strong> has been received successfully.</p>
                 <p>The admin will review your application and you will be notified of the outcome.</p>
                 <p>Thank you,<br/>UCOSA-NA</p>`
        }).catch(() => {});
      }
      const phone = normalizePhone(u.phone);
      if (phone) {
        sendSMS(phone, `Dear ${name}, your UCOSA-NA Member's Endowment Fund Application has been received. The admin will review and notify you of the outcome. — UCOSA-NA`).catch(() => {});
      }
    } catch(_) {}

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/member/fund-application — update own application
router.put('/fund-application', requireAuth, async (req, res) => {
  if (!isEnrollmentOpen()) {
    return res.status(403).json({ error: 'The enrollment period is closed. For 2026, applications can be updated June 15 – August 15. From 2027 onward, enrollment runs January 1 – March 15 each year.' });
  }
  try {
    const { rows: existing } = await pool.query(
      `SELECT id, status, commencement_date FROM member_fund_applications WHERE user_id = $1`, [req.user.id]
    );
    if (!existing.length) return res.status(404).json({ error: 'No application found.' });
    const f = req.body;
    // Preserve commencement_date if previously approved — cannot be changed after approval
    const commencementDate = existing[0].status === 'approved'
      ? existing[0].commencement_date
      : (f.commencement_date || null);
    const { rows } = await pool.query(`
      UPDATE member_fund_applications SET
        applicant_name=$2, sex=$3, birth_date=$4, commencement_date=$5, ssn_last4=$6,
        street_address=$7, city=$8, state=$9, zip_code=$10, email=$11,
        alt_address=$12, alt_city=$13, alt_state=$14, alt_zip=$15, alt_phone=$16, alt_email=$17,
        ben1_name=$18, ben1_relation=$19, ben2_name=$20, ben2_relation=$21, ben3_name=$22, ben3_relation=$23,
        terms_accepted=$24, applicant_signature=$25, signature_date=$26,
        president_name=$27, president_signature=$28, president_date=$29,
        status='pending'
      WHERE user_id=$1
      RETURNING id, status`,
      [
        req.user.id, f.applicant_name, f.sex, f.birth_date || null, commencementDate, f.ssn_last4 || null,
        f.street_address, f.city, f.state || null, f.zip_code || null, f.email,
        f.alt_address || null, f.alt_city || null, f.alt_state || null, f.alt_zip || null,
        f.alt_phone || null, f.alt_email || null,
        f.ben1_name || null, f.ben1_relation || null,
        f.ben2_name || null, f.ben2_relation || null,
        f.ben3_name || null, f.ben3_relation || null,
        f.terms_accepted || false, f.applicant_signature, f.signature_date || null,
        f.president_name || null, f.president_signature || null, f.president_date || null
      ]
    );
    res.json(rows[0]);

    // Notify member of resubmission
    try {
      const { rows: uRows } = await pool.query(`SELECT full_name, email, phone FROM users WHERE id = $1`, [req.user.id]);
      const u = uRows[0] || {};
      const name = f.applicant_name || u.full_name || 'Member';
      if (u.email) {
        sendEmail({
          to: u.email,
          subject: 'Fund Application Resubmitted — UCOSA-NA',
          html: `<p>Dear ${name},</p>
                 <p>Your <strong>Member's Endowment Fund Application</strong> has been updated and resubmitted successfully.</p>
                 <p>The admin will review your updated application and notify you of the outcome.</p>
                 <p>Thank you,<br/>UCOSA-NA</p>`
        }).catch(() => {});
      }
      const phone = normalizePhone(u.phone);
      if (phone) {
        sendSMS(phone, `Dear ${name}, your UCOSA-NA Member's Endowment Fund Application has been updated and resubmitted. The admin will review and notify you. — UCOSA-NA`).catch(() => {});
      }
    } catch(_) {}

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/member/fund-application — delete own application
router.delete('/fund-application', requireAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM member_fund_applications WHERE user_id = $1`, [req.user.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'No application found.' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/member/dev-levy-status — check if member is eligible to pay development levy
router.get('/dev-levy-status', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    const { rows: [user] } = await pool.query('SELECT created_at FROM users WHERE id = $1', [userId]);
    const joinedAt = new Date(user.created_at);
    const now = new Date();
    const monthsElapsed = (now.getFullYear() - joinedAt.getFullYear()) * 12 + (now.getMonth() - joinedAt.getMonth());

    const { rows: [levyRow] } = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total_paid FROM special_levies WHERE user_id = $1 AND type = 'Development Levy'`,
      [userId]
    );

    const totalPaid = parseFloat(levyRow.total_paid);
    const remaining = Math.max(0, 200 - totalPaid);
    const withinSixMonths = monthsElapsed < 6;
    const fullyPaid = totalPaid >= 200;

    res.json({ eligible: withinSixMonths && !fullyPaid, withinSixMonths, fullyPaid, totalPaid, remaining });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
