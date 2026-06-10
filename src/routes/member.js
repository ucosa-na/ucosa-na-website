const express = require('express');
const pool = require('../db');
const requireAuth = require('../middleware/requireAuth');

const router = express.Router();

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
      `SELECT id, status, submitted_at FROM member_fund_applications WHERE user_id = $1`,
      [req.user.id]
    );
    res.json(rows[0] || null);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/member/fund-application — submit the form
router.post('/fund-application', requireAuth, async (req, res) => {
  try {
    // One submission per member
    const { rows: existing } = await pool.query(
      `SELECT id FROM member_fund_applications WHERE user_id = $1`, [req.user.id]
    );
    if (existing.length) return res.status(409).json({ error: 'You have already submitted an application.' });

    const f = req.body;
    const { rows } = await pool.query(`
      INSERT INTO member_fund_applications (
        user_id, applicant_name, sex, birth_date, ssn_last4,
        street_address, city, state, zip_code, email,
        alt_address, alt_city, alt_state, alt_zip, alt_phone, alt_email,
        ben1_name, ben1_relation, ben2_name, ben2_relation, ben3_name, ben3_relation,
        terms_accepted, applicant_signature, signature_date,
        president_name, president_signature, president_date
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
        $11,$12,$13,$14,$15,$16,
        $17,$18,$19,$20,$21,$22,
        $23,$24,$25,$26,$27,$28
      ) RETURNING id, status`,
      [
        req.user.id, f.applicant_name, f.sex, f.birth_date || null, f.ssn_last4 || null,
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
