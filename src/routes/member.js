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

module.exports = router;
