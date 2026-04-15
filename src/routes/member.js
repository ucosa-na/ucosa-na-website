const express = require('express');
const pool = require('../db');
const requireAuth = require('../middleware/requireAuth');

const router = express.Router();

// GET /api/member/financials — own financial records
router.get('/financials', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT year, annual_dues, endowment_fund, notes FROM financial_records WHERE user_id = $1 ORDER BY year DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Financials error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
