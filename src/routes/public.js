'use strict';

const express = require('express');
const pool    = require('../db');
const router  = express.Router();

// GET /api/public/birthdays/current-month — no auth, used by welcome page
router.get('/birthdays/current-month', async (req, res) => {
  const MONTHS = ['January','February','March','April','May','June','July',
                  'August','September','October','November','December'];
  const monthName = MONTHS[new Date().getMonth()];
  try {
    const { rows } = await pool.query(`
      SELECT mb.member_name, mb.birthday_month, mb.photo_url
      FROM members_birthday mb
      JOIN users u ON u.id = mb.user_id
      WHERE mb.birthday_month = $1
        AND u.is_active = TRUE
      ORDER BY mb.member_name ASC
    `, [monthName]);
    res.json({ month: monthName, members: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
