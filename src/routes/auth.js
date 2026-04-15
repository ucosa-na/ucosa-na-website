const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const requireAuth = require('../middleware/requireAuth');

const router = express.Router();

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
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    // Record last login timestamp
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

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
