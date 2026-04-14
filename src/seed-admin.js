// Run once to create the initial admin account:
//   node src/seed-admin.js
require('dotenv').config();
const bcrypt = require('bcryptjs');
const pool = require('./db');

const email    = process.env.ADMIN_EMAIL         || 'ucosa.northamerica@gmail.com';
const password = process.env.ADMIN_INIT_PASSWORD || 'Admin@ucosa2026';
const fullName = 'UCOSA Admin';

async function main() {
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (rows.length > 0) {
      console.log('Admin already exists:', email);
      return;
    }

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (full_name, email, password_hash, must_change_password, role) VALUES ($1, $2, $3, FALSE, $4)',
      [fullName, email, hash, 'admin']
    );

    console.log('Admin created!');
    console.log('Email:   ', email);
    console.log('Password:', password);
    console.log('CHANGE THIS PASSWORD after first login.');
  } catch (err) {
    console.error('Seed failed:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();
