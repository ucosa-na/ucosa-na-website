const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Initialize schema on startup
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id        SERIAL PRIMARY KEY,
    full_name TEXT        NOT NULL,
    email     TEXT UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    must_change_password BOOLEAN DEFAULT TRUE,
    role      TEXT        DEFAULT 'member',
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
`).catch(err => {
  console.error('DB schema init failed:', err.message);
  process.exit(1);
});

module.exports = pool;
