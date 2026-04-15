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
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ DEFAULT NULL
  );
`).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT NULL;`)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS financial_records (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      year          INTEGER NOT NULL,
      annual_dues   NUMERIC(10,2) DEFAULT 0,
      endowment_fund NUMERIC(10,2) DEFAULT 0,
      notes         TEXT DEFAULT NULL,
      updated_at    TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, year)
    );
  `)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS member_profiles (
      id              SERIAL PRIMARY KEY,
      user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      first_name      TEXT DEFAULT NULL,
      last_name       TEXT DEFAULT NULL,
      address         TEXT DEFAULT NULL,
      phone           TEXT DEFAULT NULL,
      year_joined     INTEGER DEFAULT NULL,
      graduation_year INTEGER DEFAULT NULL,
      updated_at      TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id)
    );
  `)
).catch(err => {
  console.error('DB schema init failed:', err.message);
  process.exit(1);
});

module.exports = pool;
