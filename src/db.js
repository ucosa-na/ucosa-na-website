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
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS annual_dues (
      id             SERIAL PRIMARY KEY,
      user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      year           INTEGER NOT NULL,
      amount         NUMERIC(10,2) NOT NULL DEFAULT 0,
      paid_date      DATE DEFAULT NULL,
      payment_method TEXT DEFAULT NULL,
      status         TEXT NOT NULL DEFAULT 'unpaid'
                       CHECK (status IN ('paid','partial','unpaid')),
      notes          TEXT DEFAULT NULL,
      recorded_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW(),
      updated_at     TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS endowment_fund (
      id             SERIAL PRIMARY KEY,
      user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount         NUMERIC(10,2) NOT NULL,
      contribution_date DATE DEFAULT CURRENT_DATE,
      payment_method TEXT DEFAULT NULL,
      notes          TEXT DEFAULT NULL,
      recorded_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`ALTER TABLE annual_dues ADD COLUMN IF NOT EXISTS due_date DATE DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE annual_dues ADD COLUMN IF NOT EXISTS reminder_sent_at TIMESTAMPTZ DEFAULT NULL;`)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS meeting_notes (
      id              SERIAL PRIMARY KEY,
      title           TEXT NOT NULL,
      meeting_date    DATE NOT NULL,
      original_name   TEXT NOT NULL,
      mime_type       TEXT NOT NULL,
      file_data       BYTEA NOT NULL,
      uploaded_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`ALTER TABLE endowment_fund ADD COLUMN IF NOT EXISTS year INTEGER DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE endowment_fund ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'paid';`)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_expires_at TIMESTAMPTZ DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;`)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT FALSE;`)
).catch(err => {
  console.error('DB schema init failed:', err.message);
  process.exit(1);
});

module.exports = pool;
