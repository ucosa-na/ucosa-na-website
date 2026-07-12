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
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by INTEGER REFERENCES users(id) ON DELETE SET NULL;`)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL;`)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE annual_dues ADD COLUMN IF NOT EXISTS updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL;`)
).then(() =>
  pool.query(`ALTER TABLE endowment_fund ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE endowment_fund ADD COLUMN IF NOT EXISTS updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL;`)
).then(() =>
  pool.query(`ALTER TABLE member_profiles ADD COLUMN IF NOT EXISTS title TEXT DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE member_profiles ADD COLUMN IF NOT EXISTS alt_phone TEXT DEFAULT NULL;`)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS expense_records (
      id           SERIAL PRIMARY KEY,
      expense_date DATE NOT NULL,
      category     TEXT NOT NULL,
      description  TEXT,
      amount       NUMERIC(10,2) NOT NULL DEFAULT 0,
      approved_by  TEXT,
      recorded_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );
  `),

  pool.query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id                SERIAL PRIMARY KEY,
      action            TEXT NOT NULL,
      entity_type       TEXT NOT NULL,
      entity_id         INTEGER,
      entity_name       TEXT,
      performed_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
      performed_by_name TEXT,
      details           TEXT,
      created_at        TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS donations (
      id             SERIAL PRIMARY KEY,
      donor_name     TEXT NOT NULL,
      donor_email    TEXT NOT NULL,
      donor_phone    TEXT DEFAULT NULL,
      amount         NUMERIC(10,2) NOT NULL,
      currency       TEXT NOT NULL DEFAULT 'usd',
      stripe_payment_intent_id TEXT UNIQUE NOT NULL,
      status         TEXT NOT NULL DEFAULT 'succeeded',
      donated_at     TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS special_levies (
      id             SERIAL PRIMARY KEY,
      user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type           TEXT NOT NULL CHECK (type IN ('Special Levy','Voluntary Contribution','Member-Donation')),
      year           INTEGER NOT NULL,
      amount         NUMERIC(10,2) NOT NULL DEFAULT 0,
      paid_date      DATE DEFAULT NULL,
      donation_code  TEXT DEFAULT NULL,
      notes          TEXT DEFAULT NULL,
      recorded_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW(),
      updated_at     TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS special_levy_records (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      year          INTEGER NOT NULL,
      levy_type     TEXT NOT NULL CHECK (levy_type IN ('Convention','Calendar','Magazine')),
      levy_amount   NUMERIC(10,2) NOT NULL DEFAULT 0,
      advert_amount NUMERIC(10,2) NOT NULL DEFAULT 0,
      paid_date     DATE,
      status        TEXT NOT NULL DEFAULT 'unpaid' CHECK (status IN ('paid','unpaid','partial')),
      notes         TEXT,
      recorded_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS email_failures (
      id          SERIAL PRIMARY KEY,
      to_address  TEXT NOT NULL,
      subject     TEXT,
      error_msg   TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token      TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used       BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`ALTER TABLE special_levies ADD COLUMN IF NOT EXISTS donation_code TEXT DEFAULT NULL;`)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_inactivity_reminder_at TIMESTAMPTZ DEFAULT NULL;`)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS members_birthday (
      id             SERIAL PRIMARY KEY,
      user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      member_name    TEXT NOT NULL,
      birthday_month TEXT NOT NULL DEFAULT 'January',
      photo_url      TEXT DEFAULT NULL,
      UNIQUE(user_id)
    );
  `)
).then(() =>
  pool.query(`
    INSERT INTO members_birthday (user_id, member_name, birthday_month)
    SELECT id, full_name, 'January'
    FROM users
    WHERE is_active = TRUE
    ON CONFLICT (user_id) DO NOTHING;
  `)
).then(() =>
  pool.query(`ALTER TABLE members_birthday ADD COLUMN IF NOT EXISTS photo_url TEXT DEFAULT NULL;`)
).then(() =>
  pool.query(`DROP TABLE IF EXISTS member_fund_applications CASCADE;`)
).then(() =>
  pool.query(`
    CREATE TABLE member_fund_applications (
      id                    SERIAL PRIMARY KEY,
      user_id               INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      applicant_name        TEXT NOT NULL,
      sex                   TEXT CHECK (sex IN ('Male','Female')),
      birth_date            DATE,
      commencement_date     DATE,
      ssn_last4             TEXT,
      street_address        TEXT,
      city                  TEXT,
      state                 TEXT,
      zip_code              TEXT,
      email                 TEXT,
      alt_address           TEXT,
      alt_city              TEXT,
      alt_state             TEXT,
      alt_zip               TEXT,
      alt_phone             TEXT,
      alt_email             TEXT,
      ben1_name             TEXT,
      ben1_relation         TEXT,
      ben2_name             TEXT,
      ben2_relation         TEXT,
      ben3_name             TEXT,
      ben3_relation         TEXT,
      terms_accepted        BOOLEAN DEFAULT FALSE,
      applicant_signature   TEXT,
      signature_date        DATE,
      president_name        TEXT,
      president_signature   TEXT,
      president_date        DATE,
      status                TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied')),
      admin_approved        BOOLEAN DEFAULT NULL,
      admin_comment         TEXT,
      admin_signature       TEXT,
      admin_date            DATE,
      submitted_at          TIMESTAMPTZ DEFAULT NOW(),
      updated_at            TIMESTAMPTZ DEFAULT NOW(),
      updated_by            INTEGER REFERENCES users(id) ON DELETE SET NULL,
      UNIQUE(user_id)
    );
  `)
).then(() =>
  pool.query(`
    ALTER TABLE special_levies DROP CONSTRAINT IF EXISTS special_levies_type_check;
    ALTER TABLE special_levies ADD CONSTRAINT special_levies_type_check
      CHECK (type IN ('Special Levy','Voluntary Contribution','Member-Donation','Development Levy'));
  `)
).then(() =>
  pool.query(`ALTER TABLE special_levies ADD COLUMN IF NOT EXISTS amount_due NUMERIC(10,2) DEFAULT 200;`)
).then(() =>
  pool.query(`
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS finsec_commencement_correct BOOLEAN DEFAULT NULL;
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS finsec_status TEXT DEFAULT NULL;
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS finsec_reason TEXT DEFAULT NULL;
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS finsec_signature TEXT DEFAULT NULL;
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS finsec_date DATE DEFAULT NULL;
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS president_status TEXT DEFAULT NULL;
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS president_reason TEXT DEFAULT NULL;
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS president_signature TEXT DEFAULT NULL;
    ALTER TABLE member_fund_applications ADD COLUMN IF NOT EXISTS president_approval_date DATE DEFAULT NULL;
  `)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS executives (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      position   TEXT NOT NULL,
      status     TEXT NOT NULL DEFAULT 'current' CHECK (status IN ('current', 'past')),
      term_start DATE DEFAULT CURRENT_DATE,
      term_end   DATE DEFAULT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).then(() =>
  pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS prev_last_login TIMESTAMPTZ DEFAULT NULL;`)
).then(() =>
  pool.query(`
    CREATE TABLE IF NOT EXISTS join_requests (
      id             SERIAL PRIMARY KEY,
      full_name      TEXT NOT NULL,
      email          TEXT NOT NULL,
      phone          TEXT NOT NULL,
      address        TEXT DEFAULT NULL,
      reached_out    BOOLEAN DEFAULT FALSE,
      reached_out_by TEXT DEFAULT NULL,
      status         TEXT DEFAULT NULL,
      submitted_at   TIMESTAMPTZ DEFAULT NOW()
    );
  `)
).catch(err => {
  console.error('DB schema init failed:', err.message);
  process.exit(1);
});

module.exports = pool;
