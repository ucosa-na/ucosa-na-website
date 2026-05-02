// One-time script to populate annual dues records for 2023–2026.
// Run once: node scripts/seed-dues.js
require('dotenv').config();
const pool = require('../src/db');

const YEARS  = [2023, 2024, 2025, 2026];
const AMOUNT = 100.00;

async function main() {
  try {
    const { rows: members } = await pool.query(
      `SELECT id, full_name FROM users WHERE is_active = true ORDER BY full_name ASC`
    );
    console.log(`Found ${members.length} active member(s). Populating dues for years: ${YEARS.join(', ')}...\n`);

    let inserted = 0;
    let skipped  = 0;

    for (const m of members) {
      for (const year of YEARS) {
        const dueDate = `${year}-05-03`;
        const { rowCount } = await pool.query(`
          INSERT INTO annual_dues (user_id, year, amount, status, due_date, paid_date, payment_method)
          SELECT $1, $2, $3, 'unpaid', $4, NULL, NULL
          WHERE NOT EXISTS (
            SELECT 1 FROM annual_dues WHERE user_id = $1 AND year = $2
          )
        `, [m.id, year, AMOUNT, dueDate]);

        if (rowCount > 0) {
          console.log(`  [INSERTED] ${m.full_name} — ${year}`);
          inserted++;
        } else {
          console.log(`  [SKIPPED]  ${m.full_name} — ${year} (record already exists)`);
          skipped++;
        }
      }
    }

    console.log(`\nDone. ${inserted} inserted, ${skipped} skipped.`);
  } catch (err) {
    console.error('seed-dues failed:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();
