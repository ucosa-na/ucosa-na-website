'use strict';

const cron        = require('node-cron');
const pool        = require('./db');
const log         = require('./logger');
const { sendEmail } = require('./mailer');

const DUE_MONTH = 5;   // May
const DUE_DAY   = 3;

// ── Helpers ───────────────────────────────────────────────────────────────────

function getTwilioClient() {
  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (!sid || !token) return null;
  return require('twilio')(sid, token);
}

async function sendSMS(to, body) {
  const client = getTwilioClient();
  if (!client) return;
  const from = process.env.TWILIO_PHONE_NUMBER;
  if (!from) return;
  await client.messages.create({ to, from, body });
}

// Returns active members who don't have a 'paid' dues record for the given year
async function getUnpaidMembers(year) {
  const { rows } = await pool.query(`
    SELECT u.id, u.full_name, u.email,
           COALESCE(p.phone, u.phone) AS phone,
           d.amount, d.status
    FROM users u
    LEFT JOIN member_profiles p ON p.user_id = u.id
    LEFT JOIN annual_dues d ON d.user_id = u.id AND d.year = $1
    WHERE u.is_active = true
      AND u.role != 'admin'
      AND (d.id IS NULL OR d.status != 'paid')
    ORDER BY u.full_name ASC
  `, [year]);
  return rows;
}

function logoHeader() {
  return `
    <div style="background:#7b2152;text-align:center;padding:28px 32px">
      <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo"
           style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
      <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
    </div>`;
}

// ── January 1st: Populate annual dues records ─────────────────────────────────

async function populateAnnualDues() {
  const year    = new Date().getFullYear();
  const dueDate = `${year}-06-04`;   // June 4th of the current year
  log.info(`Scheduler: populating annual dues records for ${year}`);

  let members;
  try {
    const { rows } = await pool.query(
      `SELECT id FROM users WHERE is_active = true AND role != 'admin' ORDER BY id ASC`
    );
    members = rows;
  } catch (err) {
    log.error(`Scheduler: failed to fetch active members for dues population — ${err.message}`);
    return;
  }

  let inserted = 0;
  let skipped  = 0;

  for (const m of members) {
    try {
      // Only insert if no record already exists for this member/year
      const { rowCount } = await pool.query(`
        INSERT INTO annual_dues (user_id, year, amount, status, due_date, paid_date, payment_method)
        SELECT $1, $2, 100.00, 'unpaid', $3, NULL, NULL
        WHERE NOT EXISTS (
          SELECT 1 FROM annual_dues WHERE user_id = $1 AND year = $2
        )
      `, [m.id, year, dueDate]);

      if (rowCount > 0) inserted++;
      else              skipped++;
    } catch (err) {
      log.error(`Scheduler: dues record insert failed for user ${m.id} — ${err.message}`);
    }
  }

  log.info(`Scheduler: dues population complete for ${year} — ${inserted} inserted, ${skipped} already existed`);
}

// ── 30-Day Advance Reminder (April 3rd) ───────────────────────────────────────

async function sendAdvanceReminders() {
  const year    = new Date().getFullYear();
  const dueDate = `June 4, ${year}`;
  log.info(`Scheduler: sending 30-day dues advance reminders for ${year}`);

  let members;
  try {
    members = await getUnpaidMembers(year);
  } catch (err) {
    log.error(`Scheduler: failed to fetch unpaid members — ${err.message}`);
    return;
  }

  log.info(`Scheduler: ${members.length} member(s) to notify (30-day reminder)`);

  for (const m of members) {
    const amountFmt = m.amount ? `$${parseFloat(m.amount).toFixed(2)}` : '$100.00';

    // Email
    sendEmail({
      to:      m.email,
      subject: `UCOSA-NA — Annual Dues Reminder: Due ${dueDate}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          ${logoHeader()}
          <div style="background:#fdf6ec;padding:32px">
            <h2 style="color:#7b2152;margin-top:0">Annual Dues Reminder</h2>
            <p>Dear <strong>${m.full_name}</strong>,</p>
            <p>This is a friendly reminder that your <strong>${year} annual dues</strong> are due in <strong>30 days</strong>.</p>
            <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #c8a96e">
              <p style="margin:0"><strong>Due Date:</strong> ${dueDate}</p>
              <p style="margin:8px 0 0"><strong>Amount:</strong> ${amountFmt}</p>
              ${m.status ? `<p style="margin:8px 0 0"><strong>Status:</strong> ${m.status.charAt(0).toUpperCase() + m.status.slice(1)}</p>` : ''}
            </div>
            <p>Please make your payment through Zelle to: <strong>ucosa.northamerica@gmail.com</strong><br>or contact the treasurer for assistance.<br><em>If you've already made your payment, please ignore this message — and thank you!</em></p>
            <p style="color:#888;font-size:0.85em;margin-top:24px">UCOSA-North America &mdash; <a href="mailto:admin@ucosa-na.org">admin@ucosa-na.org</a></p>
          </div>
        </div>`,
    }).catch(err => log.error(`Scheduler: advance reminder email failed for ${m.email}: ${err.message}`));

    // SMS
    if (m.phone) {
      sendSMS(m.phone,
        `UCOSA-NA Dues Reminder\n` +
        `Dear ${m.full_name}, your ${year} annual dues (${amountFmt}) are due on ${dueDate}.\n` +
        `Please make your payment through Zelle to: ucosa.northamerica@gmail.com\nor contact the treasurer for assistance.\nIf you've already made your payment, please ignore this message — and thank you!`
      ).catch(err => log.error(`Scheduler: advance reminder SMS failed for ${m.phone}: ${err.message}`));
    }
  }

  log.info(`Scheduler: 30-day dues reminders dispatched for ${year}`);
}

// ── Due Date Reminder (June 4th) ─────────────────────────────────────────────

async function sendDueDateReminders() {
  const year    = new Date().getFullYear();
  const dueDate = `June 4, ${year}`;
  log.info(`Scheduler: sending due-date dues reminders for ${year}`);

  let members;
  try {
    members = await getUnpaidMembers(year);
  } catch (err) {
    log.error(`Scheduler: failed to fetch unpaid members — ${err.message}`);
    return;
  }

  log.info(`Scheduler: ${members.length} member(s) to notify (due-date reminder)`);

  for (const m of members) {
    const amountFmt = m.amount ? `$${parseFloat(m.amount).toFixed(2)}` : '$100.00';

    // Email
    sendEmail({
      to:      m.email,
      subject: `UCOSA-NA — Annual Dues Due Today (${dueDate})`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          ${logoHeader()}
          <div style="background:#fdf6ec;padding:32px">
            <h2 style="color:#7b2152;margin-top:0">Annual Dues Are Due Today</h2>
            <p>Dear <strong>${m.full_name}</strong>,</p>
            <p>Your <strong>${year} annual dues</strong> are due <strong>today, ${dueDate}</strong>.</p>
            <div style="background:white;border-radius:8px;padding:20px;margin:20px 0;border-left:4px solid #c8a96e">
              <p style="margin:0"><strong>Due Date:</strong> ${dueDate}</p>
              <p style="margin:8px 0 0"><strong>Amount:</strong> ${amountFmt}</p>
              ${m.status ? `<p style="margin:8px 0 0"><strong>Status:</strong> ${m.status.charAt(0).toUpperCase() + m.status.slice(1)}</p>` : ''}
            </div>
            <p>Please make your payment through Zelle to: <strong>ucosa.northamerica@gmail.com</strong><br>or contact the treasurer for assistance.<br><em>If you've already made your payment, please ignore this message — and thank you!</em></p>
            <p style="color:#888;font-size:0.85em;margin-top:24px">UCOSA-North America &mdash; <a href="mailto:admin@ucosa-na.org">admin@ucosa-na.org</a></p>
          </div>
        </div>`,
    }).catch(err => log.error(`Scheduler: due-date reminder email failed for ${m.email}: ${err.message}`));

    // SMS
    if (m.phone) {
      sendSMS(m.phone,
        `UCOSA-NA Dues Due Today\n` +
        `Dear ${m.full_name}, your ${year} annual dues (${amountFmt}) are due today, ${dueDate}.\n` +
        `Please make your payment through Zelle to: ucosa.northamerica@gmail.com\nor contact the treasurer for assistance.\nIf you've already made your payment, please ignore this message — and thank you!`
      ).catch(err => log.error(`Scheduler: due-date reminder SMS failed for ${m.phone}: ${err.message}`));
    }
  }

  log.info(`Scheduler: due-date dues reminders dispatched for ${year}`);
}

// ── Register cron jobs ────────────────────────────────────────────────────────

// January 1st at 00:01 AM — populate annual dues records for all active members
cron.schedule('1 0 1 1 *', populateAnnualDues, { timezone: 'America/New_York' });

// May 4th at 9:00 AM — 30-day advance reminder (30 days before June 4)
cron.schedule('0 9 4 5 *', sendAdvanceReminders, { timezone: 'America/New_York' });

// June 4th at 9:00 AM — due date reminder
cron.schedule('0 9 4 6 *', sendDueDateReminders, { timezone: 'America/New_York' });

log.info('Scheduler: annual dues jobs registered (Jan 1 populate, May 4 & June 4 reminders at 09:00 ET)');

module.exports = { populateAnnualDues, sendAdvanceReminders, sendDueDateReminders };
