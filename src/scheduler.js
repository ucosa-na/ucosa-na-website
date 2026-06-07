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

function duesReminderHtml(name, year, dueDate, amount, status) {
  const statusLabel = status
    ? status.charAt(0).toUpperCase() + status.slice(1)
    : 'Unpaid';
  return `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#333;">
      <div style="background:#1a1a2e;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;">
        <h1 style="color:#fff;margin:0;font-size:20px;">Annual Dues Reminder</h1>
      </div>
      <div style="background:#f9f9f9;padding:28px 32px;border-radius:0 0 10px 10px;">
        <p>Dear <strong>${name}</strong>,</p>
        <p>This is a friendly reminder that your <strong>${year} annual dues</strong> are due on <strong>${dueDate}</strong>.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
          <tbody>
            <tr><td style="padding:10px 16px;font-weight:600;color:#555;width:140px;">Due Date</td><td style="padding:10px 16px;">${dueDate}</td></tr>
            <tr style="background:#f4f4f4;"><td style="padding:10px 16px;font-weight:600;color:#555;">Amount</td><td style="padding:10px 16px;">${amount}</td></tr>
            <tr><td style="padding:10px 16px;font-weight:600;color:#555;">Status</td><td style="padding:10px 16px;">${statusLabel}</td></tr>
            <tr style="background:#f4f4f4;"><td style="padding:10px 16px;font-weight:600;color:#555;">Payment Info</td><td style="padding:10px 16px;">Zelle to &mdash; ucosa.northamerica@gmail.com</td></tr>
          </tbody>
        </table>
        <p><em>If you've already made your payment, please ignore this message &mdash; and thank you!</em></p>
        <p style="color:#888;font-size:13px;">— UCOSA-North America</p>
      </div>
    </div>`;
}

// ── January 1st: Populate annual dues records ─────────────────────────────────

async function populateAnnualDues() {
  const year    = new Date().getFullYear();
  const dueDate = `${year}-06-01`;   // June 4th of the current year
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
  const dueDate = `June 1, ${year}`;
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
      subject: `Annual Dues Reminder`,
      html:    duesReminderHtml(m.full_name, year, dueDate, amountFmt, m.status),
    }).catch(err => log.error(`Scheduler: advance reminder email failed for ${m.email}: ${err.message}`));

    // SMS
    if (m.phone) {
      sendSMS(m.phone,
        `UCOSA-NA Dues Reminder\n` +
        `Dear ${m.full_name}, your ${year} annual dues (${amountFmt}) are due in 30 days, on ${dueDate}.\n` +
        `Payment Info: Zelle to — ucosa.northamerica@gmail.com\nIf you've already made your payment, please ignore this message — and thank you!`
      ).catch(err => log.error(`Scheduler: advance reminder SMS failed for ${m.phone}: ${err.message}`));
    }
  }

  log.info(`Scheduler: 30-day dues reminders dispatched for ${year}`);
}

// ── Due Date Reminder (June 1st) ─────────────────────────────────────────────

async function sendDueDateReminders() {
  const year    = new Date().getFullYear();
  const dueDate = `June 1, ${year}`;
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
      subject: `Annual Dues Reminder`,
      html:    duesReminderHtml(m.full_name, year, dueDate, amountFmt, m.status),
    }).catch(err => log.error(`Scheduler: due-date reminder email failed for ${m.email}: ${err.message}`));

    // SMS
    if (m.phone) {
      sendSMS(m.phone,
        `UCOSA-NA Dues Due Today\n` +
        `Dear ${m.full_name}, your ${year} annual dues (${amountFmt}) are due today, ${dueDate}.\n` +
        `Payment Info: Zelle to — ucosa.northamerica@gmail.com\nIf you've already made your payment, please ignore this message — and thank you!`
      ).catch(err => log.error(`Scheduler: due-date reminder SMS failed for ${m.phone}: ${err.message}`));
    }
  }

  log.info(`Scheduler: due-date dues reminders dispatched for ${year}`);
}

// ── 90-Day Inactivity Reminder ────────────────────────────────────────────────

async function sendInactivityReminders() {
  log.info('Scheduler: checking for members inactive 90+ days');
  let members;
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.full_name, u.email,
             COALESCE(p.phone, u.phone) AS phone,
             u.last_login
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE u.is_active = TRUE
        AND u.role != 'admin'
        AND u.last_login IS NOT NULL
        AND u.last_login < NOW() - INTERVAL '90 days'
        AND (
          u.last_inactivity_reminder_at IS NULL
          OR u.last_inactivity_reminder_at < NOW() - INTERVAL '90 days'
        )
      ORDER BY u.last_login ASC
    `);
    members = rows;
  } catch (err) {
    log.error(`Scheduler: inactivity reminder query failed — ${err.message}`);
    return;
  }

  log.info(`Scheduler: ${members.length} member(s) to notify (90-day inactivity)`);

  for (const m of members) {
    const lastLoginDate = new Date(m.last_login).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    // Email
    sendEmail({
      to: m.email,
      subject: '👋 We Miss You — Please Log In to Your UCOSA-NA Account',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          <div style="background:#7b2152;text-align:center;padding:28px 32px">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
          </div>
          <div style="background:#fdf6ec;padding:32px">
            <h2 style="color:#7b2152;margin-top:0">Account Inactivity Notice</h2>
            <p>Dear <strong>${m.full_name}</strong>,</p>
            <p>We observed that you have not logged in to your UCOSA-NA account in <strong>90 days</strong>. Your last login was on <strong>${lastLoginDate}</strong>.</p>
            <p>Please log in to your account to stay up to date with:</p>
            <ul style="margin:12px 0 16px;padding-left:20px;line-height:1.8;">
              <li>Association news and announcements</li>
              <li>Your membership and dues status</li>
              <li>Upcoming events and meetings</li>
              <li>Important communications from the executive</li>
            </ul>
            <div style="text-align:center;margin:24px 0;">
              <a href="https://ucosa-na.org" style="background:#7b2152;color:#fff;text-decoration:none;padding:12px 32px;border-radius:6px;font-weight:700;font-size:16px;display:inline-block;">Log In Now</a>
            </div>
            <p>If you have any questions or need assistance logging in, contact us at
              <a href="mailto:ucosa.northamerica@gmail.com">ucosa.northamerica@gmail.com</a>.
            </p>
            <p style="color:#888;font-size:0.85em;margin-top:24px;">— UCOSA-North America Executive</p>
          </div>
        </div>
      `,
    }).catch(err => log.error(`Scheduler: inactivity email failed for ${m.email}: ${err.message}`));

    // SMS
    if (m.phone) {
      sendSMS(m.phone,
        `UCOSA-NA: Hi ${m.full_name}, we observed you have not logged in to your UCOSA account in 90 days.\n` +
        `Please log in to see what is happening and check your account status.\n` +
        `Login: https://ucosa-na.org`
      ).catch(err => log.error(`Scheduler: inactivity SMS failed for ${m.phone}: ${err.message}`));
    }

    // Mark reminder sent
    pool.query(
      `UPDATE users SET last_inactivity_reminder_at = NOW() WHERE id = $1`,
      [m.id]
    ).catch(err => log.error(`Scheduler: failed to update last_inactivity_reminder_at for user ${m.id}: ${err.message}`));
  }

  log.info(`Scheduler: 90-day inactivity reminders dispatched to ${members.length} member(s)`);
}

// ── Register cron jobs ────────────────────────────────────────────────────────

// January 1st at 00:01 AM — populate annual dues records for all active members
cron.schedule('1 0 1 1 *', populateAnnualDues, { timezone: 'America/New_York' });

// May 2nd at 9:00 AM — 30-day advance reminder (30 days before June 1)
cron.schedule('0 9 2 5 *', sendAdvanceReminders, { timezone: 'America/New_York' });

// June 1st at 9:00 AM — due date reminder
cron.schedule('0 9 1 6 *', sendDueDateReminders, { timezone: 'America/New_York' });

// Daily at 8:00 AM — 90-day inactivity reminder
cron.schedule('0 8 * * *', sendInactivityReminders, { timezone: 'America/New_York' });

log.info('Scheduler: jobs registered (Jan 1 populate, May 2 & June 1 dues reminders, daily 8AM inactivity check)');

module.exports = { populateAnnualDues, sendAdvanceReminders, sendDueDateReminders, sendInactivityReminders };
