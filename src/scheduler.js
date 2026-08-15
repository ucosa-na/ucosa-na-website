'use strict';

const cron        = require('node-cron');
const pool        = require('./db');
const log         = require('./logger');
const { sendEmail } = require('./mailer');

const { sendSMS } = require('./sms');

const DUE_MONTH = 5;   // May
const DUE_DAY   = 3;

// ── General Meeting Zoom constants (reused across all notifications) ───────────
const GENERAL_ZOOM_LINK = 'https://us02web.zoom.us/j/88274188382?pwd=RzVEUFZRYWYxUVl4dkFZdEVBdzhlQT09';
const GENERAL_ZOOM_ID   = '882 7418 8382';
const GENERAL_ZOOM_PASS = '161773';

function zoomMeetingBlock() {
  return `
    <div style="background:#f0f4ff;border:1.5px solid #1a3a8f;border-radius:8px;padding:16px 20px;margin:24px 0 8px;">
      <p style="font-weight:700;color:#1a3a8f;margin:0 0 8px;font-size:14px;">Monthly General Meeting — Last Sunday of Every Month</p>
      <p style="margin:0 0 4px;font-size:13px;color:#333;">Time: 5:00 PM Eastern &nbsp;|&nbsp; 4:00 PM Central (US &amp; Canada)</p>
      <p style="margin:0 0 6px;font-size:13px;color:#333;">Meeting ID: ${GENERAL_ZOOM_ID} &nbsp;|&nbsp; Passcode: ${GENERAL_ZOOM_PASS}</p>
      <a href="${GENERAL_ZOOM_LINK}" style="color:#2d8cff;font-size:13px;font-weight:600;">Join Zoom Meeting &rarr;</a>
    </div>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const sleep = ms => new Promise(r => setTimeout(r, ms));

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
      AND u.id != 1
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
        ${zoomMeetingBlock()}
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
      `SELECT id FROM users WHERE is_active = true AND id != 1 ORDER BY id ASC`
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

    try {
      await sendEmail({
        to:      m.email,
        subject: `Annual Dues Reminder`,
        html:    duesReminderHtml(m.full_name, year, dueDate, amountFmt, m.status),
      });
    } catch (err) {
      log.error(`Scheduler: advance reminder email failed for ${m.email}: ${err.message}`);
    }
    await sleep(250);

    if (m.phone) {
      try {
        await sendSMS(m.phone,
          `UCOSA-NA Dues Reminder\n` +
          `Dear ${m.full_name}, your ${year} annual dues (${amountFmt}) are due in 30 days, on ${dueDate}.\n` +
          `Payment Info: Zelle to — ucosa.northamerica@gmail.com\nIf you've already made your payment, please ignore this message — and thank you!\n\n` +
          `Monthly General Meeting — Last Sunday of every month at 5:00 PM Eastern.\n` +
          `Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS}`
        );
      } catch (err) { log.error(`Scheduler: advance reminder SMS failed for ${m.phone}: ${err.message}`); }
      await sleep(300);
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

    try {
      await sendEmail({
        to:      m.email,
        subject: `Annual Dues Reminder`,
        html:    duesReminderHtml(m.full_name, year, dueDate, amountFmt, m.status),
      });
    } catch (err) {
      log.error(`Scheduler: due-date reminder email failed for ${m.email}: ${err.message}`);
    }
    await sleep(250);

    if (m.phone) {
      try {
        await sendSMS(m.phone,
          `UCOSA-NA Dues Due Today\n` +
          `Dear ${m.full_name}, your ${year} annual dues (${amountFmt}) are due today, ${dueDate}.\n` +
          `Payment Info: Zelle to — ucosa.northamerica@gmail.com\nIf you've already made your payment, please ignore this message — and thank you!\n\n` +
          `Monthly General Meeting — Last Sunday of every month at 5:00 PM Eastern.\n` +
          `Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS}`
        );
      } catch (err) { log.error(`Scheduler: due-date reminder SMS failed for ${m.phone}: ${err.message}`); }
      await sleep(300);
    }
  }

  log.info(`Scheduler: due-date dues reminders dispatched for ${year}`);
}

// ── Monthly Birthday Email (1st of each month) ────────────────────────────────

async function sendBirthdayEmails() {
  const MONTHS = ['January','February','March','April','May','June','July',
                  'August','September','October','November','December'];
  const monthName = MONTHS[new Date().getMonth()];
  log.info(`Scheduler: sending birthday emails for ${monthName}`);

  let members;
  try {
    const { rows } = await pool.query(`
      SELECT mb.member_name, mb.birthday_month,
             u.email, COALESCE(p.phone, u.phone) AS phone
      FROM members_birthday mb
      JOIN users u ON u.id = mb.user_id
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE mb.birthday_month = $1
        AND u.is_active = TRUE
    `, [monthName]);
    members = rows;
  } catch (err) {
    log.error(`Scheduler: birthday query failed — ${err.message}`);
    return;
  }

  log.info(`Scheduler: ${members.length} birthday member(s) for ${monthName}`);

  for (const m of members) {
    try { await sendEmail({
      to: m.email,
      subject: `🎂 Happy Birthday, ${m.member_name}! — UCOSA-NA`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          <div style="background:#7b2152;text-align:center;padding:28px 32px">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
          </div>
          <div style="background:#fdf6ec;padding:32px;text-align:center">
            <div style="font-size:60px;line-height:1;">🎂</div>
            <h2 style="color:#7b2152;margin:12px 0 4px;font-size:26px;">Happy Birthday, ${m.member_name}!</h2>
            <p style="color:#555;font-size:16px;margin:0 0 20px;">Welcome to your birthday month of <strong>${monthName}</strong>!</p>
            <div style="background:white;border-radius:10px;padding:20px 24px;text-align:left;border-left:4px solid #c8a96e;margin-bottom:20px;">
              <p style="margin:0 0 12px;font-size:15px;color:#333;">
                On behalf of the entire UCOSA-NA family, we wish you a wonderful and joyful birthday month.
                May this new year of your life bring you abundant blessings, good health, peace, and happiness.
              </p>
              <p style="margin:0;font-size:15px;color:#555;font-style:italic;">
                🙏 <strong>A short prayer for you:</strong><br><br>
                May the Lord bless you and keep you. May His face shine upon you and be gracious to you.
                May He grant you long life, good health, and fulfilment in all you set out to do.
                May this birthday mark the beginning of your best year yet — surrounded by love, laughter, and the warmth of family and friends.
                Amen. 🕊️
              </p>
            </div>
            ${zoomMeetingBlock()}
            <p style="color:#888;font-size:13px;margin-top:12px;">With love and warm regards,<br><strong>UCOSA-North America Executive</strong></p>
          </div>
        </div>
      `,
    }); } catch (err) { log.error(`Scheduler: birthday email failed for ${m.email}: ${err.message}`); }
    await sleep(250);

    if (m.phone) {
      try {
        await sendSMS(m.phone,
          `Happy Birthday, ${m.member_name}!\n` +
          `Welcome to your birthday month of ${monthName}!\n\n` +
          `On behalf of the entire UCOSA-NA family, we wish you a wonderful birthday month filled with joy, good health, and blessings.\n\n` +
          `Monthly General Meeting — Last Sunday of every month at 5:00 PM Eastern.\n` +
          `Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS}\n\n` +
          `— UCOSA-North America`
        );
      } catch (err) { log.error(`Scheduler: birthday SMS failed for ${m.phone}: ${err.message}`); }
      await sleep(300);
    }
  }

  log.info(`Scheduler: birthday emails dispatched for ${monthName} (${members.length} member(s))`);
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
        AND u.id != 1
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
    try { await sendEmail({
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
            ${zoomMeetingBlock()}
            <p style="color:#888;font-size:0.85em;margin-top:12px;">— UCOSA-North America Executive</p>
          </div>
        </div>
      `,
    }); } catch (err) { log.error(`Scheduler: inactivity email failed for ${m.email}: ${err.message}`); }
    await sleep(250);

    // SMS
    if (m.phone) {
      try {
        await sendSMS(m.phone,
          `UCOSA-NA: Hi ${m.full_name}, we observed you have not logged in to your UCOSA account in 90 days.\n` +
          `Please log in to see what is happening and check your account status.\n` +
          `Login: https://ucosa-na.org\n\n` +
          `Monthly General Meeting — Last Sunday of every month at 5:00 PM Eastern.\n` +
          `Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS}`
        );
      } catch (err) { log.error(`Scheduler: inactivity SMS failed for ${m.phone}: ${err.message}`); }
      await sleep(300);
    }

    // Mark reminder sent
    pool.query(
      `UPDATE users SET last_inactivity_reminder_at = NOW() WHERE id = $1`,
      [m.id]
    ).catch(err => log.error(`Scheduler: failed to update last_inactivity_reminder_at for user ${m.id}: ${err.message}`));
  }

  log.info(`Scheduler: 90-day inactivity reminders dispatched to ${members.length} member(s)`);
}

// ── Endowment Fund Enrollment Open notification (email + SMS) ─────────────────
// Triggered June 15 for 2026, January 1 from 2027 onwards

async function sendEnrollmentOpenNotifications() {
  const year = new Date().getFullYear();
  const enrollDeadline = year === 2026 ? 'August 15' : 'March 15';
  const enrollPeriod   = year === 2026 ? 'June 14 – August 15' : 'January 1 – March 15';

  log.info(`Scheduler: sending endowment enrollment open notifications for ${year} (${enrollPeriod})`);

  let members;
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.full_name, u.email, COALESCE(p.phone, u.phone) AS phone
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE u.is_active = TRUE AND u.id != 1
      ORDER BY u.full_name ASC
    `);
    members = rows;
  } catch (err) {
    log.error(`Scheduler: failed to fetch members for enrollment notification — ${err.message}`);
    return;
  }

  if (!members.length) { log.info('Scheduler: no active members for enrollment notification'); return; }

  log.info(`Scheduler: sending enrollment notifications to ${members.length} member(s)`);

  for (const m of members) {
    // Email
    if (m.email) {
      try { await sendEmail({
        to: m.email,
        subject: `UCOSA-NA Member's Endowment Fund — Enrollment Now Open (${year})`,
        html: `
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#fdf6ec;margin:0;padding:0}
  .wrap{max-width:600px;margin:32px auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.08)}
  .hdr{background:#7b2152;padding:28px 36px;text-align:center}
  .hdr img{width:80px;height:80px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px}
  .hdr h1{color:#f5e6d0;font-size:20px;margin:0;letter-spacing:.06em}
  .hdr p{color:#d4a0b8;font-size:12px;margin:6px 0 0;text-transform:uppercase;letter-spacing:.1em}
  .body{padding:32px 36px;color:#333;font-size:15px;line-height:1.75}
  .body p{margin:0 0 14px}
  .badge{display:inline-block;background:#1b5e20;color:#fff;padding:6px 18px;border-radius:20px;font-size:13px;font-weight:700;margin-bottom:18px}
  .info-box{background:#f0f7ff;border-left:4px solid #0d47a1;border-radius:0 8px 8px 0;padding:14px 18px;margin:16px 0}
  .cta{text-align:center;margin:24px 0}
  .cta a{background:#7b2152;color:#fff;text-decoration:none;padding:14px 36px;border-radius:6px;font-weight:700;font-size:14px;letter-spacing:.06em;text-transform:uppercase;display:inline-block;margin:6px}
  .ftr{background:#1a1a2e;color:#aab4c8;text-align:center;padding:16px 20px;font-size:12px}
  .ftr a{color:#c8a96e;text-decoration:none}
  strong{color:#7b2152}
</style></head><body>
<div class="wrap">
  <div class="hdr">
    <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo"/>
    <h1>UCOSA-NA Member's Endowment Fund</h1>
    <p>Bereavement Benefit Program — ${year}</p>
  </div>
  <div class="body">
    <p>Dear <strong>${m.full_name}</strong>,</p>
    <div class="badge">✅ Enrollment Now Open</div>
    <p>We are pleased to announce that the <strong>UCOSA-NA Member's Endowment Fund (UCOSA-MF)</strong> enrollment period is now open for <strong>${year}</strong>.</p>
    <div class="info-box">
      <strong style="color:#0d47a1;">Enrollment Period: ${enrollPeriod}, ${year}</strong><br/>
      <span style="font-size:14px;color:#444;">Applications submitted after ${enrollDeadline}, ${year} will not be accepted until the next enrollment period.</span>
    </div>
    <p>The UCOSA-MF provides financial assistance to enrolled members and their designated beneficiaries during times of bereavement. Benefits range from <strong>$250 up to $5,000</strong> depending on your continuous enrollment period, with a maximum lifetime benefit of <strong>$10,000</strong>.</p>
    <p>To enroll, log in to your Member Portal and complete the <strong>Member's Endowment Fund Application</strong> using the button below.</p>
    <div class="cta">
      <a href="https://ucosa-na.org/member-fund-form.html">Complete Endowment Fund Application</a>
      <a href="https://ucosa-na.org/members.html" style="background:#0d47a1;">Log In to Member Portal</a>
    </div>
    <div style="background:#f0f4ff;border:1.5px solid #1a3a8f;border-radius:8px;padding:16px 20px;margin:24px 0 8px;">
      <p style="font-weight:700;color:#1a3a8f;margin:0 0 8px;font-size:14px;">Monthly General Meeting — Last Sunday of Every Month</p>
      <p style="margin:0 0 4px;font-size:13px;color:#333;">Time: 5:00 PM Eastern &nbsp;|&nbsp; 4:00 PM Central (US &amp; Canada)</p>
      <p style="margin:0 0 6px;font-size:13px;color:#333;">Meeting ID: ${GENERAL_ZOOM_ID} &nbsp;|&nbsp; Passcode: ${GENERAL_ZOOM_PASS}</p>
      <a href="${GENERAL_ZOOM_LINK}" style="color:#2d8cff;font-size:13px;font-weight:600;">Join Zoom Meeting &rarr;</a>
    </div>
    <p>With warmth and fellowship,</p>
    <p><strong>The Executive Committee</strong><br/>UCOSA-North America<br/><a href="https://ucosa-na.org" style="color:#7b2152;">www.ucosa-na.org</a></p>
  </div>
  <div class="ftr">&copy; ${year} UCOSA-North America. All rights reserved. &mdash; <a href="https://ucosa-na.org">ucosa-na.org</a></div>
</div>
</body></html>`.trim(),
      }); } catch (err) { log.error(`Scheduler: enrollment email failed for ${m.email}: ${err.message}`); }
      await sleep(250);
    }

    // SMS
    if (m.phone) {
      try {
        await sendSMS(m.phone,
          `Dear ${m.full_name}, the UCOSA-NA Endowment Fund enrollment is now OPEN (${enrollPeriod}, ${year}).\n` +
          `Apply here: https://ucosa-na.org/member-fund-form.html\n\n` +
          `Monthly General Meeting — Last Sunday of every month at 5:00 PM Eastern.\n` +
          `Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS}\n— UCOSA-NA`
        );
      } catch (err) { log.error(`Scheduler: enrollment SMS failed for ${m.phone}: ${err.message}`); }
      await sleep(300);
    }
  }

  log.info(`Scheduler: enrollment open notifications dispatched to ${members.length} member(s)`);
}

// ── General Meeting Auto-Reminders ────────────────────────────────────────────

function getLastSundayOfMonth(year, month) {
  // Use noon UTC to avoid date shifting when formatted in Eastern time (UTC-4/5)
  const lastDay = new Date(Date.UTC(year, month + 1, 0, 12, 0, 0));
  lastDay.setUTCDate(lastDay.getUTCDate() - lastDay.getUTCDay());
  return lastDay;
}

function fmtMeetingDate(date) {
  return date.toLocaleDateString('en-US', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    timeZone: 'America/New_York',
  });
}

function generalMeetingHtml(memberName, formatted, badgeHtml, introPara) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f0eb;margin:0;padding:0}
  .wrap{max-width:600px;margin:32px auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.08)}
  .hdr{background:#7b2152;padding:28px 36px;text-align:center}
  .hdr img{width:80px;height:80px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px}
  .hdr h1{color:#f5e6d0;font-size:22px;margin:0;letter-spacing:.04em}
  .hdr p{color:#d4a0b8;font-size:12px;margin:6px 0 0;text-transform:uppercase;letter-spacing:.1em}
  .body{padding:32px 36px;color:#333;font-size:15px;line-height:1.8}
  .body p{margin:0 0 14px}
  .invite-box{background:#f0f4ff;border:1.5px solid #1a3a8f;border-radius:8px;padding:20px 24px;margin:20px 0}
  .invite-box h2{color:#1a3a8f;font-size:16px;margin:0 0 14px;border-bottom:1px solid #c5d0f5;padding-bottom:8px}
  .invite-box .row{display:flex;gap:10px;margin-bottom:8px;font-size:14px}
  .invite-box .label{font-weight:700;color:#444;min-width:110px}
  .cta{text-align:center;margin:24px 0}
  .cta a{background:#2d8cff;color:#fff;text-decoration:none;padding:14px 36px;border-radius:6px;font-weight:700;font-size:15px;display:inline-block}
  .ftr{background:#1a1a2e;color:#aab4c8;text-align:center;padding:16px 20px;font-size:12px}
  .ftr a{color:#c8a96e;text-decoration:none}
</style></head><body>
<div class="wrap">
  ${badgeHtml}
  <div class="hdr">
    <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo"/>
    <h1>UCOSA-NA Monthly General Meeting</h1>
    <p>${formatted}</p>
  </div>
  <div class="body">
    <p>Dear <strong>${memberName}</strong>,</p>
    ${introPara}
    <div class="invite-box">
      <h2>&#128197; Meeting Details</h2>
      <div class="row"><span class="label">Topic:</span><span>UCOSA North America Monthly General Zoom Meeting</span></div>
      <div class="row"><span class="label">Date:</span><span>${formatted}</span></div>
      <div class="row"><span class="label">Time:</span><span>5:00 PM Eastern &nbsp;|&nbsp; 4:00 PM Central (US &amp; Canada)</span></div>
      <div class="row"><span class="label">Meeting ID:</span><span>${GENERAL_ZOOM_ID}</span></div>
      <div class="row"><span class="label">Passcode:</span><span>${GENERAL_ZOOM_PASS}</span></div>
    </div>
    <div class="cta">
      <a href="${GENERAL_ZOOM_LINK}">&#128249; Join Zoom Meeting</a>
    </div>
    <p style="font-size:13px;color:#888;text-align:center;">Or copy this link:<br/>
      <a href="${GENERAL_ZOOM_LINK}" style="color:#2d8cff;word-break:break-all;">${GENERAL_ZOOM_LINK}</a>
    </p>
    <p>With warmth and fellowship,</p>
    <p><strong>The Executive Committee</strong><br/>UCOSA-North America<br/><a href="https://ucosa-na.org" style="color:#7b2152;">www.ucosa-na.org</a></p>
  </div>
  <div class="ftr">&copy; ${new Date().getFullYear()} UCOSA-North America. All rights reserved. &mdash; <a href="https://ucosa-na.org">ucosa-na.org</a></div>
</div>
</body></html>`.trim();
}

async function sendGeneralMeetingNotices(meetingDate, type) {
  const formatted = fmtMeetingDate(meetingDate);

  let subject, badgeHtml, introPara, smsFn;

  if (type === 'invite') {
    subject   = `UCOSA-NA Monthly General Meeting — ${formatted}`;
    badgeHtml = '';
    introPara = `<p>You are cordially invited to the <strong>UCOSA North America Monthly General Zoom Meeting</strong>. We look forward to your participation.</p>`;
    smsFn     = n => `Dear ${n}, you are invited to the UCOSA-NA Monthly General Meeting on ${formatted} at 5:00 PM Eastern. Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS} — UCOSA-NA`;
  } else if (type === 3) {
    subject   = `Reminder: UCOSA-NA General Meeting in 3 Days — ${formatted}`;
    badgeHtml = `<div style="background:#e65100;color:#fff;text-align:center;padding:10px;font-size:14px;font-weight:700;">REMINDER — Meeting in 3 Days</div>`;
    introPara = `<p>This is a friendly reminder that the <strong>UCOSA-NA Monthly General Zoom Meeting</strong> is in <strong>3 days</strong> on <strong>${formatted}</strong> at <strong>5:00 PM Eastern</strong>.</p>`;
    smsFn     = n => `UCOSA-NA Reminder: Dear ${n}, the Monthly General Meeting is in 3 days on ${formatted} at 5:00 PM Eastern. Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS} — UCOSA-NA`;
  } else if (type === 2) {
    subject   = `Reminder: UCOSA-NA General Meeting in 2 Days — ${formatted}`;
    badgeHtml = `<div style="background:#e65100;color:#fff;text-align:center;padding:10px;font-size:14px;font-weight:700;">REMINDER — Meeting in 2 Days</div>`;
    introPara = `<p>This is a friendly reminder that the <strong>UCOSA-NA Monthly General Zoom Meeting</strong> is in <strong>2 days</strong> on <strong>${formatted}</strong> at <strong>5:00 PM Eastern</strong>.</p>`;
    smsFn     = n => `UCOSA-NA Reminder: Dear ${n}, the Monthly General Meeting is in 2 days on ${formatted} at 5:00 PM Eastern. Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS} — UCOSA-NA`;
  } else if (type === 1) {
    subject   = `Reminder: UCOSA-NA General Meeting is Tomorrow — ${formatted}`;
    badgeHtml = `<div style="background:#c62828;color:#fff;text-align:center;padding:10px;font-size:14px;font-weight:700;">REMINDER — Meeting is TOMORROW</div>`;
    introPara = `<p>This is a reminder that the <strong>UCOSA-NA Monthly General Zoom Meeting</strong> is <strong>tomorrow</strong>, <strong>${formatted}</strong> at <strong>5:00 PM Eastern</strong>. Please make sure you have the details ready.</p>`;
    smsFn     = n => `UCOSA-NA Reminder: Dear ${n}, the Monthly General Meeting is TOMORROW, ${formatted} at 5:00 PM Eastern. Join: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS} — UCOSA-NA`;
  } else if (type === 'hour') {
    subject   = `Meeting Starts in 1 Hour — UCOSA-NA General Meeting Today`;
    badgeHtml = `<div style="background:#1b5e20;color:#fff;text-align:center;padding:10px;font-size:14px;font-weight:700;">MEETING STARTS IN 1 HOUR — Join Now!</div>`;
    introPara = `<p>The <strong>UCOSA-NA Monthly General Zoom Meeting</strong> starts in <strong>1 hour</strong> at <strong>5:00 PM Eastern</strong> today, <strong>${formatted}</strong>. Please join on time.</p>`;
    smsFn     = n => `UCOSA-NA: Dear ${n}, the Monthly General Meeting starts in 1 HOUR at 5:00 PM Eastern today. Join now: ${GENERAL_ZOOM_LINK} | ID: ${GENERAL_ZOOM_ID} | Passcode: ${GENERAL_ZOOM_PASS} — UCOSA-NA`;
  } else {
    return;
  }

  let members;
  try {
    const { rows } = await pool.query(`
      SELECT u.full_name, u.email, COALESCE(p.phone, u.phone) AS phone
      FROM users u
      LEFT JOIN member_profiles p ON p.user_id = u.id
      WHERE u.is_active = TRUE AND u.id != 1
      UNION
      SELECT fm.full_name, fm.email, fm.phone
      FROM former_members fm
      WHERE fm.status = 'pending'
        AND (fm.email IS NOT NULL OR fm.phone IS NOT NULL)
      ORDER BY full_name ASC
    `);
    members = rows;
  } catch (err) {
    log.error(`General meeting notice (${type}): DB query failed — ${err.message}`);
    return;
  }

  log.info(`General meeting notice (${type}): sending to ${members.length} member(s) for ${formatted}`);

  let emailCount = 0, smsCount = 0;
  for (const m of members) {
    if (m.email) {
      try {
        await sendEmail({ to: m.email, subject, html: generalMeetingHtml(m.full_name, formatted, badgeHtml, introPara) });
        emailCount++;
      } catch (err) {
        log.error(`General meeting email failed for ${m.email}: ${err.message}`);
      }
      await sleep(250);
    }
    if (m.phone) {
      try {
        await sendSMS(m.phone, smsFn(m.full_name));
        smsCount++;
      } catch (err) {
        log.error(`General meeting SMS failed for ${m.phone}: ${err.message}`);
      }
      await sleep(300);
    }
  }

  log.info(`General meeting notice (${type}): dispatched — ${emailCount} email(s), ${smsCount} SMS(es)`);
}

// Daily check: fires 7-day invite, 3-day reminder, or 1-day reminder
async function checkGeneralMeetingDayReminders() {
  try {
    const etStr  = new Date().toLocaleString('en-US', { timeZone: 'America/New_York' });
    const etNow  = new Date(etStr);
    const year   = etNow.getFullYear();
    const month  = etNow.getMonth();
    const today  = new Date(year, month, etNow.getDate());
    const lastSun = getLastSundayOfMonth(year, month);
    const meeting = new Date(lastSun.getFullYear(), lastSun.getMonth(), lastSun.getDate());
    const diffDays = Math.round((meeting - today) / 86400000);

    if      (diffDays === 7) await sendGeneralMeetingNotices(lastSun, 'invite');
    else if (diffDays === 3) await sendGeneralMeetingNotices(lastSun, 3);
    else if (diffDays === 2) await sendGeneralMeetingNotices(lastSun, 2); // catch-up if 3-day was missed
    else if (diffDays === 1) await sendGeneralMeetingNotices(lastSun, 1);
    else log.info(`General meeting day check: ${diffDays} day(s) to meeting — no notice needed`);
  } catch (err) {
    log.error(`checkGeneralMeetingDayReminders failed: ${err.message}`);
  }
}

// Sunday 4 PM check: fires 1-hour notice if today is the last Sunday
async function checkGeneralMeetingHourReminder() {
  try {
    const etStr  = new Date().toLocaleString('en-US', { timeZone: 'America/New_York' });
    const etNow  = new Date(etStr);
    const year   = etNow.getFullYear();
    const month  = etNow.getMonth();
    const today  = new Date(year, month, etNow.getDate());
    const lastSun = getLastSundayOfMonth(year, month);
    const meeting = new Date(lastSun.getFullYear(), lastSun.getMonth(), lastSun.getDate());

    if (today.getTime() === meeting.getTime()) {
      await sendGeneralMeetingNotices(lastSun, 'hour');
    } else {
      log.info('General meeting hour check: not meeting day, skipping');
    }
  } catch (err) {
    log.error(`checkGeneralMeetingHourReminder failed: ${err.message}`);
  }
}

// ── Former Member Invite Broadcast (every 60 days) ───────────────────────────

function buildFormerMemberInviteHtml(fullName) {
  return `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#fdf6ec;margin:0;padding:0}
  .wrap{max-width:620px;margin:32px auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.08)}
  .hdr{background:#7b2152;padding:28px 36px;text-align:center}
  .hdr h1{color:#f5e6d0;font-size:22px;margin:0;letter-spacing:.08em}
  .hdr p{color:#d4a0b8;font-size:13px;margin:6px 0 0;letter-spacing:.1em;text-transform:uppercase}
  .body{padding:36px 40px;color:#333;font-size:15px;line-height:1.75}
  .body p{margin:0 0 16px}
  .body ul{margin:0 0 16px 20px}
  .body ul li{margin-bottom:8px}
  .links-table{width:100%;border-collapse:collapse;margin:0 0 20px}
  .links-table th{background:#1a1a2e;color:#c8a96e;padding:10px 14px;text-align:left;font-size:13px;letter-spacing:.06em;text-transform:uppercase}
  .links-table td{padding:10px 14px;border-bottom:1px solid #f0e6f4;font-size:14px}
  .links-table tr:last-child td{border-bottom:none}
  .links-table tr:nth-child(even) td{background:#fdf6fb}
  .links-table td a{color:#7b2152;font-weight:600;text-decoration:none}
  .cta{text-align:center;margin:28px 0}
  .cta a{background:#c8a96e;color:#fff;text-decoration:none;padding:14px 36px;border-radius:6px;font-weight:700;font-size:14px;letter-spacing:.08em;text-transform:uppercase;display:inline-block}
  .ftr{background:#1a1a2e;color:#aab4c8;text-align:center;padding:18px 20px;font-size:12px}
  .ftr a{color:#c8a96e;text-decoration:none}
  strong{color:#7b2152}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px"/>
    <h1>UCOSA-North America</h1>
    <p>Alumni United Across North America</p>
  </div>
  <div class="body">
    <p>Dear <strong>${fullName}</strong>,</p>
    <p>We hope this message finds you well.</p>
    <p>We are reaching out because you are part of something that does not fade with time — the bond of fellowship forged at Ugbeka College. That connection is exactly why <strong>UCOSA-North America</strong> exists: <em>Alumni United Across North America</em>, staying connected, supporting our alma mater, and uplifting one another.</p>
    <p>We have come a long way from our humble beginnings. We have grown, we have organized, and we are proud to say — <strong>we now have a home online.</strong> We warmly invite you to visit us at:</p>
    <p style="text-align:center;font-size:18px;font-weight:700;color:#7b2152"><a href="https://ucosa-na.org" style="color:#7b2152">www.ucosa-na.org</a></p>
    <p>We are a not-for-profit, non-political, charitable, and voluntary association of Ugbeka College alumni residing in the United States and Canada. We meet via <strong>Zoom video conferencing on the last Sunday of every month</strong>, so no matter where you are in North America, you can join from any internet-connected device.</p>
    <p>Our goals remain the same as the values we all share:</p>
    <ul>
      <li>To foster <strong>unity, brotherhood, and fellowship</strong> among fellow Ugbeka College alumni in North America</li>
      <li>To <strong>support the development and improvement</strong> of Ugbeka College and the Ugbeka community</li>
      <li>To organize cultural, social, and fundraising activities that benefit our association and the broader Ugbeka community</li>
    </ul>
    <p>We recognize our shared heritage and our collective responsibility to the institution that shaped us all. That responsibility does not expire — and neither does your place among us.</p>
    <p><strong>We would love to welcome you back.</strong> Visit <a href="https://ucosa-na.org">ucosa-na.org</a> to reconnect. While at the website, check out our member benefits and the development work we have done so far at our alma mater:</p>
    <table class="links-table">
      <thead><tr><th>Page</th><th>Direct Link</th></tr></thead>
      <tbody>
        <tr><td>Member Benefits</td><td><a href="https://ucosa-na.org/#member-benefit">ucosa-na.org/#member-benefit</a></td></tr>
        <tr><td>Computer Lab</td><td><a href="https://ucosa-na.org/#computer-lab">ucosa-na.org/#computer-lab</a></td></tr>
        <tr><td>Development Projects</td><td><a href="https://ucosa-na.org/#dev-projects">ucosa-na.org/#dev-projects</a></td></tr>
        <tr><td><strong>Request To Join</strong></td><td><a href="https://ucosa-na.org/#join"><strong>ucosa-na.org/#join</strong></a></td></tr>
      </tbody>
    </table>
    <p>Please click <strong>"Request To Join"</strong> so we can reconnect and get you back where you belong.</p>
    <div class="cta"><a href="https://ucosa-na.org/#join">Request To Join</a></div>
    <p>With warmth and fellowship,</p>
    <p><strong>The Executive Committee</strong><br/>UCOSA-North America<br/><a href="https://ucosa-na.org">www.ucosa-na.org</a></p>
  </div>
  <div class="ftr">&copy; 2026 UCOSA-North America. All rights reserved. &mdash; <a href="https://ucosa-na.org">ucosa-na.org</a></div>
</div>
</body></html>`.trim();
}

async function sendFormerMemberInvites() {
  try {
    const { rows } = await pool.query(`
      SELECT id, full_name, email, phone
      FROM former_members
      WHERE status = 'pending'
        AND (email IS NOT NULL OR phone IS NOT NULL)
        AND (last_invite_sent_at IS NULL OR last_invite_sent_at < NOW() - INTERVAL '60 days')
      ORDER BY full_name ASC
    `);

    if (!rows.length) {
      log.info('sendFormerMemberInvites: no pending former members due for invite');
      return;
    }

    log.info(`sendFormerMemberInvites: sending invites to ${rows.length} former member(s)`);

    for (const row of rows) {
      if (row.email) {
        try {
          await sendEmail({
            to: `"${row.full_name}" <${row.email}>`,
            subject: 'We Miss You — Come Back Home to UCOSA-NA',
            html: buildFormerMemberInviteHtml(row.full_name),
          });
        } catch (err) {
          log.error(`sendFormerMemberInvites: email failed for ${row.full_name}: ${err.message}`);
        }
        await sleep(250);
      }

      if (row.phone) {
        const sms =
          `UCOSA-NA: Dear ${row.full_name}, we miss you!\n\n` +
          `We invite you to reconnect with your fellow Ugbeka College alumni in North America.\n\n` +
          `Visit us at https://ucosa-na.org and click "Request To Join" to come back home.\n\n` +
          `— UCOSA-North America`;
        try {
          await sendSMS(row.phone, sms);
        } catch (err) {
          log.error(`sendFormerMemberInvites: SMS failed for ${row.full_name}: ${err.message}`);
        }
        await sleep(300);
      }

      await pool.query('UPDATE former_members SET last_invite_sent_at = NOW() WHERE id = $1', [row.id]);
    }

    log.info(`sendFormerMemberInvites: done — ${rows.length} former member(s) contacted`);
  } catch (err) {
    log.error(`sendFormerMemberInvites failed: ${err.message}`);
  }
}

// ── Computer Teacher Salary Pledge Reminder (Last Sunday of Month, 9 AM ET) ───

async function sendCtsPledgeReminders() {
  const etStr  = new Date().toLocaleString('en-US', { timeZone: 'America/New_York' });
  const etNow  = new Date(etStr);
  const year   = etNow.getFullYear();
  const month  = etNow.getMonth();
  const today  = new Date(year, month, etNow.getDate());
  const lastSun = getLastSundayOfMonth(year, month);
  const meeting = new Date(lastSun.getFullYear(), lastSun.getMonth(), lastSun.getDate());

  if (today.getTime() !== meeting.getTime()) {
    log.info('CTS pledge reminder: not last Sunday of the month — skipping');
    return;
  }

  log.info('CTS pledge reminder: last Sunday detected — fetching unredeemed pledges');

  let records;
  try {
    const { rows } = await pool.query(`
      SELECT cts.id, cts.member_name, cts.amt_pledged, cts.amt_redeemed, cts.status,
             u.email, COALESCE(p.phone, u.phone) AS phone
      FROM computer_teacher_salary cts
      JOIN users u ON u.id = cts.user_id
      LEFT JOIN member_profiles p ON p.user_id = cts.user_id
      WHERE cts.status IN ('pending', 'partial')
        AND cts.user_id IS NOT NULL
      ORDER BY cts.member_name ASC
    `);
    records = rows;
  } catch (err) {
    log.error(`CTS pledge reminder: DB query failed — ${err.message}`);
    return;
  }

  if (!records.length) {
    log.info('CTS pledge reminder: no unredeemed pledges found — done');
    return;
  }

  log.info(`CTS pledge reminder: sending to ${records.length} member(s)`);

  let emailCount = 0, smsCount = 0;
  for (const r of records) {
    const pledged     = parseFloat(r.amt_pledged);
    const redeemed    = parseFloat(r.amt_redeemed || 0);
    const balance     = pledged - redeemed;
    const statusLabel = r.status === 'partial' ? 'Partial' : 'Pending';

    if (r.email) {
      try {
        await sendEmail({
          to: r.email,
          subject: 'Friendly Reminder — Redeem Your Computer Teacher Salary Pledge — UCOSA-NA',
          html: `
            <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#333;">
              <div style="background:#1a1a2e;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;">
                <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:80px;height:80px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 10px">
                <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
                <h1 style="color:#fff;margin:8px 0 0;font-size:22px;">Pledge Redemption Reminder</h1>
              </div>
              <div style="background:#f9f9f9;padding:28px 32px;border-radius:0 0 10px 10px;">
                <p>Dear <strong>${r.member_name}</strong>,</p>
                <p>This is a friendly reminder that you have an outstanding pledge toward the <strong>Computer Teacher Salary</strong>.</p>
                <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
                  <thead><tr style="background:#1a1a2e;color:#fff;">
                    <th style="padding:10px 12px;text-align:left;">Detail</th>
                    <th style="padding:10px 12px;text-align:left;">Amount</th>
                  </tr></thead>
                  <tbody>
                    <tr><td style="padding:8px 12px;">Amount Pledged</td><td style="padding:8px 12px;">&#8358;${pledged.toLocaleString('en-NG', { minimumFractionDigits: 2 })}</td></tr>
                    <tr style="background:#f4f4f4;"><td style="padding:8px 12px;">Amount Redeemed</td><td style="padding:8px 12px;">&#8358;${redeemed.toLocaleString('en-NG', { minimumFractionDigits: 2 })}</td></tr>
                    <tr><td style="padding:8px 12px;font-weight:700;">Balance Due</td><td style="padding:8px 12px;font-weight:700;color:#b71c1c;">&#8358;${balance.toLocaleString('en-NG', { minimumFractionDigits: 2 })}</td></tr>
                    <tr style="background:#f4f4f4;"><td style="padding:8px 12px;">Status</td><td style="padding:8px 12px;">${statusLabel}</td></tr>
                  </tbody>
                </table>
                <p>Kindly redeem your pledge using any of the payment options below:</p>
                <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
                  <thead><tr style="background:#1a1a2e;color:#fff;">
                    <th style="padding:10px 12px;text-align:left;">Payment Method</th>
                    <th style="padding:10px 12px;text-align:left;">Details</th>
                  </tr></thead>
                  <tbody>
                    <tr><td style="padding:8px 12px;">Naira Transfer</td><td style="padding:8px 12px;">Osatohanmwen Gloria Obakpolor Sule<br>Sterling Bank &mdash; Account: 0027219075</td></tr>
                    <tr style="background:#f4f4f4;"><td style="padding:8px 12px;">Dollar (Zelle)</td><td style="padding:8px 12px;">osatosule@yahoo.com</td></tr>
                  </tbody>
                </table>
                <p>Once payment is made, please notify the Welfare Officer so your record can be updated.</p>
                <p>Thank you for your continued generosity and support of our teachers.</p>
                <p style="color:#888;font-size:13px;">— UCOSA-North America</p>
              </div>
            </div>`,
        });
        emailCount++;
      } catch (err) {
        log.error(`CTS pledge reminder email failed for ${r.email}: ${err.message}`);
      }
      await sleep(250);
    }

    if (r.phone) {
      try {
        await sendSMS(r.phone,
          `Dear ${r.member_name}, this is a reminder that your Computer Teacher Salary pledge of NGN ${pledged.toLocaleString('en-NG')} has a balance of NGN ${balance.toLocaleString('en-NG')} (${statusLabel}). To redeem: Naira transfer to Osatohanmwen Gloria Obakpolor Sule, Sterling Bank, Acct: 0027219075. Dollar (Zelle): osatosule@yahoo.com — UCOSA-NA`
        );
        smsCount++;
      } catch (err) {
        log.error(`CTS pledge reminder SMS failed for ${r.phone}: ${err.message}`);
      }
      await sleep(300);
    }
  }

  log.info(`CTS pledge reminder: dispatched — ${emailCount} email(s), ${smsCount} SMS(es)`);
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

// 1st of every month at 9:00 AM — birthday emails
cron.schedule('0 9 1 * *', sendBirthdayEmails, { timezone: 'America/New_York' });

// January 1st at 9:00 AM — endowment enrollment open (2027+)
cron.schedule('0 9 1 1 *', sendEnrollmentOpenNotifications, { timezone: 'America/New_York' });

// June 14th at 9:00 AM — endowment enrollment open (2026 special window)
cron.schedule('0 9 14 6 *', sendEnrollmentOpenNotifications, { timezone: 'America/New_York' });

// Daily at 9:00 AM ET — check for general meeting 7-day invite / 3-day / 1-day reminders
cron.schedule('0 9 * * *', checkGeneralMeetingDayReminders, { timezone: 'America/New_York' });

// Every Sunday at 4:00 PM ET — 1-hour notice before 5:00 PM general meeting
cron.schedule('0 16 * * 0', checkGeneralMeetingHourReminder, { timezone: 'America/New_York' });

// Daily at 10:00 AM ET — send "We Miss You" invites to pending former members (60-day interval)
cron.schedule('0 10 * * *', sendFormerMemberInvites, { timezone: 'America/New_York' });

// Every Sunday at 9:00 AM ET — CTS pledge reminder (only fires on the last Sunday of the month)
cron.schedule('0 9 * * 0', sendCtsPledgeReminders, { timezone: 'America/New_York' });

log.info('Scheduler: jobs registered (Jan 1 dues populate + enrollment open, Jun 14 2026 enrollment open, May 2 & June 1 dues reminders, daily 8AM inactivity check, daily 9AM general meeting day reminders, Sunday 4PM general meeting hour notice, 1st-of-month 9AM birthday emails, daily 10AM former-member invite check, Sunday 9AM CTS pledge reminder)');

module.exports = {
  populateAnnualDues, sendAdvanceReminders, sendDueDateReminders,
  sendInactivityReminders, sendBirthdayEmails, sendEnrollmentOpenNotifications,
  checkGeneralMeetingDayReminders, checkGeneralMeetingHourReminder,
  sendFormerMemberInvites, sendCtsPledgeReminders,
  // Exported for test endpoints in admin.js
  duesReminderHtml, zoomMeetingBlock, generalMeetingHtml, fmtMeetingDate, getLastSundayOfMonth, sendGeneralMeetingNotices,
};
