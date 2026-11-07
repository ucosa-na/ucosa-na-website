// UCOSA-NA WAEC Sponsorship Announcement Broadcast
// Sends email + SMS to all active members AND former members.
//
// Usage (run on the server when ready to send):
//   node src/broadcast-waec.js
//
// Dry-run (preview recipients, no messages sent):
//   node src/broadcast-waec.js --dry-run

require('dotenv').config();
const pool       = require('./db');
const { sendEmail } = require('./mailer');
const { sendSMS, normalizePhone } = require('./sms');

const SUBJECT = 'UCOSA-NA: Educational Support Initiative — 2027 WAEC Sponsorship';
const SITE_URL = 'https://ucosa-na.org/#dev-waec';
const DRY_RUN  = process.argv.includes('--dry-run');

function buildEmailHtml(fullName) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #fdf6ec; margin: 0; padding: 0; }
    .wrapper { max-width: 620px; margin: 32px auto; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 16px rgba(0,0,0,0.08); }
    .header { background: #7b2152; padding: 28px 36px; text-align: center; }
    .header img { width: 90px; height: 90px; border-radius: 50%; border: 3px solid #c8a96e; display: block; margin: 0 auto 12px; }
    .header h1 { color: #f5e6d0; font-size: 22px; margin: 0; letter-spacing: 0.08em; }
    .header p  { color: #d4a0b8; font-size: 13px; margin: 6px 0 0; letter-spacing: 0.1em; text-transform: uppercase; }
    .body { padding: 36px 40px; color: #333; font-size: 15px; line-height: 1.75; }
    .body p { margin: 0 0 16px; }
    .highlight { background: #fdf6ec; border-left: 4px solid #c8a96e; padding: 16px 20px; border-radius: 0 8px 8px 0; margin: 20px 0; }
    .cta { text-align: center; margin: 28px 0; }
    .cta a { background: #c8a96e; color: #fff; text-decoration: none; padding: 14px 36px; border-radius: 6px; font-weight: 700; font-size: 14px; letter-spacing: 0.08em; text-transform: uppercase; display: inline-block; }
    .footer { background: #1a1a2e; color: #aab4c8; text-align: center; padding: 18px 20px; font-size: 12px; }
    .footer a { color: #c8a96e; text-decoration: none; }
    strong { color: #7b2152; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo"/>
      <h1>UCOSA-North America</h1>
      <p>Alumni United Across North America</p>
    </div>
    <div class="body">
      <p>Dear <strong>${fullName}</strong>,</p>

      <p>We are excited to share a major milestone in UCOSA-NA's commitment to supporting education at <strong>Ugbeka College Evboehighae</strong>.</p>

      <div class="highlight">
        <p style="margin:0;font-size:16px;"><strong>UCOSA-NA is proud to sponsor 32 current SS3 students for the 2027 West African Examinations Council (WAEC) exams at Ugbeka College Evboehighae.</strong></p>
      </div>

      <p>This initiative — the <strong>Educational Support Initiative – 2027 WAEC Sponsorship</strong> — reflects our shared dedication to investing in the next generation of Ugbeka College graduates.</p>

      <p>You can view the full list of sponsored students and learn more about this initiative on our website under <strong>Development Projects</strong>:</p>

      <div class="cta">
        <a href="${SITE_URL}">View the WAEC Sponsorship Page</a>
      </div>

      <p>We are grateful for the continued support of every member that makes initiatives like this possible. Together, we are building a legacy.</p>

      <p>With warmth and fellowship,</p>
      <p>
        <strong>The Executive Committee</strong><br/>
        UCOSA-North America<br/>
        <a href="https://ucosa-na.org">www.ucosa-na.org</a>
      </p>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} UCOSA-North America. All rights reserved.<br/>
      <a href="https://ucosa-na.org">ucosa-na.org</a>
    </div>
  </div>
</body>
</html>`.trim();
}

function buildSMS(fullName) {
  return `Dear ${fullName}, UCOSA-NA is proud to sponsor 32 current SS3 students for the 2027 WAEC exams at Ugbeka College Evboehighae. View the full list at: ${SITE_URL} — UCOSA-NA`;
}

async function main() {
  try {
    // Active members
    const { rows: activeMembers } = await pool.query(
      `SELECT u.full_name, u.email, COALESCE(p.phone, u.phone) AS phone
       FROM users u
       LEFT JOIN member_profiles p ON p.user_id = u.id
       WHERE u.is_active = TRUE AND u.id != 1
       ORDER BY u.full_name ASC`
    );

    // Former members
    const { rows: formerMembers } = await pool.query(
      `SELECT full_name, email, phone FROM former_members ORDER BY full_name ASC`
    );

    const recipients = [
      ...activeMembers.map(m => ({ ...m, type: 'active' })),
      ...formerMembers.map(m => ({ ...m, type: 'former' })),
    ];

    console.log(`\n${ DRY_RUN ? '[DRY RUN] ' : '' }Broadcasting WAEC announcement to ${recipients.length} recipient(s):`);
    console.log(`  Active members: ${activeMembers.length}`);
    console.log(`  Former members: ${formerMembers.length}\n`);

    if (DRY_RUN) {
      recipients.forEach(r => console.log(`  [${r.type.toUpperCase()}] ${r.full_name} | email: ${r.email || 'none'} | phone: ${r.phone || 'none'}`));
      console.log('\n[DRY RUN] No messages were sent.\n');
      await pool.end();
      return;
    }

    let emailSent = 0, emailFailed = 0, smsSent = 0, smsFailed = 0;

    for (const r of recipients) {
      if (r.email) {
        try {
          await sendEmail({
            to: `"${r.full_name}" <${r.email}>`,
            subject: SUBJECT,
            html: buildEmailHtml(r.full_name),
          });
          console.log(`  [EMAIL OK]  ${r.full_name} <${r.email}>`);
          emailSent++;
        } catch (err) {
          console.error(`  [EMAIL FAIL] ${r.full_name} <${r.email}> — ${err.message}`);
          emailFailed++;
        }
      }
      const phone = normalizePhone(r.phone);
      if (phone) {
        try {
          await sendSMS(phone, buildSMS(r.full_name));
          console.log(`  [SMS OK]    ${r.full_name} ${phone}`);
          smsSent++;
        } catch (err) {
          console.error(`  [SMS FAIL]  ${r.full_name} ${phone} — ${err.message}`);
          smsFailed++;
        }
      }
    }

    console.log(`\nDone. Email sent: ${emailSent}  Email failed: ${emailFailed}  SMS sent: ${smsSent}  SMS failed: ${smsFailed}\n`);
    await pool.end();
  } catch (err) {
    console.error('Fatal error:', err.message);
    process.exit(1);
  }
}

main();
