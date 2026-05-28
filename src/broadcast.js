// UCOSA-NA Broadcast Mailer
// Usage:
//   node src/broadcast.js "Samson Imaria:sonnie_avens@gmail.com, John Doe:john@example.com"
//
// Each entry is "Full Name:email" separated by commas.

require('dotenv').config();
const { sendEmail } = require('./mailer');

const FROM = `"UCOSA-NA" <${process.env.EMAIL_USER}>`;
const SUBJECT = 'We Miss You — Come Back Home to UCOSA-NA';

function buildHtml(fullName) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #fdf6ec; margin: 0; padding: 0; }
    .wrapper { max-width: 620px; margin: 32px auto; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 16px rgba(0,0,0,0.08); }
    .header { background: #7b2152; padding: 28px 36px; text-align: center; }
    .header h1 { color: #f5e6d0; font-size: 22px; margin: 0; letter-spacing: 0.08em; }
    .header p  { color: #d4a0b8; font-size: 13px; margin: 6px 0 0; letter-spacing: 0.1em; text-transform: uppercase; }
    .body { padding: 36px 40px; color: #333; font-size: 15px; line-height: 1.75; }
    .body p { margin: 0 0 16px; }
    .body ul { margin: 0 0 16px 20px; }
    .body ul li { margin-bottom: 8px; }
    .cta { text-align: center; margin: 28px 0; }
    .cta a {
      background: #c8a96e; color: #fff; text-decoration: none;
      padding: 14px 36px; border-radius: 6px; font-weight: 700;
      font-size: 14px; letter-spacing: 0.08em; text-transform: uppercase;
      display: inline-block;
    }
    .footer { background: #1a1a2e; color: #aab4c8; text-align: center; padding: 18px 20px; font-size: 12px; }
    .footer a { color: #c8a96e; text-decoration: none; }
    strong { color: #7b2152; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px;"/>
      <h1>UCOSA-North America</h1>
      <p>Alumni United Across North America</p>
    </div>
    <div class="body">
      <p>Dear <strong>${fullName}</strong>,</p>

      <p>We hope this message finds you well.</p>

      <p>We are reaching out because you are part of something that does not fade with time — the bond of fellowship forged at Ugbeka College. That connection is exactly why <strong>UCOSA-North America</strong> exists: <em>Alumni United Across North America</em>, staying connected, supporting our alma mater, and uplifting one another.</p>

      <p>We have come a long way from our humble beginnings. We have grown, we have organized, and we are proud to say — <strong>we now have a home online.</strong> We warmly invite you to visit us at:</p>

      <p style="text-align:center;font-size:18px;font-weight:700;color:#7b2152;">
        <a href="https://ucosa-na.org" style="color:#7b2152;">www.ucosa-na.org</a>
      </p>

      <p>We are a not-for-profit, non-political, charitable, and voluntary association of Ugbeka College alumni residing in the United States and Canada. We meet via <strong>Zoom video conferencing on the last Sunday of every month</strong>, so no matter where you are in North America, you can join from any internet-connected device.</p>

      <p>Our goals remain the same as the values we all share:</p>
      <ul>
        <li>To foster <strong>unity, brotherhood, and fellowship</strong> among fellow Ugbeka College alumni in North America</li>
        <li>To <strong>support the development and improvement</strong> of Ugbeka College and the Ugbeka community</li>
        <li>To organize cultural, social, and fundraising activities that benefit our association and the broader Ugbeka community</li>
      </ul>

      <p>We recognize our shared heritage and our collective responsibility to the institution that shaped us all. That responsibility does not expire — and neither does your place among us.</p>

      <p><strong>We would love to welcome you back.</strong> Visit <a href="https://ucosa-na.org">ucosa-na.org</a> to reconnect. While at the website, click on <strong>"Request To Join"</strong> so we can reconnect and get you back where you belong.</p>

      <div class="cta">
        <a href="https://ucosa-na.org">Visit ucosa-na.org</a>
      </div>

      <p>With warmth and fellowship,</p>
      <p>
        <strong>The Executive Committee</strong><br/>
        UCOSA-North America<br/>
        <a href="https://ucosa-na.org">www.ucosa-na.org</a>
      </p>
    </div>
    <div class="footer">
      &copy; 2026 UCOSA-North America. All rights reserved.<br/>
      <a href="https://ucosa-na.org">ucosa-na.org</a>
    </div>
  </div>
</body>
</html>
  `.trim();
}

async function main() {
  const input = process.argv[2];
  if (!input) {
    console.error('Usage: node src/broadcast.js "Full Name:email@example.com, Name Two:email2@example.com"');
    process.exit(1);
  }

  const entries = input.split(',').map(e => e.trim()).filter(Boolean);
  if (!entries.length) {
    console.error('No valid entries found.');
    process.exit(1);
  }

  console.log(`\nSending broadcast to ${entries.length} recipient(s)...\n`);

  let sent = 0;
  let failed = 0;

  for (const entry of entries) {
    const colonIdx = entry.lastIndexOf(':');
    if (colonIdx === -1) {
      console.warn(`  [SKIP] Invalid format (missing colon): "${entry}"`);
      failed++;
      continue;
    }

    const fullName = entry.slice(0, colonIdx).trim();
    const email    = entry.slice(colonIdx + 1).trim();

    if (!fullName || !email) {
      console.warn(`  [SKIP] Missing name or email in: "${entry}"`);
      failed++;
      continue;
    }

    try {
      await sendEmail({
        from:    FROM,
        to:      `"${fullName}" <${email}>`,
        subject: SUBJECT,
        html:    buildHtml(fullName),
      });
      console.log(`  [OK]   ${fullName} <${email}>`);
      sent++;
    } catch (err) {
      console.error(`  [FAIL] ${fullName} <${email}> — ${err.message}`);
      failed++;
    }
  }

  console.log(`\nDone. Sent: ${sent}  Failed/Skipped: ${failed}\n`);
}

main();
