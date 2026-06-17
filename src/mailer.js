// Sends email via Resend HTTP API (port 443) — works on DigitalOcean
// which blocks all outbound SMTP (25, 465, 587).

const pool = require('./db');

async function sendEmail({ from, to, subject, html, replyTo }) {
  const apiKey = process.env.RESEND_API_KEY;
  const sender = from || `UCOSA-NA <${process.env.EMAIL_USER}>`;

  const body = { from: sender, to: [to], subject, html };
  if (replyTo) body.reply_to = replyTo;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    const errMsg = `Resend ${res.status}: ${text}`;
    // Store failure in DB for admin review
    pool.query(
      'INSERT INTO email_failures (to_address, subject, error_msg) VALUES ($1, $2, $3)',
      [to, subject || null, errMsg]
    ).catch(() => {});
    throw new Error(errMsg);
  }
}

module.exports = { sendEmail };
