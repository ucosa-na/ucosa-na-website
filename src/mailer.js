// Sends email via SendGrid HTTP API (port 443) — works on DigitalOcean
// which blocks all outbound SMTP (25, 465, 587).

const pool = require('./db');

async function sendEmail({ from, to, subject, html, replyTo }) {
  const apiKey = process.env.SENDGRID_API_KEY;
  const sender = from || `"UCOSA-NA" <${process.env.EMAIL_USER}>`;

  // Parse "Name <email>" into SendGrid format
  const parseAddr = str => {
    const m = str.match(/^"?([^"<]*)"?\s*<([^>]+)>$/);
    return m ? { name: m[1].trim(), email: m[2].trim() } : { email: str.trim() };
  };

  const body = {
    personalizations: [{ to: [parseAddr(to)] }],
    from: parseAddr(sender),
    subject,
    content: [{ type: 'text/html', value: html }],
  };
  if (replyTo) body.reply_to = parseAddr(replyTo);

  const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    const errMsg = `SendGrid ${res.status}: ${text}`;
    // Store failure in DB for admin review
    pool.query(
      'INSERT INTO email_failures (to_address, subject, error_msg) VALUES ($1, $2, $3)',
      [to, subject || null, errMsg]
    ).catch(() => {});
    throw new Error(errMsg);
  }
}

module.exports = { sendEmail };
