const express = require('express');
const { sendEmail } = require('../mailer');

const router = express.Router();

// POST /api/join — membership interest form
router.post('/', async (req, res) => {
  const { name, email, phone, address } = req.body;

  if (!name || !email || !phone) {
    return res.status(400).json({ error: 'Full name, email, and phone number are required.' });
  }

  try {
    await sendEmail({
      to: 'ucosa.northamerica@gmail.com',
      replyTo: email,
      subject: `Membership Request: ${name}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          <div style="background:#7b2152;text-align:center;padding:28px 32px">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
          </div>
          <div style="background:#fdf6ec;padding:32px">
            <h2 style="color:#7b2152;margin-top:0">New Membership Request</h2>
            <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
              <tr><td style="padding:8px 0;font-weight:700;color:#555;width:120px">Full Name:</td><td style="padding:8px 0">${name}</td></tr>
              <tr style="background:#f5ede0"><td style="padding:8px 6px;font-weight:700;color:#555">Email:</td><td style="padding:8px 6px"><a href="mailto:${email}">${email}</a></td></tr>
              <tr><td style="padding:8px 0;font-weight:700;color:#555">Phone:</td><td style="padding:8px 0">${phone}</td></tr>
              <tr style="background:#f5ede0"><td style="padding:8px 6px;font-weight:700;color:#555">Address:</td><td style="padding:8px 6px">${address || '<em style="color:#999">Not provided</em>'}</td></tr>
            </table>
            <p style="color:#888;font-size:0.85em;margin:0">Submitted via ucosa-na.org membership request form</p>
          </div>
        </div>
      `,
    });

    res.json({ message: 'Request sent successfully.' });
  } catch (err) {
    console.error('Join request email error:', err.message);
    res.status(500).json({ error: 'Failed to send request. Please try again later.' });
  }
});

module.exports = router;
