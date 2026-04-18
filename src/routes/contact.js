const express = require('express');
const nodemailer = require('nodemailer');

const router = express.Router();

// POST /api/contact — send contact form email to ucosa.northamerica@gmail.com
router.post('/', async (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Name, email, and message are required.' });
  }

  if (!process.env.SENDGRID_API_KEY || !process.env.EMAIL_USER) {
    return res.status(500).json({ error: 'Email service not configured on server.' });
  }

  try {
    const transport = nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 465,
      secure: true,
      auth: {
        user: 'apikey',
        pass: process.env.SENDGRID_API_KEY,
      },
    });

    await transport.sendMail({
      from: `"UCOSA-NA Website" <${process.env.EMAIL_USER}>`,
      to: 'ucosa.northamerica@gmail.com',
      replyTo: email,
      subject: `Contact Form: Message from ${name}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:32px;background:#fdf6ec;border-radius:12px;">
          <h2 style="color:#7b2152;">New Contact Form Submission</h2>
          <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
            <tr><td style="padding:8px 0;font-weight:700;color:#555;width:120px;">Full Name:</td><td style="padding:8px 0;">${name}</td></tr>
            <tr><td style="padding:8px 0;font-weight:700;color:#555;">Email:</td><td style="padding:8px 0;"><a href="mailto:${email}">${email}</a></td></tr>
          </table>
          <div style="background:white;border-radius:8px;padding:20px;border-left:4px solid #c8a96e;">
            <p style="font-weight:700;color:#555;margin:0 0 8px;">Message:</p>
            <p style="margin:0;white-space:pre-wrap;">${message}</p>
          </div>
          <p style="color:#888;font-size:0.85em;margin-top:24px;">Sent via ucosa-na.org contact form</p>
        </div>
      `,
    });

    res.json({ message: 'Message sent successfully.' });
  } catch (err) {
    console.error('Contact form email error:', err.message);
    res.status(500).json({ error: 'Failed to send message. Please try again later.' });
  }
});

module.exports = router;
