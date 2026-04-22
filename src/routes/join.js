const express = require('express');
const { sendEmail } = require('../mailer');

const router = express.Router();

// POST /api/join — membership interest form
router.post('/', async (req, res) => {
  const { name, email, phone, address } = req.body;

  if (!name || !email || !phone) {
    return res.status(400).json({ error: 'Full name, email, and phone number are required.' });
  }

  const logoHeader = `
    <div style="background:#7b2152;text-align:center;padding:28px 32px">
      <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:90px;height:90px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 12px">
      <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase">UCOSA North America</div>
    </div>`;

  try {
    // Notify the admin
    await sendEmail({
      to: 'ucosa.northamerica@gmail.com',
      replyTo: email,
      subject: `Membership Request: ${name}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          ${logoHeader}
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

    // Send confirmation to the requester
    sendEmail({
      to: email,
      replyTo: 'ucosa.northamerica@gmail.com',
      subject: 'Thank You for Your Interest in UCOSA-North America',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:580px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0">
          ${logoHeader}
          <div style="background:#fdf6ec;padding:36px 32px">
            <p style="font-size:17px;color:#333;margin-top:0">Dear <strong>${name}</strong>,</p>

            <p style="color:#333;line-height:1.7">
              Thank you for reaching out and expressing your interest in joining the
              <strong style="color:#7b2152">Ugbeka College Old Students' Association — North America (UCOSA-NA)</strong>.
              We are truly delighted to hear from you, and we warmly welcome you to connect with us.
            </p>

            <div style="background:white;border-left:4px solid #c8a96e;border-radius:0 8px 8px 0;padding:20px 24px;margin:24px 0">
              <h3 style="color:#7b2152;margin-top:0;font-size:16px">Who We Are</h3>
              <p style="color:#444;line-height:1.7;margin:0">
                UCOSA-North America is a <strong>not-for-profit, non-political, charitable, and voluntary association</strong>
                of former students of Ugbeka College Evboehighae residing in the United States and Canada.
                We are united by a shared pride in our alma mater and a deep commitment to giving back —
                to one another and to the school that shaped us.
              </p>
            </div>

            <div style="background:white;border-left:4px solid #c8a96e;border-radius:0 8px 8px 0;padding:20px 24px;margin:24px 0">
              <h3 style="color:#7b2152;margin-top:0;font-size:16px">What We Do</h3>
              <p style="color:#444;line-height:1.7;margin:0">
                Our association actively works to <strong>reconnect alumni across North America</strong>,
                support meaningful development projects at Ugbeka College, and foster a spirit of brotherhood
                and sisterhood among all members. From donating equipment and funding infrastructure improvements
                to hosting bimonthly virtual meetings, we stay engaged and invested in our school's growth
                and our community's well-being.
              </p>
            </div>

            <div style="background:white;border-left:4px solid #c8a96e;border-radius:0 8px 8px 0;padding:20px 24px;margin:24px 0">
              <h3 style="color:#7b2152;margin-top:0;font-size:16px">How We Connect</h3>
              <p style="color:#444;line-height:1.7;margin:0">
                Members meet via <strong>Zoom</strong> every two months — on the last Sunday of the meeting month
                at <strong>5:00 p.m. EST</strong>. Between meetings, we stay connected through WhatsApp and our
                shared email network. Annual membership dues are <strong>$100</strong>, which go directly toward
                supporting our alma mater and community initiatives.
              </p>
            </div>

            <p style="color:#333;line-height:1.7">
              A member of our team will be reaching out to you shortly to welcome you personally and guide you
              through the next steps. In the meantime, feel free to visit our website at
              <a href="https://ucosa-na.org" style="color:#7b2152;font-weight:600">ucosa-na.org</a>
              to learn more about us.
            </p>

            <p style="color:#333;line-height:1.7;margin-bottom:0">
              Once again, thank you for your interest. We look forward to having you as part of our
              growing family of Ugbeka College alumni in North America.
            </p>

            <p style="color:#333;margin-top:24px;margin-bottom:0">
              Warm regards,<br>
              <strong style="color:#7b2152">The UCOSA-North America Team</strong>
            </p>

            <p style="color:#aaa;font-size:0.8em;margin-top:28px;border-top:1px solid #e8d9c0;padding-top:16px">
              UCOSA-North America &mdash;
              <a href="mailto:ucosa.northamerica@gmail.com" style="color:#aaa">ucosa.northamerica@gmail.com</a> &mdash;
              <a href="https://ucosa-na.org" style="color:#aaa">ucosa-na.org</a>
            </p>
          </div>
        </div>
      `,
    }).catch(err => console.error('Join confirmation email error:', err.message));

    res.json({ message: 'Request sent successfully.' });
  } catch (err) {
    console.error('Join request email error:', err.message);
    res.status(500).json({ error: 'Failed to send request. Please try again later.' });
  }
});

module.exports = router;
