const express     = require('express');
const Stripe      = require('stripe');
const requireAuth = require('../middleware/requireAuth');
const db          = require('../db');
const { sendEmail } = require('../mailer');

let _stripe;
function getStripe() {
  if (!_stripe) _stripe = Stripe(process.env.STRIPE_SECRET_KEY);
  return _stripe;
}

const router = express.Router();

// Allowed amounts in cents: $100 dues, $50 or $150 endowment
const ALLOWED = {
  dues:      [10000],
  endowment: [5000, 15000],
};

// ── Member payment (requires login) ─────────────────────────────────────────
router.post('/create-intent', requireAuth, async (req, res) => {
  try {
    const { type, amount } = req.body;
    if (!ALLOWED[type] || !ALLOWED[type].includes(amount)) {
      return res.status(400).json({ error: 'Invalid payment type or amount.' });
    }
    const labels = { dues: 'Annual Dues', endowment: 'Endowment Fund' };
    const intent = await getStripe().paymentIntents.create({
      amount,
      currency: 'usd',
      description: `UCOSA-NA ${labels[type]} — ${req.user.name || req.user.email}`,
      metadata: { member_email: req.user.email, member_name: req.user.name || '', payment_type: type },
    });
    res.json({ clientSecret: intent.client_secret });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Public donation: create PaymentIntent ────────────────────────────────────
router.post('/donate-intent', async (req, res) => {
  try {
    const { name, email, amount } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email are required.' });
    const amt = parseInt(amount, 10);
    if (!amt || amt < 100) return res.status(400).json({ error: 'Invalid donation amount.' });

    const intent = await getStripe().paymentIntents.create({
      amount: amt,
      currency: 'usd',
      description: `UCOSA-NA Donation — ${name}`,
      receipt_email: email,
      metadata: { donor_name: name, donor_email: email },
    });
    res.json({ clientSecret: intent.client_secret });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Public donation: confirm, record, send receipt ───────────────────────────
router.post('/donate-confirm', async (req, res) => {
  try {
    const { paymentIntentId, name, email, phone } = req.body;
    if (!paymentIntentId || !name || !email) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }

    // Verify with Stripe that payment succeeded
    const intent = await getStripe().paymentIntents.retrieve(paymentIntentId);
    if (intent.status !== 'succeeded') {
      return res.status(400).json({ error: 'Payment has not been completed.' });
    }

    const amount = (intent.amount / 100).toFixed(2);

    // Record in DB (ignore duplicate if already recorded)
    await db.query(
      `INSERT INTO donations (donor_name, donor_email, donor_phone, amount, stripe_payment_intent_id)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT (stripe_payment_intent_id) DO NOTHING`,
      [name, email, phone || null, amount, paymentIntentId]
    );

    // Send receipt email to donor
    await sendEmail({
      to: email,
      subject: 'Thank You for Your Donation — UCOSA-NA',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#333;">
          <div style="background:#2e7d32;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;">
            <h1 style="color:#fff;margin:0;font-size:22px;">Thank You, ${name}!</h1>
          </div>
          <div style="background:#fdf6ec;padding:28px 32px;border-radius:0 0 10px 10px;">
            <p>Your generous donation of <strong>$${amount}</strong> to the Ugbeka College Old Students' Association of North America has been received.</p>
            <p>Your contribution goes directly toward supporting students at Ugbeka College — funding the computer laboratory, school supplies, and educational resources that open doors for the next generation.</p>
            <div style="background:#f0f9f0;border-left:4px solid #2e7d32;padding:14px 18px;border-radius:4px;margin:20px 0;">
              <strong>Donation Receipt</strong><br>
              Donor: ${name}<br>
              Amount: $${amount}<br>
              Reference: ${paymentIntentId}<br>
              Date: ${new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' })}
            </div>
            <p style="color:#888;font-size:13px;">On behalf of all our students and alumni, thank you for making a difference.</p>
            <p style="color:#888;font-size:13px;">— UCOSA-North America</p>
          </div>
        </div>`,
    }).catch(() => {}); // Don't fail the request if email fails

    res.json({ ok: true, amount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
