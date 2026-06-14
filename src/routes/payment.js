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

const DUES_AMOUNT      = 10000; // $100 in cents
const ENDOW_ALLOWED    = [5000, 15000]; // $50 or $150

// ── Member payment: create PaymentIntent (supports combined dues + endowment) ─
router.post('/create-intent', requireAuth, async (req, res) => {
  try {
    const { payDues, endowmentAmount, levyAmount, devLevyAmount } = req.body;
    const payEndow   = ENDOW_ALLOWED.includes(endowmentAmount);
    const payLevy    = Number.isInteger(levyAmount) && levyAmount >= 100;
    const payDevLevy = Number.isInteger(devLevyAmount) && devLevyAmount >= 100;

    if (!payDues && !payEndow && !payLevy && !payDevLevy) {
      return res.status(400).json({ error: 'Select at least one payment option.' });
    }
    if (endowmentAmount && !payEndow) {
      return res.status(400).json({ error: 'Invalid endowment amount.' });
    }

    const total = (payDues ? DUES_AMOUNT : 0) + (payEndow ? endowmentAmount : 0) + (payLevy ? levyAmount : 0) + (payDevLevy ? devLevyAmount : 0);
    const parts = [];
    if (payDues)    parts.push('Annual Dues ($100)');
    if (payEndow)   parts.push(`Endowment Fund ($${endowmentAmount / 100})`);
    if (payLevy)    parts.push(`Levy ($${levyAmount / 100})`);
    if (payDevLevy) parts.push(`Development Fee ($${devLevyAmount / 100})`);
    const description = `UCOSA-NA — ${parts.join(' + ')} — ${req.user.email}`;

    const intent = await getStripe().paymentIntents.create({
      amount: total,
      currency: 'usd',
      description,
      receipt_email: req.user.email,
      metadata: {
        member_id:        String(req.user.id),
        member_email:     req.user.email,
        pay_dues:         String(payDues || false),
        endowment_amount: String(payEndow ? endowmentAmount : 0),
      },
    });
    res.json({ clientSecret: intent.client_secret, total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Member payment: confirm, record in DB, send receipt ──────────────────────
router.post('/member-confirm', requireAuth, async (req, res) => {
  try {
    const { paymentIntentId, payDues, duesYear, endowmentAmount, endowYear, levyAmount, levyYear, levyType, levyNote, devLevyAmount, devLevyYear } = req.body;
    if (!paymentIntentId) return res.status(400).json({ error: 'Missing paymentIntentId.' });

    const intent = await getStripe().paymentIntents.retrieve(paymentIntentId);
    if (intent.status !== 'succeeded') {
      return res.status(400).json({ error: 'Payment not completed.' });
    }

    const currentYear = new Date().getFullYear();
    const today       = new Date().toISOString().split('T')[0];
    const items       = [];

    if (payDues) {
      const yr = duesYear || currentYear;
      const upd = await db.query(
        `UPDATE annual_dues
         SET amount = $3, paid_date = $4, payment_method = 'stripe',
             status = 'paid', notes = 'Online payment via Stripe', updated_at = NOW()
         WHERE user_id = $1 AND year = $2`,
        [req.user.id, yr, 100, today]
      );
      if (upd.rowCount === 0) {
        await db.query(
          `INSERT INTO annual_dues (user_id, year, amount, paid_date, payment_method, status, notes)
           VALUES ($1, $2, $3, $4, 'stripe', 'paid', 'Online payment via Stripe')`,
          [req.user.id, yr, 100, today]
        );
      }
      items.push({ label: `Annual Dues (${yr})`, amount: '$100.00' });
    }

    if (ENDOW_ALLOWED.includes(endowmentAmount)) {
      const endAmt = (endowmentAmount / 100).toFixed(2);
      const yr     = endowYear || currentYear;
      const upd = await db.query(
        `UPDATE endowment_fund
         SET amount = $3, contribution_date = $4, payment_method = 'stripe',
             status = 'paid', notes = 'Online payment via Stripe', updated_at = NOW()
         WHERE user_id = $1 AND year = $2`,
        [req.user.id, yr, endAmt, today]
      );
      if (upd.rowCount === 0) {
        await db.query(
          `INSERT INTO endowment_fund (user_id, amount, contribution_date, year, status, payment_method, notes)
           VALUES ($1, $2, $3, $4, 'paid', 'stripe', 'Online payment via Stripe')`,
          [req.user.id, endAmt, today, yr]
        );
      }
      items.push({ label: `Endowment Fund (${yr})`, amount: `$${endAmt}` });
    }

    if (Number.isInteger(levyAmount) && levyAmount >= 100) {
      const levyAmt = (levyAmount / 100).toFixed(2);
      const yr      = levyYear || currentYear;
      const LEVY_TYPES = ['Special Levy', 'Voluntary Contribution', 'Member-Donation'];
      const type    = LEVY_TYPES.includes(levyType) ? levyType : 'Voluntary Contribution';
      const noteText = levyNote ? `${levyNote} — Online payment via Stripe` : 'Online payment via Stripe';
      await db.query(
        `INSERT INTO special_levies (user_id, type, year, amount, paid_date, notes, recorded_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [req.user.id, type, yr, levyAmt, today, noteText, req.user.id]
      );
      items.push({ label: `${type} (${yr})`, amount: `$${levyAmt}` });
    }

    if (Number.isInteger(devLevyAmount) && devLevyAmount >= 100) {
      const devAmt = (devLevyAmount / 100).toFixed(2);
      const yr     = devLevyYear || currentYear;
      await db.query(
        `INSERT INTO special_levies (user_id, type, year, amount, paid_date, notes, recorded_by)
         VALUES ($1, 'Development Levy', $2, $3, $4, 'Online payment via Stripe', $5)`,
        [req.user.id, yr, devAmt, today, req.user.id]
      );
      items.push({ label: `Development Fee (${yr})`, amount: `$${devAmt}` });
    }

    const total = (intent.amount / 100).toFixed(2);
    const rows  = items.map(i => `<tr><td style="padding:6px 12px;">${i.label}</td><td style="padding:6px 12px;font-weight:700;color:#1b5e20;">${i.amount}</td></tr>`).join('');

    await sendEmail({
      to: req.user.email,
      subject: 'Payment Receipt — UCOSA-NA',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#333;">
          <div style="background:#1a1a2e;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;">
            <h1 style="color:#fff;margin:0;font-size:22px;">Payment Received</h1>
          </div>
          <div style="background:#f9f9f9;padding:28px 32px;border-radius:0 0 10px 10px;">
            <p>Dear <strong>${req.user.fullName || req.user.email}</strong>,</p>
            <p>Thank you! Your payment has been successfully processed. Here is your receipt:</p>
            <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
              <thead><tr style="background:#1a1a2e;color:#fff;"><th style="padding:10px 12px;text-align:left;">Description</th><th style="padding:10px 12px;text-align:left;">Amount</th></tr></thead>
              <tbody>${rows}</tbody>
              <tfoot><tr style="border-top:2px solid #eee;"><td style="padding:10px 12px;font-weight:700;">Total Paid</td><td style="padding:10px 12px;font-weight:700;color:#1b5e20;">$${total}</td></tr></tfoot>
            </table>
            <p style="font-size:13px;color:#888;">Reference: ${paymentIntentId}</p>
            <p style="font-size:13px;color:#888;">Date: ${new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})}</p>
            <p style="margin-top:20px;">Thank you for your continued support of UCOSA-NA and Ugbeka College.</p>
            <p style="color:#888;font-size:13px;">— UCOSA-North America</p>
          </div>
        </div>`,
    }).catch(() => {});

    res.json({ ok: true, total });
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
