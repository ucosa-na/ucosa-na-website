const express     = require('express');
const https       = require('https');
const Stripe      = require('stripe');
const requireAuth = require('../middleware/requireAuth');
const db          = require('../db');
const log         = require('../logger');
const { sendEmail } = require('../mailer');
const { sendSMS, normalizePhone } = require('../sms');

function verifyRecaptcha(token) {
  return new Promise((resolve, reject) => {
    const secret = process.env.RECAPTCHA_SECRET_KEY;
    const body   = `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}`;
    const req = https.request({
      hostname: 'www.google.com',
      path:     '/recaptcha/api/siteverify',
      method:   'POST',
      headers:  { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      let data = '';
      res.on('data', d => { data += d; });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve({ success: false }); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function donationReceiptHtml(name, amount, paymentIntentId) {
  return `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0;">
      <div style="background:#7b2152;text-align:center;padding:24px 32px;">
        <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:80px;height:80px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 10px;">
        <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase;">UCOSA North America</div>
      </div>
      <div style="background:#fdf6ec;padding:28px 32px;">
        <p>Dear <strong>${name}</strong>,</p>
        <p>Your generous donation of <strong>$${amount}</strong> to the Ugbeka College Old Students' Association of North America has been received.</p>
        <p>Your contribution goes directly toward supporting students at Ugbeka College — funding the computer laboratory, school supplies, and educational resources that open doors for the next generation.</p>
        <div style="background:#fff;border-left:4px solid #c8a96e;padding:14px 18px;border-radius:4px;margin:20px 0;">
          <strong>Donation Receipt</strong><br>
          Donor: ${name}<br>
          Amount: $${amount}<br>
          Reference: ${paymentIntentId}<br>
          Date: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
        </div>
        <p style="color:#888;font-size:13px;">On behalf of all our students and alumni, thank you for making a difference.</p>
        <p style="color:#888;font-size:13px;">— UCOSA-North America</p>
      </div>
    </div>`;
}

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

    // Server-side dev levy eligibility check
    if (payDevLevy) {
      const DEV_LEVY_POLICY_DATE = new Date('2026-06-13T00:00:00Z');
      const { rows: [user] } = await db.query('SELECT created_at FROM users WHERE id = $1', [req.user.id]);
      const joinedAt = new Date(user.created_at);
      const now = new Date();
      const isNewMember = joinedAt >= DEV_LEVY_POLICY_DATE;
      const monthsElapsed = (now.getFullYear() - joinedAt.getFullYear()) * 12 + (now.getMonth() - joinedAt.getMonth());
      const { rows: [levyRow] } = await db.query(
        `SELECT COALESCE(SUM(amount), 0) AS total_paid FROM special_levies WHERE user_id = $1 AND type = 'Development Levy'`,
        [req.user.id]
      );
      const totalPaid = parseFloat(levyRow.total_paid);
      if (!isNewMember) {
        return res.status(403).json({ error: 'Development levy is not required for existing members.' });
      }
      if (monthsElapsed >= 6) {
        return res.status(403).json({ error: 'Development levy enrollment period has closed (6 months from joining).' });
      }
      if (totalPaid >= 200) {
        return res.status(403).json({ error: 'Development levy already fully paid.' });
      }
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
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border-radius:12px;overflow:hidden;border:1px solid #e8d9c0;">
          <div style="background:#7b2152;text-align:center;padding:24px 32px;">
            <img src="https://ucosa-na.org/logo.jpg" alt="UCOSA-NA Logo" style="width:80px;height:80px;border-radius:50%;border:3px solid #c8a96e;display:block;margin:0 auto 10px;">
            <div style="color:#c8a96e;font-size:0.85em;letter-spacing:2px;text-transform:uppercase;">UCOSA North America</div>
          </div>
          <div style="background:#f9f9f9;padding:28px 32px;">
            <p>Dear <strong>${req.user.fullName || req.user.email}</strong>,</p>
            <p>Thank you! Your payment has been successfully processed. Here is your receipt:</p>
            <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
              <thead><tr style="background:#7b2152;color:#fff;"><th style="padding:10px 12px;text-align:left;">Description</th><th style="padding:10px 12px;text-align:left;">Amount</th></tr></thead>
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

    // Send SMS receipt if member has a phone number
    const { rows: [profile] } = await db.query(
      `SELECT COALESCE(p.phone, u.phone) AS phone, u.full_name
       FROM users u LEFT JOIN member_profiles p ON p.user_id = u.id WHERE u.id = $1`,
      [req.user.id]
    );
    if (profile && profile.phone) {
      const normalized = normalizePhone(profile.phone);
      if (normalized) {
        const memberName = profile.full_name || req.user.email;
        const itemSummary = items.map(i => `${i.label}: ${i.amount}`).join(', ');
        const smsBody = `UCOSA-NA Payment Receipt: Dear ${memberName}, your payment of $${total} has been received. ${itemSummary}. Ref: ${paymentIntentId} — UCOSA-NA`;
        sendSMS(normalized, smsBody).catch(() => {});
      }
    }

    res.json({ ok: true, total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Public donation: create PaymentIntent ────────────────────────────────────
router.post('/donate-intent', async (req, res) => {
  try {
    const { name, email, amount, recaptchaToken } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email are required.' });
    const amt = parseInt(amount, 10);
    if (!amt || amt < 100) return res.status(400).json({ error: 'Invalid donation amount.' });

    // reCAPTCHA v3 verification
    if (process.env.RECAPTCHA_SECRET_KEY) {
      if (!recaptchaToken) {
        return res.status(400).json({ error: 'Security verification required.' });
      }
      try {
        const check = await verifyRecaptcha(recaptchaToken);
        if (!check.success || (check.score !== undefined && check.score < 0.5)) {
          log.warn(`reCAPTCHA failed for donation — ${email} (score: ${check.score ?? 'n/a'})`);
          return res.status(400).json({ error: 'Security check failed. Please try again.' });
        }
      } catch (err) {
        log.error(`reCAPTCHA verification error: ${err.message}`);
        // Don't block legitimate donors on reCAPTCHA network errors
      }
    }

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
    sendEmail({
      to: email,
      subject: 'Thank You for Your Donation — UCOSA-NA',
      html: donationReceiptHtml(name, amount, paymentIntentId),
    }).catch(err => log.error(`donate-confirm: receipt email failed for ${email}: ${err.message}`));

    res.json({ ok: true, amount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Stripe webhook: record donation + send receipt server-side ────────────────
router.post('/webhook', async (req, res) => {
  const sig           = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (webhookSecret) {
      event = getStripe().webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      log.warn('Stripe webhook received but STRIPE_WEBHOOK_SECRET not set — skipping signature check');
      event = JSON.parse(req.body.toString());
    }
  } catch (err) {
    log.error(`Stripe webhook signature error: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'payment_intent.succeeded') {
    const intent = event.data.object;
    const desc   = intent.description || '';

    if (desc.startsWith('UCOSA-NA Donation')) {
      const name           = intent.metadata?.donor_name  || desc.replace('UCOSA-NA Donation — ', '').trim();
      const email          = intent.metadata?.donor_email || intent.receipt_email;
      const amount         = (intent.amount / 100).toFixed(2);
      const paymentIntentId = intent.id;

      // Record in DB (ON CONFLICT handles case where donate-confirm already recorded it)
      try {
        const { rowCount } = await db.query(
          `INSERT INTO donations (donor_name, donor_email, amount, stripe_payment_intent_id)
           VALUES ($1, $2, $3, $4) ON CONFLICT (stripe_payment_intent_id) DO NOTHING`,
          [name, email, amount, paymentIntentId]
        );
        if (rowCount > 0) {
          log.info(`Webhook: donation recorded — ${name} (${email}) $${amount} [${paymentIntentId}]`);
          // Only send email if this is a new record (not already handled by donate-confirm)
          if (email) {
            sendEmail({
              to: email,
              subject: 'Thank You for Your Donation — UCOSA-NA',
              html: donationReceiptHtml(name, amount, paymentIntentId),
            }).catch(err => log.error(`Webhook: receipt email failed for ${email}: ${err.message}`));
          }
        } else {
          log.info(`Webhook: donation already recorded via donate-confirm — skipping [${paymentIntentId}]`);
        }
      } catch (err) {
        log.error(`Webhook: DB insert failed for ${paymentIntentId}: ${err.message}`);
      }
    }
  }

  res.json({ received: true });
});

module.exports = router;
