const express  = require('express');
const Stripe   = require('stripe');
const requireAuth = require('../middleware/requireAuth');

let _stripe;
function getStripe() {
  if (!_stripe) _stripe = Stripe(process.env.STRIPE_SECRET_KEY);
  return _stripe;
}

const router = express.Router();

// Allowed amounts in cents: $100 dues, $50 or $150 endowment
const ALLOWED = {
  dues:       [10000],
  endowment:  [5000, 15000],
};

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
      metadata: {
        member_email: req.user.email,
        member_name:  req.user.name || '',
        payment_type: type,
      },
    });

    res.json({ clientSecret: intent.client_secret });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
