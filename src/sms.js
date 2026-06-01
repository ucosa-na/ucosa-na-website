// Shared SMS utility — Twilio (primary) with Vonage fallback.
// Used by admin routes and meeting notes notifications.

const log = require('./logger') || console;

function normalizePhone(raw) {
  if (!raw) return null;
  const s = String(raw).trim();
  // Detect scientific notation (e.g. "2.35E+12") — Excel mangles long phone numbers this way.
  if (/^[+\-]?[\d.]+[eE][+\-]?\d+$/.test(s)) {
    log.warn(`Phone number stored as scientific notation ("${s}") — original digits lost; skipping SMS`);
    return null;
  }
  let digits = s.replace(/[^\d+]/g, '');
  if (!digits.startsWith('+')) digits = '+' + digits;
  if (digits.replace(/\D/g, '').length < 10) return null;
  return digits;
}

async function sendSMS(to, body) {
  const normalizedTo = normalizePhone(to);
  if (!normalizedTo) { log.warn(`SMS skipped — invalid phone number: "${to}"`); return false; }
  to = normalizedTo;

  const sid   = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  const from  = process.env.TWILIO_PHONE_NUMBER;
  if (sid && token && from) {
    try {
      await require('twilio')(sid, token).messages.create({ to, from, body });
      log.info(`SMS sent via Twilio to ${to}`);
      return true;
    } catch (err) {
      log.warn(`Twilio SMS failed for ${to}: ${err.message} — trying Vonage`);
    }
  }

  const vonageKey    = process.env.VONAGE_API_KEY;
  const vonageSecret = process.env.VONAGE_API_SECRET;
  const vonageFrom   = process.env.VONAGE_PHONE_NUMBER || 'UCOSA-NA';
  if (!vonageKey || !vonageSecret) { log.warn('SMS skipped: neither Twilio nor Vonage configured'); return false; }
  try {
    const { Vonage } = require('@vonage/server-sdk');
    const vonage = new Vonage({ apiKey: vonageKey, apiSecret: vonageSecret });
    const result = await vonage.sms.send({ to, from: vonageFrom, text: body });
    const msg = result?.messages?.[0];
    const status = msg?.status;
    if (status === '0') {
      log.info(`SMS sent via Vonage to ${to}`);
      return true;
    } else {
      log.warn(`Vonage SMS rejected for ${to}: status=${status} error="${msg?.['error-text']}"`);
      return false;
    }
  } catch (err) {
    log.warn(`Vonage SMS failed for ${to}: ${err.message}`);
    return false;
  }
}

module.exports = { normalizePhone, sendSMS };
