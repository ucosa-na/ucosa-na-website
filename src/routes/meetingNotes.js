const express  = require('express');
const crypto   = require('crypto');
const multer   = require('multer');
const mammoth  = require('mammoth');
const PDFDocument = require('pdfkit');
const pool     = require('../db');
const requireAuth = require('../middleware/requireAuth');
const requireRole = require('../middleware/requireRole');
const { sendEmail } = require('../mailer');
const { sendSMS }   = require('../sms');
const log = require('../logger');

const router    = express.Router();
const upload    = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const secOrAdmin = requireRole('admin', 'security-role');

async function logAudit(performedById, performedByName, action, entityType, entityId, entityName, details) {
  try {
    await pool.query(
      `INSERT INTO audit_log (action, entity_type, entity_id, entity_name, performed_by, performed_by_name, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [action, entityType, entityId || null, entityName || null,
       performedById || null, performedByName || null,
       details ? JSON.stringify(details) : null]
    );
  } catch (_) {}
}

// In-memory short-lived view tokens: token -> { noteId, expires }
const viewTokens = new Map();

/** Convert a .docx buffer to a PDF buffer using mammoth + pdfkit */
async function docxToPdf(buffer, title) {
  const { value: rawText } = await mammoth.extractRawText({ buffer });

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 72, size: 'LETTER' });
    const chunks = [];
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Title
    if (title) {
      doc.fontSize(16).font('Helvetica-Bold').text(title, { align: 'center' });
      doc.moveDown(1);
    }

    doc.fontSize(11).font('Helvetica');

    const paragraphs = rawText.split(/\n{2,}/);
    for (const para of paragraphs) {
      const line = para.trim();
      if (!line) continue;
      // Simple heuristic: short all-caps or short lines are headings
      if (line.length < 80 && line === line.toUpperCase() && line.length > 3) {
        doc.font('Helvetica-Bold').text(line).font('Helvetica');
      } else {
        doc.text(line, { lineGap: 2 });
      }
      doc.moveDown(0.6);
    }

    doc.end();
  });
}

const PORTAL_URL = 'https://ucosa-na.org/members.html';

/** Fire-and-forget: email + SMS all active members about newly uploaded minutes. */
async function notifyAllMembers(noteId, title, meetingDate) {
  let members;
  try {
    const { rows } = await pool.query(
      `SELECT u.full_name, u.email, COALESCE(mp.phone, u.phone) AS phone
       FROM users u
       LEFT JOIN member_profiles mp ON mp.user_id = u.id
       WHERE u.is_active = TRUE AND u.email IS NOT NULL`
    );
    members = rows;
  } catch (err) {
    log.error('Meeting notes notify: failed to fetch members:', err.message);
    return;
  }

  // Format meeting date for display (YYYY-MM-DD → "Month DD, YYYY")
  const [y, m, d] = String(meetingDate).slice(0, 10).split('-');
  const displayDate = new Date(+y, +m - 1, +d).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  const subject = `Meeting Minutes Available: ${title}`;
  const smsBody = `UCOSA-NA: The minutes for "${title}" (${displayDate}) are now available. Log in at ${PORTAL_URL} to read them. Please review before the next meeting.`;

  let emailOk = 0, emailFail = 0, smsOk = 0, smsFail = 0;

  for (const member of members) {
    const firstName = (member.full_name || '').split(' ')[0] || 'Member';

    // ── Email ──
    const html = `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;">
        <div style="background:#1a1a2e;padding:18px 24px;border-radius:10px 10px 0 0;">
          <h2 style="color:#fff;margin:0;font-size:20px;">UCOSA-NA &mdash; Meeting Minutes Available</h2>
        </div>
        <div style="border:1px solid #dde3f0;border-top:none;border-radius:0 0 10px 10px;padding:24px;">
          <p style="font-size:16px;color:#333;">Dear ${firstName},</p>
          <p style="font-size:15px;color:#333;">
            The minutes for our meeting have been uploaded and are now ready for your review.
          </p>
          <table style="width:100%;border-collapse:collapse;margin:16px 0;">
            <tr>
              <td style="padding:8px 12px;background:#f4f6fb;font-weight:700;color:#1a1a2e;border-radius:6px 0 0 6px;width:40%;">Title</td>
              <td style="padding:8px 12px;background:#f4f6fb;color:#333;border-radius:0 6px 6px 0;">${title}</td>
            </tr>
            <tr>
              <td style="padding:8px 12px;font-weight:700;color:#1a1a2e;">Meeting Date</td>
              <td style="padding:8px 12px;color:#333;">${displayDate}</td>
            </tr>
          </table>
          <p style="font-size:15px;color:#333;">
            We encourage all members to read the minutes <strong>before our next meeting</strong> so we can make the most of our time together.
          </p>
          <div style="text-align:center;margin:24px 0;">
            <a href="${PORTAL_URL}" style="background:#1a1a2e;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-size:16px;font-weight:700;">
              View Meeting Minutes
            </a>
          </div>
          <p style="font-size:13px;color:#888;margin-top:24px;">
            Log in to the members portal and navigate to the <strong>Meeting Notes</strong> section to open the document.
          </p>
          <hr style="border:none;border-top:1px solid #eee;margin:20px 0;" />
          <p style="font-size:12px;color:#aaa;text-align:center;">UCOSA-North America &mdash; Members Portal</p>
        </div>
      </div>`;

    try {
      await sendEmail({
        to: member.email,
        subject,
        html,
      });
      emailOk++;
    } catch (err) {
      emailFail++;
      log.warn(`Meeting notes email failed for ${member.email}: ${err.message}`);
    }

    // ── SMS ──
    if (member.phone) {
      const ok = await sendSMS(member.phone, smsBody);
      ok ? smsOk++ : smsFail++;
    }
  }

  log.info(`Meeting notes notifications: email ${emailOk}ok/${emailFail}fail, SMS ${smsOk}ok/${smsFail}fail`);
}

// GET /api/meeting-notes — list all (auth required)
router.get('/', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, title, meeting_date, original_name, mime_type, created_at
       FROM meeting_notes ORDER BY meeting_date DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/meeting-notes/:id/view-token — issue a short-lived URL token (auth required)
router.post('/:id/view-token', requireAuth, (req, res) => {
  const token   = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 5 * 60 * 1000; // 5 minutes
  viewTokens.set(token, { noteId: req.params.id, expires });
  // Clean up expired tokens
  for (const [k, v] of viewTokens) {
    if (v.expires < Date.now()) viewTokens.delete(k);
  }
  res.json({ token });
});

// GET /api/meeting-notes/:id/file — serve file (Authorization header OR ?token=)
router.get('/:id/file', async (req, res, next) => {
  // Check query token first
  const qToken = req.query.token;
  if (qToken) {
    const entry = viewTokens.get(qToken);
    if (!entry || entry.expires < Date.now() || String(entry.noteId) !== String(req.params.id)) {
      viewTokens.delete(qToken);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    viewTokens.delete(qToken); // single-use
    return serveFile(req, res);
  }
  // Fall back to JWT auth
  requireAuth(req, res, () => serveFile(req, res));
});

async function serveFile(req, res) {
  try {
    const { rows } = await pool.query(
      'SELECT original_name, mime_type, file_data FROM meeting_notes WHERE id = $1',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const { original_name, mime_type, file_data } = rows[0];
    res.setHeader('Content-Type', mime_type);
    res.setHeader('Content-Disposition', `inline; filename="${original_name}"`);
    res.send(file_data);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
}

// POST /api/meeting-notes — upload (admin/security-role)
// Auto-converts .docx files to PDF before storing.
router.post('/', secOrAdmin, upload.single('file'), async (req, res) => {
  const { title, meeting_date } = req.body;
  if (!title || !meeting_date || !req.file) {
    return res.status(400).json({ error: 'Title, date, and file are required.' });
  }

  let fileBuffer   = req.file.buffer;
  let mimeType     = req.file.mimetype;
  let originalName = req.file.originalname;

  // Convert .docx → PDF
  const isDocx = mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    || originalName.toLowerCase().endsWith('.docx');

  if (isDocx) {
    try {
      fileBuffer   = await docxToPdf(fileBuffer, title);
      mimeType     = 'application/pdf';
      originalName = originalName.replace(/\.docx$/i, '.pdf');
    } catch (convErr) {
      console.error('docx→pdf conversion error:', convErr.message);
      return res.status(500).json({ error: 'Failed to convert document to PDF.' });
    }
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO meeting_notes (title, meeting_date, original_name, mime_type, file_data, uploaded_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [title, meeting_date, originalName, mimeType, fileBuffer, req.user.id]
    );
    await logAudit(req.user.id, req.user.email, 'MEETING_NOTE_UPLOADED', 'MEETING_NOTE', rows[0].id, title, { meeting_date, file: originalName });
    // Notify all members in the background — do not block the upload response
    notifyAllMembers(rows[0].id, title, meeting_date).catch(err => log.error('notifyAllMembers error:', err.message));
    res.status(201).json({ message: 'Meeting notes uploaded.', id: rows[0].id });
  } catch (err) {
    console.error('Upload meeting notes error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/meeting-notes/:id (admin/security-role)
router.delete('/:id', secOrAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT title, meeting_date FROM meeting_notes WHERE id = $1', [req.params.id]);
    await pool.query('DELETE FROM meeting_notes WHERE id = $1', [req.params.id]);
    if (rows.length) {
      await logAudit(req.user.id, req.user.email, 'MEETING_NOTE_DELETED', 'MEETING_NOTE', parseInt(req.params.id), rows[0].title, { meeting_date: rows[0].meeting_date });
    }
    res.json({ message: 'Deleted.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
