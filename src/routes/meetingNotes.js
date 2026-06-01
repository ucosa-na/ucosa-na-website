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

  // Format meeting date (YYYY-MM-DD → "Month DD, YYYY") without UTC shift
  const [y, mo, d] = String(meetingDate).slice(0, 10).split('-');
  const displayDate = new Date(+y, +mo - 1, +d).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  const subject = `Meeting Minutes Now Available — ${title}`;
  const smsBody = `UCOSA-NA: The minutes of the meeting held on ${displayDate} have been uploaded to the UCOSA-NA website. Log in at ${PORTAL_URL} to read them. Please review the minutes before our next meeting.`;

  let emailOk = 0, emailFail = 0, smsOk = 0, smsFail = 0;

  for (const member of members) {
    const name = member.full_name || 'Member';

    const html = `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#333;">
      <div style="background:#1a1a2e;padding:28px 32px;border-radius:10px 10px 0 0;text-align:center;">
        <h1 style="color:#fff;margin:0;font-size:20px;">Meeting Minutes Available</h1>
      </div>
      <div style="background:#f9f9f9;padding:28px 32px;border-radius:0 0 10px 10px;">
        <p>Dear <strong>${name}</strong>,</p>
        <p>The meeting minutes of the meeting held on <strong>${displayDate}</strong> have been uploaded to the UCOSA-NA website.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
          <tbody>
            <tr><td style="padding:10px 16px;font-weight:600;color:#555;width:140px;">Title</td><td style="padding:10px 16px;">${title}</td></tr>
            <tr style="background:#f4f4f4;"><td style="padding:10px 16px;font-weight:600;color:#555;">Meeting Date</td><td style="padding:10px 16px;">${displayDate}</td></tr>
            <tr><td style="padding:10px 16px;font-weight:600;color:#555;">Where</td><td style="padding:10px 16px;"><a href="${PORTAL_URL}" style="color:#1a1a2e;font-weight:700;">Members Portal &rarr; Meeting Notes</a></td></tr>
          </tbody>
        </table>
        <p>We encourage all members to read the minutes <strong>before our next meeting</strong> so we can make the most of our time together.</p>
        <p style="color:#888;font-size:13px;">— UCOSA-North America</p>
      </div>
    </div>`;

    try {
      await sendEmail({ to: member.email, subject, html });
      emailOk++;
    } catch (err) {
      emailFail++;
      log.warn(`Meeting notes email failed for ${member.email}: ${err.message}`);
    }

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
