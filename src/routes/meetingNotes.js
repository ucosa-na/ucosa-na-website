const express = require('express');
const crypto  = require('crypto');
const multer  = require('multer');
const pool    = require('../db');
const requireAuth = require('../middleware/requireAuth');
const requireRole = require('../middleware/requireRole');

const router    = express.Router();
const upload    = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const secOrAdmin = requireRole('admin', 'security-role');

// In-memory short-lived view tokens: token -> { noteId, expires }
const viewTokens = new Map();

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
router.post('/', secOrAdmin, upload.single('file'), async (req, res) => {
  const { title, meeting_date } = req.body;
  if (!title || !meeting_date || !req.file) {
    return res.status(400).json({ error: 'Title, date, and file are required.' });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO meeting_notes (title, meeting_date, original_name, mime_type, file_data, uploaded_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [title, meeting_date, req.file.originalname, req.file.mimetype,
       req.file.buffer, req.user.id]
    );
    res.status(201).json({ message: 'Meeting notes uploaded.', id: rows[0].id });
  } catch (err) {
    console.error('Upload meeting notes error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/meeting-notes/:id (admin/security-role)
router.delete('/:id', secOrAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM meeting_notes WHERE id = $1', [req.params.id]);
    res.json({ message: 'Deleted.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
