#!/usr/bin/env node
/**
 * Upload all files from public/Minute_Of_Meetings to Meeting Notes.
 * - .docx files are converted to PDF locally before upload.
 * - .pdf files are uploaded as-is.
 * - Duplicate .docx/.pdf pairs (same base name) → only PDF is uploaded.
 * - All existing meeting notes are deleted first (overwrite mode).
 *
 * Usage:
 *   UCOSA_PASSWORD=xxx node scripts/upload-meeting-notes.js
 */

const fs          = require('fs');
const path        = require('path');
const mammoth     = require('mammoth');
const PDFDocument = require('pdfkit');

const API      = process.env.UCOSA_API      || 'https://ucosa-na.org';
const EMAIL    = process.env.UCOSA_EMAIL    || 'ucosa.northamerica@gmail.com';
const PASSWORD = process.env.UCOSA_PASSWORD || '';

const MINUTES_DIR = path.join(__dirname, '..', 'public', 'Minute_Of_Meetings');

// Metadata: file base name (no extension) → { title, date }
const FILE_META = {
  'EXECUTIVE  APRIL 11':                    { title: 'Executive Meeting – April 11, 2021',          date: '2021-04-11' },
  'EXECUTIVE  JUNE 13':                     { title: 'Executive Meeting – June 13, 2021',           date: '2021-06-13' },
  'UCOSA  JUNE 27 2021':                    { title: 'UCOSA Meeting – June 27, 2021',               date: '2021-06-27' },
  'UCOSA NA NOV. 28':                       { title: 'UCOSA-NA Meeting – November 28, 2025',        date: '2025-11-28' },
  'UCOSA NAE  AUGUST 15':                   { title: 'UCOSA-NAE Meeting – August 15, 2021',         date: '2021-08-15' },
  'UCOSA NORTH AMERICA  NOVEMBER 14, 2021': { title: 'UCOSA North America – November 14, 2021',    date: '2021-11-14' },
  'UCOSA SEPTEMBER 26, 2021':               { title: 'UCOSA Meeting – September 26, 2021',          date: '2021-09-26' },
  'UCOSA SEPTEMBER 26, 2021 (1)':           { title: 'UCOSA Meeting – September 26, 2021 (Part 2)', date: '2021-09-26' },
  'UCOSA SEPTEMBER 26, 2021 (2)':           { title: 'UCOSA Meeting – September 26, 2021 (Part 3)', date: '2021-09-26' },
};

async function docxToPdf(buffer, title) {
  const { value: rawText } = await mammoth.extractRawText({ buffer });

  return new Promise((resolve, reject) => {
    const doc    = new PDFDocument({ margin: 72, size: 'LETTER' });
    const chunks = [];
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end',  () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    if (title) {
      doc.fontSize(16).font('Helvetica-Bold').text(title, { align: 'center' });
      doc.moveDown(1);
    }
    doc.fontSize(11).font('Helvetica');

    for (const para of rawText.split(/\n{2,}/)) {
      const line = para.trim();
      if (!line) continue;
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

async function login() {
  const r = await fetch(`${API}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  if (!r.ok) throw new Error(`Login failed (${r.status}): ${await r.text()}`);
  const { token } = await r.json();
  return token;
}

async function deleteAll(token) {
  const r     = await fetch(`${API}/api/meeting-notes`, { headers: { Authorization: `Bearer ${token}` } });
  const notes = await r.json();
  console.log(`Deleting ${notes.length} existing note(s)…`);
  for (const note of notes) {
    await fetch(`${API}/api/meeting-notes/${note.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    console.log(`  Deleted: [${note.id}] ${note.title}`);
  }
}

async function uploadPdf(token, pdfBuffer, filename, title, date) {
  const fd = new FormData();
  fd.append('title', title);
  fd.append('meeting_date', date);
  fd.append('file', new Blob([pdfBuffer], { type: 'application/pdf' }), filename);

  const r = await fetch(`${API}/api/meeting-notes`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: fd,
  });
  if (!r.ok) throw new Error(`Upload failed (${r.status}): ${await r.text()}`);
  const { id } = await r.json();
  console.log(`  ✓ Uploaded: "${title}" → id ${id}`);
}

async function main() {
  if (!PASSWORD) { console.error('Set UCOSA_PASSWORD env var.'); process.exit(1); }

  console.log(`API: ${API}`);
  const token = await login();
  console.log('Logged in.\n');

  await deleteAll(token);
  console.log('');

  // Collect files; prefer PDF over docx when both exist
  const allFiles = fs.readdirSync(MINUTES_DIR);
  const pdfBases = new Set(
    allFiles.filter(f => f.toLowerCase().endsWith('.pdf')).map(f => f.replace(/\.pdf$/i, ''))
  );

  const toUpload = [];
  for (const f of allFiles) {
    const ext  = path.extname(f).toLowerCase();
    const base = f.slice(0, -ext.length);
    if (ext === '.pdf') {
      toUpload.push({ base, ext, filepath: path.join(MINUTES_DIR, f) });
    } else if (ext === '.docx' && !pdfBases.has(base)) {
      toUpload.push({ base, ext, filepath: path.join(MINUTES_DIR, f) });
    }
  }

  // Sort by date for cleaner upload order
  toUpload.sort((a, b) => {
    const da = (FILE_META[a.base] || {}).date || '0000';
    const db = (FILE_META[b.base] || {}).date || '0000';
    return da.localeCompare(db);
  });

  console.log(`Files to upload: ${toUpload.length}`);
  for (const item of toUpload) {
    const meta = FILE_META[item.base];
    if (!meta) { console.warn(`  SKIP (no metadata): ${item.base}${item.ext}`); continue; }

    let pdfBuffer, pdfName;

    if (item.ext === '.pdf') {
      console.log(`\nUploading PDF: ${meta.title}`);
      pdfBuffer = fs.readFileSync(item.filepath);
      pdfName   = path.basename(item.filepath);
    } else {
      console.log(`\nConverting .docx → PDF: ${meta.title}`);
      pdfBuffer = await docxToPdf(fs.readFileSync(item.filepath), meta.title);
      pdfName   = item.base + '.pdf';
    }

    await uploadPdf(token, pdfBuffer, pdfName, meta.title, meta.date);
  }

  console.log('\nAll done.');
}

main().catch(err => { console.error('\nERROR:', err.message); process.exit(1); });
