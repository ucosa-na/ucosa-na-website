require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const log = require('./logger');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// HTTP request logger (skip static assets)
app.use((req, _res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/health') {
    log.info(`${req.method} ${req.path}`);
  }
  next();
});

// Rate limit auth endpoints
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts, try again later' } });
app.use('/api/auth', authLimiter);

// Routes
app.use('/api/auth',    require('./routes/auth'));
app.use('/api/admin',   require('./routes/admin'));
app.use('/api/member',  require('./routes/member'));
app.use('/api/contact', require('./routes/contact'));
app.use('/api/join',          require('./routes/join'));
app.use('/api/meeting-notes', require('./routes/meetingNotes'));

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.status(404).sendFile(path.join(__dirname, '../public/index.html'));
});

const server = app.listen(PORT, () => {
  log.info(`Server started on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
});

module.exports = { app, server };
