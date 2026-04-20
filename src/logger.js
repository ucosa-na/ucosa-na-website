const fs   = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, '../app.log');

function write(level, message) {
  const ts   = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const line = `[${ts}] ${level.padEnd(5)} ${message}\n`;
  process.stdout.write(line);
  fs.appendFile(LOG_FILE, line, () => {}); // fire-and-forget
}

module.exports = {
  info:  msg => write('INFO',  msg),
  warn:  msg => write('WARN',  msg),
  error: msg => write('ERROR', msg),
};
