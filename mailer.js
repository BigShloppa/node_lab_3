const nodemailer = require('nodemailer');
const logger = require('./logger');
let transporter = null, initialized = false;

async function initMailer() {
  if (initialized) return transporter;
  initialized = true;
  try {
    const acc = await nodemailer.createTestAccount();
    transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email', port: 587, secure: false,
      auth: { user: acc.user, pass: acc.pass },
    });
    logger.info({ user: acc.user }, 'ethereal SMTP ready (test mailbox)');
  } catch (e) {
    logger.warn({ err: e.message }, 'ethereal unavailable, emails will be logged only');
  }
  return transporter;
}

async function sendMail({ to, subject, text }) {
  await initMailer();
  if (!transporter) { logger.info({ to, subject, text }, 'EMAIL (fallback log)'); return null; }
  const info = await transporter.sendMail({ from: '"Notes App" <no-reply@notes.local>', to, subject, text });
  const preview = nodemailer.getTestMessageUrl(info);
  logger.info({ to, subject, preview }, 'EMAIL sent');
  return preview;
}

module.exports = { sendMail };