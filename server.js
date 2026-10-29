require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const pinoHttp = require('pino-http');
const rateLimit = require('express-rate-limit');

const logger = require('./logger');
const { pool, init } = require('./db');
const { sendMail } = require('./mailer');
const { signAccess, signRefresh, verifyRefresh, hashToken, authRequired, requireRole, REFRESH_TTL } = require('./auth');
const { validateEmail, validatePassword, validateNote } = require('./utils');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(pinoHttp({
  logger,
  genReqId: (req) => req.headers['x-request-id'] || crypto.randomUUID(),
  customLogLevel: (req, res, err) => (err || res.statusCode >= 500) ? 'error' : (res.statusCode >= 400 ? 'warn' : 'info'),
  redact: ['req.headers.authorization', 'req.headers.cookie', 'req.body.password'],
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase()),
});
const ALLOWED = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'];
const upload = multer({
  storage, limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => ALLOWED.includes(file.mimetype) ? cb(null, true) : cb(new Error('Недопустимый тип файла')),
});
function rmFile(url) { if (url) fs.unlink(path.join(__dirname, url.replace(/^\//, '')), () => {}); }

const authLimiter   = rateLimit({ windowMs: 15*60*1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Слишком много попыток, попробуйте позже' } });
const loginLimiter  = rateLimit({ windowMs: 15*60*1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Слишком много попыток входа, попробуйте позже' } });
const forgotLimiter = rateLimit({ windowMs: 60*60*1000, max: 5,  standardHeaders: true, legacyHeaders: false, message: { error: 'Слишком много запросов восстановления' } });

// === AUTH ===
app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const eErr = validateEmail(email), pErr = validatePassword(password);
    if (eErr || pErr) return res.status(400).json({ error: [eErr, pErr].filter(Boolean).join('; ') });
    const norm = email.trim().toLowerCase();
    if ((await pool.query('SELECT id FROM users WHERE email=$1', [norm])).rows[0])
      return res.status(409).json({ error: 'Пользователь уже существует' });
    const r = await pool.query('INSERT INTO users (email, password_hash) VALUES ($1,$2) RETURNING id, email, role',
      [norm, await bcrypt.hash(password, 10)]);
    logger.info({ userId: r.rows[0].id }, 'user registered');
    res.status(201).json({ user: r.rows[0] });
  } catch (e) { next(e); }
});

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });
    const user = (await pool.query('SELECT * FROM users WHERE email=$1', [String(email).trim().toLowerCase()])).rows[0];
    if (!user) { logger.warn({ email }, 'login: unknown email'); return res.status(401).json({ error: 'Неверный email или пароль' }); }
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      logger.warn({ userId: user.id }, 'login: locked');
      return res.status(423).json({ error: 'Аккаунт временно заблокирован' });
    }
    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) {
      const failed = user.failed_attempts + 1;
      const lockedUntil = failed >= 5 ? new Date(Date.now() + 15*60*1000) : null;
      await pool.query('UPDATE users SET failed_attempts=$1, locked_until=$2 WHERE id=$3', [failed, lockedUntil, user.id]);
      logger.warn({ userId: user.id, failed }, 'login: wrong password');
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    await pool.query('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=$1', [user.id]);
    const accessToken = signAccess(user);
    const refreshToken = signRefresh(user);
    const sess = await pool.query(
      'INSERT INTO sessions (user_id, token_hash, user_agent, ip, expires_at) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [user.id, hashToken(refreshToken), req.headers['user-agent'] || '', req.ip, new Date(Date.now() + REFRESH_TTL*1000)]);
    logger.info({ userId: user.id, sessionId: sess.rows[0].id }, 'login: success');
    res.status(200).json({ accessToken, refreshToken, user: { id: user.id, email: user.email, role: user.role } });
  } catch (e) { next(e); }
});

app.post('/api/auth/refresh', async (req, res, next) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: 'refreshToken обязателен' });
    let payload;
    try { payload = verifyRefresh(refreshToken); }
    catch { return res.status(401).json({ error: 'Неверный или истёкший refreshToken' }); }
    const s = await pool.query('SELECT * FROM sessions WHERE token_hash=$1 AND revoked=FALSE AND expires_at > NOW()', [hashToken(refreshToken)]);
    if (!s.rows[0]) return res.status(401).json({ error: 'Сессия не найдена или отозвана' });
    const u = await pool.query('SELECT id, email, role FROM users WHERE id=$1', [payload.sub]);
    if (!u.rows[0]) return res.status(401).json({ error: 'Пользователь не найден' });
    res.status(200).json({ accessToken: signAccess(u.rows[0]) });
  } catch (e) { next(e); }
});

app.post('/api/auth/logout', authRequired, async (req, res, next) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: 'refreshToken обязателен' });
    await pool.query('UPDATE sessions SET revoked=TRUE WHERE token_hash=$1 AND user_id=$2', [hashToken(refreshToken), req.user.id]);
    logger.info({ userId: req.user.id }, 'logout');
    res.status(200).json({ message: 'Выход выполнен' });
  } catch (e) { next(e); }
});

app.get('/api/auth/me', authRequired, (req, res) => res.status(200).json({ user: req.user }));

app.get('/api/auth/sessions', authRequired, async (req, res, next) => {
  try {
    const r = await pool.query(
      'SELECT id, user_agent, ip, created_at, expires_at FROM sessions WHERE user_id=$1 AND revoked=FALSE AND expires_at > NOW() ORDER BY created_at DESC',
      [req.user.id]);
    res.status(200).json(r.rows);
  } catch (e) { next(e); }
});

app.delete('/api/auth/sessions/:id', authRequired, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Некорректный id' });
    const r = await pool.query('UPDATE sessions SET revoked=TRUE WHERE id=$1 AND user_id=$2 RETURNING id', [id, req.user.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Сессия не найдена' });
    logger.info({ userId: req.user.id, sessionId: id }, 'session revoked');
    res.status(200).json({ message: 'Сессия отозвана' });
  } catch (e) { next(e); }
});

app.post('/api/auth/forgot', forgotLimiter, async (req, res, next) => {
  try {
    const { email } = req.body || {};
    const eErr = validateEmail(email);
    if (eErr) return res.status(400).json({ error: eErr });
    const r = await pool.query('SELECT id FROM users WHERE email=$1', [email.trim().toLowerCase()]);
    if (!r.rows[0]) return res.status(200).json({ message: 'Если email существует, письмо отправлено' });
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1,$2,$3)',
      [r.rows[0].id, hashToken(token), new Date(Date.now() + 60*60*1000)]);
    const resetUrl = `${req.protocol}://${req.headers.host}/?reset=${token}`;
    try { await sendMail({ to: email, subject: 'Восстановление пароля', text: `Сброс пароля: ${resetUrl}\nДействует 1 час.` }); }
    catch (e) { logger.error({ err: e.message }, 'mail failed'); }
    res.status(200).json({ message: 'Если email существует, письмо отправлено' });
  } catch (e) { next(e); }
});

app.post('/api/auth/reset', authLimiter, async (req, res, next) => {
  try {
    const { token, password } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token обязателен' });
    const pErr = validatePassword(password);
    if (pErr) return res.status(400).json({ error: pErr });
    const r = await pool.query('SELECT * FROM password_resets WHERE token_hash=$1 AND used=FALSE AND expires_at > NOW()', [hashToken(token)]);
    if (!r.rows[0]) return res.status(400).json({ error: 'Ссылка недействительна или истекла' });
    const pr = r.rows[0];
    await pool.query('UPDATE users SET password_hash=$1, failed_attempts=0, locked_until=NULL WHERE id=$2', [await bcrypt.hash(password, 10), pr.user_id]);
    await pool.query('UPDATE password_resets SET used=TRUE WHERE id=$1', [pr.id]);
    await pool.query('UPDATE sessions SET revoked=TRUE WHERE user_id=$1', [pr.user_id]);
    logger.info({ userId: pr.user_id }, 'password reset');
    res.status(200).json({ message: 'Пароль изменён, все сессии отозваны' });
  } catch (e) { next(e); }
});

// === USERS (admin) ===
app.get('/api/users', authRequired, requireRole('admin'), async (req, res, next) => {
  try { res.status(200).json((await pool.query('SELECT id, email, role, created_at FROM users ORDER BY id')).rows); }
  catch (e) { next(e); }
});

app.put('/api/users/:id/role', authRequired, requireRole('admin'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Некорректный id' });
    const { role } = req.body || {};
    if (!['user','moderator','admin'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
    const r = await pool.query('UPDATE users SET role=$1 WHERE id=$2 RETURNING id, email, role', [role, id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
    logger.info({ actor: req.user.id, target: id, role }, 'role changed');
    res.status(200).json(r.rows[0]);
  } catch (e) { next(e); }
});

app.delete('/api/users/:id', authRequired, requireRole('admin'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Некорректный id' });
    if (id === req.user.id) return res.status(400).json({ error: 'Нельзя удалить себя' });
    const r = await pool.query('DELETE FROM users WHERE id=$1 RETURNING id', [id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
    logger.info({ actor: req.user.id, target: id }, 'user deleted');
    res.status(200).json({ message: 'Пользователь удалён' });
  } catch (e) { next(e); }
});

// === NOTES ===
app.get('/api/notes', authRequired, async (req, res, next) => {
  try {
    const isPriv = req.user.role === 'admin' || req.user.role === 'moderator';
    const r = isPriv
      ? await pool.query('SELECT n.*, u.email AS owner_email FROM notes n LEFT JOIN users u ON u.id=n.user_id ORDER BY n.id DESC')
      : await pool.query('SELECT * FROM notes WHERE user_id=$1 ORDER BY id DESC', [req.user.id]);
    res.status(200).json(r.rows);
  } catch (e) { next(e); }
});

app.get('/api/notes/:id', authRequired, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Некорректный id' });
    const n = (await pool.query('SELECT * FROM notes WHERE id=$1', [id])).rows[0];
    if (!n) return res.status(404).json({ error: 'Заметка не найдена' });
    const isOwner = n.user_id === req.user.id;
    const isPriv = req.user.role === 'admin' || req.user.role === 'moderator';
    if (!isOwner && !isPriv) return res.status(403).json({ error: 'Нет доступа' });
    res.status(200).json(n);
  } catch (e) { next(e); }
});

app.post('/api/notes', authRequired, upload.single('image'), async (req, res, next) => {
  try {
    const { errors, title, content } = validateNote(req.body);
    if (errors.length) { if (req.file) rmFile('/uploads/' + req.file.filename); return res.status(400).json({ error: errors.join('; ') }); }
    const image_url = req.file ? '/uploads/' + req.file.filename : null;
    const r = await pool.query('INSERT INTO notes (user_id, title, content, image_url) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.user.id, title, content, image_url]);
    logger.info({ userId: req.user.id, noteId: r.rows[0].id }, 'note created');
    res.status(201).json(r.rows[0]);
  } catch (e) { next(e); }
});

app.put('/api/notes/:id', authRequired, upload.single('image'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Некорректный id' });
    const n = (await pool.query('SELECT * FROM notes WHERE id=$1', [id])).rows[0];
    if (!n) { if (req.file) rmFile('/uploads/' + req.file.filename); return res.status(404).json({ error: 'Заметка не найдена' }); }
    const isOwner = n.user_id === req.user.id;
    const isPriv = req.user.role === 'admin' || req.user.role === 'moderator';
    if (!isOwner && !isPriv) { if (req.file) rmFile('/uploads/' + req.file.filename); return res.status(403).json({ error: 'Нет доступа' }); }
    const { errors, title, content } = validateNote(req.body);
    if (errors.length) { if (req.file) rmFile('/uploads/' + req.file.filename); return res.status(400).json({ error: errors.join('; ') }); }
    let image_url = n.image_url;
    if (req.file) { rmFile(image_url); image_url = '/uploads/' + req.file.filename; }
    const r = await pool.query('UPDATE notes SET title=$1, content=$2, image_url=$3 WHERE id=$4 RETURNING *', [title, content, image_url, id]);
    logger.info({ userId: req.user.id, noteId: id }, 'note updated');
    res.status(200).json(r.rows[0]);
  } catch (e) { next(e); }
});

app.delete('/api/notes/:id', authRequired, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Некорректный id' });
    const n = (await pool.query('SELECT * FROM notes WHERE id=$1', [id])).rows[0];
    if (!n) return res.status(404).json({ error: 'Заметка не найдена' });
    const isOwner = n.user_id === req.user.id;
    const isPriv = req.user.role === 'admin' || req.user.role === 'moderator';
    if (!isOwner && !isPriv) return res.status(403).json({ error: 'Нет доступа' });
    await pool.query('DELETE FROM notes WHERE id=$1', [id]);
    rmFile(n.image_url);
    logger.info({ userId: req.user.id, noteId: id }, 'note deleted');
    res.status(200).json({ message: 'Удалено' });
  } catch (e) { next(e); }
});

app.get('/health', async (req, res) => {
  try { await pool.query('SELECT 1'); res.status(200).json({ status: 'ok' }); }
  catch { res.status(503).json({ status: 'db down' }); }
});

app.use((req, res) => res.status(404).json({ error: 'Не найдено', path: req.path }));

app.use((err, req, res, _next) => {
  logger.error({ err: { message: err.message, stack: err.stack }, reqId: req.id }, 'request failed');
  if (err.message === 'Недопустимый тип файла') return res.status(400).json({ error: err.message, reqId: req.id });
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Файл слишком большой (макс. 5 МБ)', reqId: req.id });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Некорректный JSON', reqId: req.id });
  res.status(500).json({ error: 'Внутренняя ошибка сервера', reqId: req.id });
});

async function start() {
  for (let i = 1; i <= 30; i++) {
    try { await init(); break; }
    catch (e) { logger.warn({ attempt: i, err: e.message }, 'waiting for DB'); await new Promise(r => setTimeout(r, 1500)); }
  }
  app.listen(PORT, () => logger.info({ port: PORT }, 'server started'));
}
if (require.main === module) start();
module.exports = { app };