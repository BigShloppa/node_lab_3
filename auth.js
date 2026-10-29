const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'dev-access-secret-change-me';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-change-me';
const ACCESS_TTL = Number(process.env.JWT_ACCESS_TTL) || 900;
const REFRESH_TTL = Number(process.env.JWT_REFRESH_TTL) || 604800;

const signAccess  = (u) => jwt.sign({ sub: u.id, email: u.email, role: u.role }, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
const signRefresh = (u) => jwt.sign({ sub: u.id, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
const verifyAccess  = (t) => jwt.verify(t, ACCESS_SECRET);
const verifyRefresh = (t) => jwt.verify(t, REFRESH_SECRET);
const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');

function authRequired(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Требуется токен авторизации' });
  try {
    const p = verifyAccess(token);
    req.user = { id: p.sub, email: p.email, role: p.role };
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') return res.status(401).json({ error: 'Токен истёк' });
    return res.status(401).json({ error: 'Неверный токен' });
  }
}

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Не авторизован' });
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Недостаточно прав' });
  next();
};

module.exports = { signAccess, signRefresh, verifyAccess, verifyRefresh, hashToken, authRequired, requireRole, ACCESS_TTL, REFRESH_TTL };