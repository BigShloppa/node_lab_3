const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateEmail(email) {
  if (typeof email !== 'string') return 'Email должен быть строкой';
  const e = email.trim();
  if (e.length < 3 || e.length > 255) return 'Email: 3–255 символов';
  if (!EMAIL_RE.test(e)) return 'Некорректный email';
  return null;
}

function validatePassword(password) {
  if (typeof password !== 'string') return 'Пароль должен быть строкой';
  if (password.length < 8 || password.length > 100) return 'Пароль: 8–100 символов';
  if (!/[A-Za-z]/.test(password)) return 'Пароль должен содержать буквы';
  if (!/\d/.test(password)) return 'Пароль должен содержать цифры';
  return null;
}

function validateNote(body) {
  const errors = [];
  const title = (body.title || '').trim();
  const content = (body.content || '').trim();
  if (title.length < 1 || title.length > 200) errors.push('Заголовок: 1–200 символов');
  if (content.length < 1 || content.length > 5000) errors.push('Содержимое: 1–5000 символов');
  return { errors, title, content };
}

module.exports = { validateEmail, validatePassword, validateNote };