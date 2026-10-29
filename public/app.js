const state = {
  accessToken: localStorage.getItem('accessToken') || null,
  refreshToken: localStorage.getItem('refreshToken') || null,
  user: null,
  editingId: null,
};
const $ = (s) => document.querySelector(s);

function toast(text, type = 'ok') {
  const t = $('#toast');
  t.textContent = text;
  t.className = 'toast ' + type + ' show';
  clearTimeout(toast._tid);
  toast._tid = setTimeout(() => { t.className = 'toast ' + type; }, 3500);
}

async function authFetch(url, opts = {}) {
  opts.headers = opts.headers || {};
  if (state.accessToken) opts.headers['Authorization'] = 'Bearer ' + state.accessToken;
  let res = await fetch(url, opts);
  if (res.status === 401 && state.refreshToken && !url.includes('/api/auth/refresh')) {
    const r = await fetch('/api/auth/refresh', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: state.refreshToken }),
    });
    if (r.ok) {
      const d = await r.json();
      state.accessToken = d.accessToken;
      localStorage.setItem('accessToken', d.accessToken);
      opts.headers['Authorization'] = 'Bearer ' + state.accessToken;
      res = await fetch(url, opts);
    } else { logout(); throw new Error('Сессия истекла'); }
  }
  return res;
}

async function parseRes(res) {
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error((data && data.error) || ('Ошибка ' + res.status));
  return data;
}

function showAuthView(name) {
  $('#view-app').hidden = true;
  $('#view-auth').hidden = false;
  for (const f of ['login', 'register', 'forgot', 'reset']) {
    const el = $('#form-' + f);
    if (el) el.hidden = f !== name;
  }
}
function showApp() { $('#view-auth').hidden = true; $('#view-app').hidden = false; }

async function doLogin(email, password) {
  const res = await fetch('/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await parseRes(res);
  state.accessToken = data.accessToken;
  state.refreshToken = data.refreshToken;
  state.user = data.user;
  localStorage.setItem('accessToken', data.accessToken);
  localStorage.setItem('refreshToken', data.refreshToken);
  enterApp();
}

async function doRegister(email, password) {
  const res = await fetch('/api/auth/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  await parseRes(res);
  await doLogin(email, password);
}

function logout() {
  if (state.refreshToken) {
    fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + state.accessToken },
      body: JSON.stringify({ refreshToken: state.refreshToken }),
    }).catch(() => {});
  }
  state.accessToken = null; state.refreshToken = null; state.user = null;
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  showAuthView('login');
}

async function enterApp() {
  showApp();
  $('#user-email').textContent = state.user.email;
  const roleEl = $('#user-role');
  roleEl.textContent = state.user.role;
  roleEl.className = 'badge role-' + state.user.role;
  $('#tab-users').hidden = state.user.role !== 'admin';
  await Promise.all([loadNotes(), loadSessions()]);
  if (state.user.role === 'admin') loadUsers();
}

function renderNotes(notes) {
  const list = $('#notes-list');
  if (!notes.length) { list.innerHTML = '<p class="empty">Заметок пока нет</p>'; return; }
  list.innerHTML = '';
  for (const n of notes) {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      ${n.image_url ? '<img alt="">' : ''}
      <h3></h3>
      <p class="content"></p>
      <small></small>
      <div class="actions">
        <button class="edit">✏ Изменить</button>
        <button class="del">🗑 Удалить</button>
      </div>`;
    if (n.image_url) card.querySelector('img').src = n.image_url;
    card.querySelector('h3').textContent = n.title;
    card.querySelector('.content').textContent = n.content;
    const owner = n.owner_email ? ` · ${n.owner_email}` : '';
    card.querySelector('small').textContent = new Date(n.created_at).toLocaleString('ru-RU') + owner;
    card.querySelector('.edit').addEventListener('click', () => startEdit(n));
    card.querySelector('.del').addEventListener('click', () => deleteNote(n.id));
    list.appendChild(card);
  }
}

async function loadNotes() {
  try { renderNotes(await parseRes(await authFetch('/api/notes'))); }
  catch (e) { toast(e.message, 'error'); }
}

function startEdit(n) {
  state.editingId = n.id;
  $('#note-form [name=title]').value = n.title;
  $('#note-form [name=content]').value = n.content;
  $('#note-form [name=image]').value = '';
  $('#note-form button[type=submit]').textContent = 'Сохранить';
  $('#cancel-edit').hidden = false;
}
function resetNoteForm() {
  state.editingId = null;
  $('#note-form').reset();
  $('#note-form button[type=submit]').textContent = 'Добавить';
  $('#cancel-edit').hidden = true;
}

async function deleteNote(id) {
  if (!confirm('Удалить заметку?')) return;
  try { await parseRes(await authFetch('/api/notes/' + id, { method: 'DELETE' })); toast('Удалено'); loadNotes(); }
  catch (e) { toast(e.message, 'error'); }
}

async function loadSessions() {
  try {
    const list = await parseRes(await authFetch('/api/auth/sessions'));
    const el = $('#sessions-list');
    if (!list.length) { el.innerHTML = '<p class="empty">Нет активных сессий</p>'; return; }
    el.innerHTML = '';
    for (const s of list) {
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = `<strong></strong><br><small></small><div class="actions"><button class="del">Отозвать</button></div>`;
      card.querySelector('strong').textContent = s.ip + ' — ' + (s.user_agent || 'unknown').slice(0, 60);
      card.querySelector('small').textContent = 'Создана: ' + new Date(s.created_at).toLocaleString('ru-RU') + ' · истекает: ' + new Date(s.expires_at).toLocaleString('ru-RU');
      card.querySelector('.del').addEventListener('click', async () => {
        if (!confirm('Отозвать сессию?')) return;
        try { await parseRes(await authFetch('/api/auth/sessions/' + s.id, { method: 'DELETE' })); toast('Отозвана'); loadSessions(); }
        catch (e) { toast(e.message, 'error'); }
      });
      el.appendChild(card);
    }
  } catch (e) { toast(e.message, 'error'); }
}

async function loadUsers() {
  try {
    const list = await parseRes(await authFetch('/api/users'));
    const el = $('#users-list');
    el.innerHTML = '';
    for (const u of list) {
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = `<strong></strong><br><small></small>
        <div class="actions">
          <select><option value="user">user</option><option value="moderator">moderator</option><option value="admin">admin</option></select>
          <button class="del">Удалить</button>
        </div>`;
      card.querySelector('strong').textContent = u.email + ' (#' + u.id + ')';
      card.querySelector('small').textContent = 'создан ' + new Date(u.created_at).toLocaleString('ru-RU');
      const sel = card.querySelector('select');
      sel.value = u.role;
      sel.addEventListener('change', async () => {
        try { await parseRes(await authFetch('/api/users/' + u.id + '/role', {
          method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role: sel.value }) }));
          toast('Роль обновлена');
        } catch (e) { toast(e.message, 'error'); loadUsers(); }
      });
      card.querySelector('.del').addEventListener('click', async () => {
        if (!confirm('Удалить пользователя ' + u.email + '?')) return;
        try { await parseRes(await authFetch('/api/users/' + u.id, { method: 'DELETE' })); toast('Удалён'); loadUsers(); }
        catch (e) { toast(e.message, 'error'); }
      });
      el.appendChild(card);
    }
  } catch (e) { toast(e.message, 'error'); }
}

document.addEventListener('click', (e) => {
  const link = e.target.closest('[data-goto]');
  if (link) { e.preventDefault(); showAuthView(link.dataset.goto); }
});

$('#form-login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try { await doLogin(fd.get('email'), fd.get('password')); } catch (err) { toast(err.message, 'error'); }
});
$('#form-register').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try { await doRegister(fd.get('email'), fd.get('password')); toast('Аккаунт создан'); } catch (err) { toast(err.message, 'error'); }
});
$('#form-forgot').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const data = await parseRes(await fetch('/api/auth/forgot', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: fd.get('email') }) }));
    toast(data.message || 'Письмо отправлено'); showAuthView('login');
  } catch (err) { toast(err.message, 'error'); }
});
$('#form-reset').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const token = new URLSearchParams(location.search).get('reset');
  try {
    const data = await parseRes(await fetch('/api/auth/reset', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, password: fd.get('password') }) }));
    toast(data.message || 'Пароль изменён'); history.replaceState({}, '', '/'); showAuthView('login');
  } catch (err) { toast(err.message, 'error'); }
});
$('#note-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  if (!fd.get('image') || !fd.get('image').name) fd.delete('image');
  try {
    if (state.editingId) {
      await parseRes(await authFetch('/api/notes/' + state.editingId, { method: 'PUT', body: fd }));
      toast('Обновлено');
    } else {
      await parseRes(await authFetch('/api/notes', { method: 'POST', body: fd }));
      toast('Добавлено');
    }
    resetNoteForm(); loadNotes();
  } catch (err) { toast(err.message, 'error'); }
});
$('#cancel-edit').addEventListener('click', resetNoteForm);
$('#btn-logout').addEventListener('click', logout);

document.querySelectorAll('.tabs button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    for (const t of ['notes', 'sessions', 'users']) {
      const el = document.getElementById('tab-' + t);
      if (el) el.hidden = t !== btn.dataset.tab;
    }
    if (btn.dataset.tab === 'users') loadUsers();
    if (btn.dataset.tab === 'sessions') loadSessions();
  });
});

(async function boot() {
  const params = new URLSearchParams(location.search);
  if (params.get('reset')) { showAuthView('reset'); return; }
  if (!state.accessToken) { showAuthView('login'); return; }
  try {
    const data = await parseRes(await authFetch('/api/auth/me'));
    state.user = data.user;
    enterApp();
  } catch { showAuthView('login'); }
})();