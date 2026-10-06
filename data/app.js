(() => {
  const $ = (id) => document.getElementById(id);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const LS_KEYS = {
    session: 'pm_session',
  };

  const state = {
    provisioned: false,
    unlocked: false,
    busy: false,
    failCount: 0,
    lockoutMsLeft: 0,
    masterPasswordChars: 38,
    maxEntryCount: 1000,
    session: localStorage.getItem(LS_KEYS.session) || '',
    entries: [],
    entriesFiltered: [],
    filter: '',
    currentJob: null,
    jobStart: 0,
    provisionJob: null,
    masterPasswordOnce: '',
    editingId: 0,
    lockoutTimer: 0,
  };

  const screens = {
    setup: $('screenSetup'),
    unlock: $('screenUnlock'),
    app: $('screenApp'),
  };

  const ui = {
    headerControls: $('headerControls'),
    btnProvision: $('btnProvision'),
    setupStatus: $('setupStatus'),
    masterBlock: $('masterBlock'),
    masterPassword: $('masterPassword'),
    masterLen: $('masterLen'),
    btnCopyMaster: $('btnCopyMaster'),
    btnHideMaster: $('btnHideMaster'),
    btnDoneMaster: $('btnDoneMaster'),
    formUnlock: $('formUnlock'),
    inputUnlock: $('inputUnlock'),
    btnUnlock: $('btnUnlock'),
    unlockStatus: $('unlockStatus'),
    lockoutBlock: $('lockoutBlock'),
    lockoutLeft: $('lockoutLeft'),
    btnUnlockRetry: $('btnUnlockRetry'),
    btnLock: $('btnLock'),
    btnReset: $('btnReset'),
    searchInput: $('searchInput'),
    btnNew: $('btnNew'),
    btnRefresh: $('btnRefresh'),
    entriesEmpty: $('entriesEmpty'),
    entriesList: $('entriesList'),
    appStatus: $('appStatus'),
    statusLine: $('statusLine'),
    modalEntry: $('modalEntry'),
    formEntry: $('formEntry'),
    entryModalTitle: $('entryModalTitle'),
    btnEntryClose: $('btnEntryClose'),
    entryTitle: $('entryTitle'),
    entryLogin: $('entryLogin'),
    entryPassword: $('entryPassword'),
    btnGenPass: $('btnGenPass'),
    btnTogglePass: $('btnTogglePass'),
    btnCopyPass: $('btnCopyPass'),
    genOpts: $('genOpts'),
    genLen: $('genLen'),
    genLenVal: $('genLenVal'),
    genUpper: $('genUpper'),
    genLower: $('genLower'),
    genDigits: $('genDigits'),
    genSym: $('genSym'),
    entryUrl: $('entryUrl'),
    entryNote: $('entryNote'),
    btnEntryDelete: $('btnEntryDelete'),
    btnEntryCancel: $('btnEntryCancel'),
    modalReset: $('modalReset'),
    formReset: $('formReset'),
    btnResetClose: $('btnResetClose'),
    inputResetConfirm: $('inputResetConfirm'),
    resetStatus: $('resetStatus'),
    btnResetConfirm: $('btnResetConfirm'),
  };

  function setStatus(el, type, text) {
    if (!el) return;
    el.hidden = !text;
    el.textContent = text;
    el.classList.remove('status--ok', 'status--warn', 'status--error');
    if (type === 'ok') el.classList.add('status--ok');
    if (type === 'warn') el.classList.add('status--warn');
    if (type === 'error') el.classList.add('status--error');
    if (type === 'none' && !text) el.hidden = true;
  }

  function setStatusLine(text) {
    if (ui.statusLine) ui.statusLine.textContent = text;
  }

  function showScreen(name) {
    Object.entries(screens).forEach(([k, el]) => {
      if (!el) return;
      el.hidden = k !== name;
    });
    ui.headerControls.hidden = name !== 'app';
  }

  function saveSession(s) {
    state.session = s || '';
    if (s) localStorage.setItem(LS_KEYS.session, s);
    else localStorage.removeItem(LS_KEYS.session);
  }

  function api(path, opts = {}) {
    const headers = new Headers(opts.headers || {});
    if (state.session) headers.set('X-PM-Session', state.session);
    if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    return fetch(path, { ...opts, headers }).catch((e) => {
      return new Response(JSON.stringify({ ok: false, error: 'network_error' }), {
        status: 0,
        headers: { 'Content-Type': 'application/json' },
      });
    });
  }

  async function apiJson(path, opts = {}) {
    const r = await api(path, opts);
    let data = { ok: false, error: 'unknown' };
    try {
      data = await r.json();
    } catch (_) {}
    return { res: r, data };
  }

  async function loadState() {
    const { data } = await apiJson('/api/auth/state', { method: 'GET' });
    if (data && data.ok) {
      state.provisioned = !!data.provisioned;
      state.unlocked = !!data.unlocked;
      state.busy = !!data.busy;
      state.failCount = data.failCount || 0;
      state.lockoutMsLeft = data.lockoutMsLeft || 0;
      state.masterPasswordChars = data.masterPasswordChars || 38;
      state.maxEntryCount = data.maxEntryCount || 1000;
    }
    if (state.unlocked) showScreen('app');
    else if (state.provisioned) showScreen('unlock');
    else showScreen('setup');
    updateLockoutUI();
    return data;
  }

  function updateLockoutUI() {
    if (state.lockoutMsLeft > 0) {
      const s = Math.ceil(state.lockoutMsLeft / 1000);
      ui.lockoutLeft.textContent = String(s);
      ui.lockoutBlock.hidden = false;
      ui.inputUnlock.disabled = true;
      ui.btnUnlock.disabled = true;
    } else {
      ui.lockoutBlock.hidden = true;
      ui.inputUnlock.disabled = false;
      ui.btnUnlock.disabled = false;
    }
  }

  async function pollJob(jobId, timeoutMs = 120000) {
    const t0 = Date.now();
    while (Date.now() - t0 < timeoutMs) {
      const { data } = await apiJson(`/api/auth/job/${jobId}`, { method: 'GET' });
      if (!data || !data.ok) return data;
      if (data.state === 'pending') {
        await sleep(500);
        continue;
      }
      if (data.result === 'ok') return data;
      return data;
    }
    return { ok: false, error: 'job_timeout' };
  }

  async function doProvision() {
    setStatus(ui.setupStatus, 'warn', 'Создание хранилища, подождите ~2–3 секунды...');
    ui.btnProvision.disabled = true;
    const { res, data } = await apiJson('/api/auth/provision', { method: 'POST' });
    if (res.status !== 202 || !data || !data.ok || !data.job) {
      const err = (data && data.error) || 'provision_failed';
      ui.btnProvision.disabled = false;
      setStatus(ui.setupStatus, 'error', `Ошибка: ${err}`);
      return;
    }
    const job = data.job;
    const resJob = await pollJob(job, 150000);
    if (!resJob || !resJob.ok) {
      ui.btnProvision.disabled = false;
      const err = resJob && resJob.error ? resJob.error : 'job_failed';
      setStatus(ui.setupStatus, 'error', `Ошибка: ${err}`);
      return;
    }
    if (resJob.password) {
      state.masterPasswordOnce = resJob.password;
      ui.masterPassword.value = resJob.password;
      ui.masterLen.textContent = String(resJob.password.length);
      ui.masterBlock.hidden = false;
      ui.masterPassword.type = 'text';
      setStatus(ui.setupStatus, 'ok', 'Хранилище создано. Сохраните мастер-пароль.');
    }
    if (resJob.session_token) saveSession(resJob.session_token);
    await loadState();
    if (!state.unlocked && resJob.session_token) {
      await loadEntries();
    }
    ui.btnProvision.disabled = false;
  }

  async function doUnlock(pw) {
    setStatus(ui.unlockStatus, 'warn', 'Разблокировка, подождите ~5–6 секунд...');
    ui.btnUnlock.disabled = true;
    const { res, data } = await apiJson('/api/auth/unlock', {
      method: 'POST',
      body: JSON.stringify({ password: pw }),
    });
    if (res.status !== 202 || !data || !data.ok || !data.job) {
      const err = (data && data.error) || 'unlock_failed';
      ui.btnUnlock.disabled = false;
      setStatus(ui.unlockStatus, 'error', `Ошибка: ${err}`);
      if (err === 'lockout') await loadState();
      if (err === 'busy') await sleep(1000);
      updateLockoutUI();
      return;
    }
    const job = data.job;
    const resJob = await pollJob(job, 200000);
    if (!resJob || !resJob.ok) {
      ui.btnUnlock.disabled = false;
      const err = resJob && resJob.error ? resJob.error : 'job_failed';
      setStatus(ui.unlockStatus, 'error', `Ошибка: ${err}`);
      await loadState();
      updateLockoutUI();
      return;
    }
    if (resJob.session_token) saveSession(resJob.session_token);
    setStatus(ui.unlockStatus, 'ok', 'Разблокировано');
    await loadState();
    await loadEntries();
    ui.btnUnlock.disabled = false;
    ui.inputUnlock.value = '';
  }

  async function doLock() {
    const { data } = await apiJson('/api/auth/lock', { method: 'POST' });
    if (data && data.ok) {
      saveSession('');
      await loadState();
    } else {
      setStatusLine('Не удалось заблокировать');
    }
  }

  async function loadEntries() {
    setStatus(ui.appStatus, 'none', '');
    const { data } = await apiJson('/api/entries', { method: 'GET' });
    if (!data || !data.ok) {
      setStatus(ui.appStatus, 'error', `Ошибка загрузки: ${data && data.error ? data.error : 'unknown'}`);
      return;
    }
    state.entries = Array.isArray(data.entries) ? data.entries : [];
    applyFilter();
  }

  function applyFilter() {
    const f = (state.filter || '').toLowerCase();
    if (!f) {
      state.entriesFiltered = state.entries.slice();
    } else {
      state.entriesFiltered = state.entries.filter((e) => {
        const t = [e.title || '', e.login || '', e.url || ''].join(' ').toLowerCase();
        return t.includes(f);
      });
    }
    renderEntries();
  }

  function renderEntries() {
    ui.entriesList.innerHTML = '';
    if (state.entriesFiltered.length === 0) {
      ui.entriesEmpty.hidden = false;
      return;
    }
    ui.entriesEmpty.hidden = true;
    for (const e of state.entriesFiltered) {
      const card = document.createElement('div');
      card.className = 'entry-card';
      const header = document.createElement('div');
      header.className = 'entry-card__header';
      const titleEl = document.createElement('h3');
      titleEl.className = 'entry-card__title';
      titleEl.textContent = e.title || '(без названия)';
      header.appendChild(titleEl);
      card.appendChild(header);
      const meta = document.createElement('div');
      meta.className = 'entry-card__meta';
      if (e.login) {
        const r = row('Логин', e.login, true);
        meta.appendChild(r);
      }
      if (e.url) {
        const r = row('URL', e.url);
        const a = document.createElement('a');
        a.href = e.url;
        a.target = '_blank';
        a.rel = 'noreferrer';
        a.textContent = e.url;
        r.querySelector('.entry-card__value').innerHTML = '';
        r.querySelector('.entry-card__value').appendChild(a);
        meta.appendChild(r);
      }
      card.appendChild(meta);
      const acts = document.createElement('div');
      acts.className = 'entry-card__actions';
      const btnView = mkBtn('Посмотреть', () => viewEntry(e.id));
      const btnEdit = mkBtn('Редактировать', () => editEntry(e.id));
      const btnCopyLogin = mkBtn('Копировать логин', () => copyText(e.login || ''));
      const btnCopyPass = mkBtn('Показать/скопировать пароль', () => viewSecret(e.id));
      acts.append(btnView, btnEdit, btnCopyLogin, btnCopyPass);
      card.appendChild(acts);
      ui.entriesList.appendChild(card);
    }
    function row(label, val, mono = false) {
      const d = document.createElement('div');
      d.className = 'entry-card__meta-row';
      const l = document.createElement('span');
      l.className = 'entry-card__label';
      l.textContent = label;
      const v = document.createElement('span');
      v.className = 'entry-card__value' + (mono ? ' entry-card__value--mono' : '');
      v.textContent = val;
      d.append(l, v);
      return d;
    }
    function mkBtn(txt, fn) {
      const b = document.createElement('button');
      b.className = 'btn btn--ghost btn--sm';
      b.type = 'button';
      b.textContent = txt;
      b.onclick = (e) => {
        e.stopPropagation();
        fn();
      };
      return b;
    }
  }

  async function viewEntry(id) {
    const { data } = await apiJson(`/api/entries/${id}`, { method: 'GET' });
    if (!data || !data.ok) return alert(`Ошибка: ${data && data.error ? data.error : 'unknown'}`);
    const lines = [];
    if (data.title) lines.push(`Название: ${data.title}`);
    if (data.login) lines.push(`Логин: ${data.login}`);
    if (data.url) lines.push(`URL: ${data.url}`);
    if (data.note) lines.push(`Заметки:\n${data.note}`);
    lines.push(`Есть пароль: ${data.hasPassword ? 'Да' : 'Нет'}`);
    alert(lines.join('\n\n'));
  }

  async function viewSecret(id) {
    const { data } = await apiJson(`/api/entries/${id}/secret`, { method: 'GET' });
    if (!data || !data.ok) return alert(`Ошибка: ${data && data.error ? data.error : 'unknown'}`);
    const pw = data.password || '';
    if (!pw) return alert('Пароль пуст');
    try {
      await navigator.clipboard.writeText(pw);
      setStatusLine('Пароль скопирован в буфер обмена');
    } catch (_) {
      prompt('Пароль (не удалось скопировать):', pw);
    }
    setTimeout(() => setStatusLine(''), 1500);
  }

  function openEntryModal(editing = 0) {
    state.editingId = editing;
    ui.entryModalTitle.textContent = editing ? 'Редактировать запись' : 'Новая запись';
    ui.btnEntryDelete.hidden = !editing;
    ui.genOpts.hidden = true;
    ui.entryPassword.type = 'password';
    if (!editing) {
      ui.entryTitle.value = '';
      ui.entryLogin.value = '';
      ui.entryPassword.value = '';
      ui.entryUrl.value = '';
      ui.entryNote.value = '';
    }
    if (ui.modalEntry.showModal) ui.modalEntry.showModal();
    else {
      ui.modalEntry.setAttribute('open', '');
    }
  }

  async function editEntry(id) {
    const { data } = await apiJson(`/api/entries/${id}`, { method: 'GET' });
    if (!data || !data.ok) return alert(`Ошибка: ${data && data.error ? data.error : 'unknown'}`);
    ui.entryTitle.value = data.title || '';
    ui.entryLogin.value = data.login || '';
    ui.entryPassword.value = '';
    ui.entryUrl.value = data.url || '';
    ui.entryNote.value = data.note || '';
    openEntryModal(id);
  }

  function randChar(set) {
    return set[Math.floor(Math.random() * set.length)];
  }

  function generatePassword() {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const sym = '!@#$%^&*()-_=+[]{}';
    let sets = [];
    if (ui.genUpper.checked) sets.push(upper);
    if (ui.genLower.checked) sets.push(lower);
    if (ui.genDigits.checked) sets.push(digits);
    if (ui.genSym.checked) sets.push(sym);
    if (sets.length === 0) sets = [lower, digits];
    const len = parseInt(ui.genLen.value) || 16;
    let res = '';
    for (let i = 0; i < len; i++) {
      const s = sets[i % sets.length];
      res += randChar(s);
    }
    return res;
  }

  async function saveEntry() {
    const title = ui.entryTitle.value.trim();
    const login = ui.entryLogin.value.trim();
    const password = ui.entryPassword.value;
    const url = ui.entryUrl.value.trim();
    const note = ui.entryNote.value;
    if (!title && !login) {
      alert('Нужно указать название или логин');
      return;
    }
    const body = {};
    body.title = title;
    body.login = login;
    if (password.length > 0) body.password = password;
    body.url = url;
    body.note = note;
    const id = state.editingId;
    const path = id ? `/api/entries/${id}` : '/api/entries';
    const { data } = await apiJson(path, { method: 'POST', body: JSON.stringify(body) });
    if (!data || !data.ok) {
      alert(`Ошибка сохранения: ${data && data.error ? data.error : 'unknown'}`);
      return;
    }
    ui.modalEntry.close();
    await loadEntries();
  }

  async function deleteEntry() {
    const id = state.editingId;
    if (!id) return;
    if (!confirm('Удалить запись?')) return;
    const { data } = await apiJson('/api/entries', {
      method: 'DELETE',
      body: JSON.stringify({ confirm: 'DELETE' }),
    });
    const path = `/api/entries/${id}`;
    const res = await apiJson(path, { method: 'DELETE', body: JSON.stringify({ confirm: 'DELETE' }) });
    if (!res.data || !res.data.ok) {
      alert(`Ошибка удаления: ${res.data && res.data.error ? res.data.error : 'unknown'}`);
      return;
    }
    ui.modalEntry.close();
    await loadEntries();
  }

  async function resetDevice() {
    const v = ui.inputResetConfirm.value.trim();
    if (v !== 'RESET') {
      setStatus(ui.resetStatus, 'warn', 'Нужно ввести RESET');
      return;
    }
    setStatus(ui.resetStatus, 'warn', 'Сброс хранилища, ждите...');
    ui.btnResetConfirm.disabled = true;
    const { res, data } = await apiJson('/api/auth/reset', {
      method: 'POST',
      body: JSON.stringify({ confirm: 'RESET' }),
    });
    if (res.status !== 202 || !data || !data.ok || !data.job) {
      const err = (data && data.error) || 'reset_failed';
      ui.btnResetConfirm.disabled = false;
      setStatus(ui.resetStatus, 'error', `Ошибка: ${err}`);
      return;
    }
    const job = data.job;
    const resJob = await pollJob(job, 150000);
    if (!resJob || !resJob.ok) {
      ui.btnResetConfirm.disabled = false;
      const err = resJob && resJob.error ? resJob.error : 'job_failed';
      setStatus(ui.resetStatus, 'error', `Ошибка: ${err}`);
      return;
    }
    saveSession('');
    ui.modalReset.close();
    ui.inputResetConfirm.value = '';
    ui.btnResetConfirm.disabled = true;
    setStatus(ui.resetStatus, 'none', '');
    await loadState();
    state.entries = [];
    renderEntries();
  }

  async function init() {
    ui.masterPassword.value = '';
    ui.masterBlock.hidden = true;
    await loadState();
    if (state.unlocked) await loadEntries();
    setStatusLine('Готово');
  }

  ui.btnProvision.onclick = () => doProvision();
  ui.btnCopyMaster.onclick = async () => {
    try {
      await navigator.clipboard.writeText(ui.masterPassword.value);
      setStatusLine('Скопировано');
      setTimeout(() => setStatusLine(''), 1000);
    } catch (_) {}
  };
  ui.btnHideMaster.onclick = () => {
    ui.masterPassword.type = ui.masterPassword.type === 'password' ? 'text' : 'password';
  };
  ui.btnDoneMaster.onclick = () => {
    ui.masterBlock.hidden = true;
    state.masterPasswordOnce = '';
  };
  ui.formUnlock.onsubmit = (e) => {
    e.preventDefault();
    doUnlock(ui.inputUnlock.value);
  };
  ui.btnUnlockRetry.onclick = () => loadState();
  ui.btnLock.onclick = () => doLock();
  ui.btnReset.onclick = () => {
    ui.inputResetConfirm.value = '';
    ui.btnResetConfirm.disabled = true;
    setStatus(ui.resetStatus, 'none', '');
    if (ui.modalReset.showModal) ui.modalReset.showModal();
    else ui.modalReset.setAttribute('open', '');
  };
  ui.searchInput.oninput = () => {
    state.filter = ui.searchInput.value;
    applyFilter();
  };
  ui.btnNew.onclick = () => openEntryModal(0);
  ui.btnRefresh.onclick = () => loadEntries();
  ui.btnEntryClose.onclick = () => ui.modalEntry.close();
  ui.btnEntryCancel.onclick = () => ui.modalEntry.close();
  ui.formEntry.onsubmit = (e) => {
    e.preventDefault();
    saveEntry();
  };
  ui.btnEntryDelete.onclick = () => deleteEntry();
  ui.btnGenPass.onclick = () => {
    ui.genOpts.hidden = !ui.genOpts.hidden;
    if (!ui.genOpts.hidden) {
      ui.entryPassword.value = generatePassword();
      ui.entryPassword.type = 'text';
    }
  };
  ui.genLen.oninput = () => {
    ui.genLenVal.textContent = ui.genLen.value;
    if (!ui.genOpts.hidden) ui.entryPassword.value = generatePassword();
  };
  ui.genUpper.onchange = () => {
    if (!ui.genOpts.hidden) ui.entryPassword.value = generatePassword();
  };
  ui.genLower.onchange = () => {
    if (!ui.genOpts.hidden) ui.entryPassword.value = generatePassword();
  };
  ui.genDigits.onchange = () => {
    if (!ui.genOpts.hidden) ui.entryPassword.value = generatePassword();
  };
  ui.genSym.onchange = () => {
    if (!ui.genOpts.hidden) ui.entryPassword.value = generatePassword();
  };
  ui.btnTogglePass.onclick = () => {
    ui.entryPassword.type = ui.entryPassword.type === 'password' ? 'text' : 'password';
  };
  ui.btnCopyPass.onclick = async () => {
    try {
      await navigator.clipboard.writeText(ui.entryPassword.value);
      setStatusLine('Пароль скопирован');
      setTimeout(() => setStatusLine(''), 1000);
    } catch (_) {}
  };
  ui.btnResetClose.onclick = () => ui.modalReset.close();
  ui.btnResetCancel.onclick = () => ui.modalReset.close();
  ui.inputResetConfirm.oninput = () => {
    ui.btnResetConfirm.disabled = ui.inputResetConfirm.value.trim() !== 'RESET';
  };
  ui.formReset.onsubmit = (e) => {
    e.preventDefault();
    resetDevice();
  };

  init();
})();
