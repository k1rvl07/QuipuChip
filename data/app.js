(() => {
  'use strict';

  const SESSION_KEY = 'pm_session';
  const IMPORT_BATCH = 4;
  const JOB_TIMEOUT_MS = 180000;
  const POLL_MS = 300;
  const BASE32_RE = /^[A-Z2-7]+=*$/;

  const state = {
    provisioned: false,
    unlocked: false,
    busy: false,
    failCount: 0,
    lockoutMsLeft: 0,
    keyfileRequired: false,
    masterPasswordChars: 38,
    maxEntryCount: 0,
    keyFileMaxBytes: 4096,
    session: localStorage.getItem(SESSION_KEY) || '',
    entries: [],
    editingId: null,
    viewId: null,
    masterShown: '',
    inAuthFlow: 0,
    lockoutTimer: null,
    totpTimer: null,
  };

  const RU = {
    wrong_password: 'Неверный мастер-пароль',
    wrong_keyfile: 'Неверный ключевой файл',
    lockout: 'Слишком много неудачных попыток — блировка',
    busy: 'Устройство занято другой операцией',
    refused: 'Операция отклонена устройством',
    already_provisioned: 'Хранилище уже настроено',
    keyfile_invalid_base64: 'Некорректный файл ключа',
    keyfile_too_large: 'Файл ключа больше 4096 байт',
    keyfile_not_a_string: 'Ошибка чтения файла ключа',
    confirmation_required: 'Введите RESET для подтверждения',
    too_many_entries: 'Хранилище переполнено — удалите запись',
    storage_full: 'Нет места во флеше хранилища',
    entry_too_long: 'Одно из полей записи слишком длинное',
    field_too_long_or_not_a_string: 'Одно из полей записи слишком длинное',
    totp_secret_invalid: 'TOTP-секрет не проходит проверку base32',
    totp_not_configured: 'TOTP не настроен для этой записи',
    time_required: 'Нет метки времени для TOTP',
    format_required: 'Файл не в формате PMX1',
    version_unsupported: 'Версия формата файла не поддерживается',
    entries_required: 'В файле нет записей',
    nothing_to_import: 'Нечего импортировать',
    batch_too_large: 'В батче больше 4 записей',
    entry_not_an_object: 'Повреждённая запись в файле',
    unknown_job: 'Операция устарела — повторите',
    entry_not_found: 'Запись не найдена',
    entries_busy: 'Сервер занят, повторите через секунду',
    session_required: 'Сессия истекла',
    vault_not_open: 'Хранилище не открыто',
    vault_load_failed: 'Ошибка чтения хранилища',
    network: 'нет связи с устройством',
    job_timeout: 'Операция выполняется слишком долго',
    bad_job_accept: 'Устройство ответило неожиданным образом',
    job_failed: 'Операция завершилась ошибкой',
    http_0: 'нет связи с устройством',
    kdbx_load_failed: 'Не удалось загрузить модуль .kdbx',
    kdbx_open_failed: 'Не удалось открыть базу: неверный пароль/ключевой файл или файл повреждён',
    kdbx_no_file: 'Выберите файл .kdbx',
    kdbx_no_password: 'Введите пароль файла',
    kdbx_make_failed: 'Не удалось сформировать файл .kdbx',
  };

  function el(id) {
    return document.getElementById(id);
  }

  function errMsg(code) {
    return RU[code] || code || 'неизвестная ошибка';
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  class ApiError extends Error {
    constructor(status, code) {
      super(`${status}: ${code}`);
      this.status = status;
      this.code = code;
    }
  }

  function statusOf(node, kind, msg) {
    node.hidden = false;
    node.className = `status status--${kind}`;
    node.textContent = msg;
  }

  function hideStatus(node) {
    node.hidden = true;
    node.textContent = '';
  }

  function sessionSensitive(path) {
    return (
      path.startsWith('/api/entries') ||
      path.startsWith('/api/export') ||
      path.startsWith('/api/import') ||
      path === '/api/auth/session' ||
      path === '/api/auth/lock' ||
      path === '/api/auth/password' ||
      path === '/api/auth/rekey' ||
      path === '/api/auth/reset'
    );
  }

  function saveSession(tok) {
    state.session = tok;
    if (tok) {
      localStorage.setItem(SESSION_KEY, tok);
    } else {
      localStorage.removeItem(SESSION_KEY);
    }
  }

  async function api(path, opts = {}) {
    const headers = { Accept: 'application/json' };
    if (state.session) {
      headers['X-PM-Session'] = state.session;
    }
    let body;
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }
    let res;
    try {
      res = await fetch(path, {
        method: opts.method || 'GET',
        headers,
        body,
        cache: 'no-store',
      });
    } catch (e) {
      throw new ApiError(0, 'network');
    }
    let data = null;
    try {
      data = await res.json();
    } catch (e) {
      data = null;
    }
    if (!res.ok) {
      const code = (data && data.error) || `http_${res.status}`;
      if (res.status === 401 && sessionSensitive(path) &&
          (code === 'session_required' || state.inAuthFlow === 0)) {
        // session_required обязан уводить на экран разблокировки ВСЕГДА, в том
        // числе внутри submitJob(): иначе счётчик inAuthFlow поднят, и операция
        // показывает молчаливый статус «Сессия истекла» в модалке, которая уже
        // не может ничего сделать — тупик, из которого пользователь не выходит.
        handleSessionExpired();
      }
      throw new ApiError(res.status, code);
    }
    return { status: res.status, data };
  }

  async function submitJob(path, body) {
    state.inAuthFlow += 1;
    try {
      const acc = await api(path, { method: 'POST', body });
      if (acc.status !== 202 || !acc.data || !acc.data.job) {
        throw new ApiError(acc.status, 'bad_job_accept');
      }
      const deadline = Date.now() + JOB_TIMEOUT_MS;
      for (;;) {
        const r = await api(`/api/auth/job/${acc.data.job}`);
        if (r.data && r.data.state === 'pending') {
          if (Date.now() > deadline) {
            throw new ApiError(0, 'job_timeout');
          }
          await sleep(POLL_MS);
          continue;
        }
        if (r.data && r.data.result === 'ok') {
          if (r.data.session_token) {
            saveSession(r.data.session_token);
          }
          return r.data;
        }
        throw new ApiError(r.status, (r.data && r.data.error) || 'job_failed');
      }
    } finally {
      state.inAuthFlow -= 1;
    }
  }

  async function fetchState() {
    const r = await api('/api/auth/state');
    const d = r.data;
    state.provisioned = !!d.provisioned;
    state.unlocked = !!d.unlocked;
    state.busy = !!d.busy;
    state.failCount = d.failCount | 0;
    state.lockoutMsLeft = d.lockoutMsLeft | 0;
    state.keyfileRequired = !!d.keyfileRequired;
    state.masterPasswordChars = d.masterPasswordChars || 38;
    state.maxEntryCount = d.maxEntryCount || 0;
    state.keyFileMaxBytes = d.keyFileMaxBytes || 4096;
    return d;
  }

  async function sessionValid() {
    if (!state.session) {
      return false;
    }
    try {
      const r = await api('/api/auth/session');
      state.entriesCount = r.data.entryCount | 0;
      return true;
    } catch (e) {
      if (e.code === 'session_required' || e.status === 401) {
        saveSession('');
        return false;
      }
      throw e;
    }
  }

  function handleSessionExpired() {
    saveSession('');
    // Открытые модалки обязаны закрываться: showScreen('unlock') прячет экран
    // приложения, но <dialog> лежит вне экранов и остался бы висеть поверх
    // экрана разблокировки с мёртвым содержимым.
    document.querySelectorAll('dialog[open]').forEach((d) => d.close());
    if (el('screenApp') && !el('screenApp').hidden) {
      showScreen('unlock');
      const st = el('unlockStatus');
      statusOf(st, 'warn', 'Сессия истекла — войдите заново');
      refreshKeyfileBlock();
    }
  }

  function showScreen(name) {
    el('screenSetup').hidden = name !== 'setup';
    el('screenUnlock').hidden = name !== 'unlock';
    el('screenApp').hidden = name !== 'app';
    el('headerControls').hidden = name !== 'app';
    if (name !== 'unlock') {
      stopLockoutTimer();
    }
    if (name !== 'app') {
      stopTotpTimer();
    }
  }

  function updateFooter() {
    const parts = [];
    parts.push(state.provisioned ? (state.unlocked ? 'разблокировано' : 'заблокировано') : 'не настроено');
    if (state.provisioned) {
      parts.push(`записей: ${state.entries.length}${state.maxEntryCount ? `/${state.maxEntryCount}` : ''}`);
      parts.push(`ключевой файл: ${state.keyfileRequired ? 'да' : 'нет'}`);
      parts.push(`неудач: ${state.failCount}`);
    }
    parts.push(state.session ? 'сессия активна' : 'без сессии');
    el('statusLine').textContent = parts.join(' · ');
  }

  async function boot() {
    try {
      await fetchState();
      if (!state.provisioned) {
        showScreen('setup');
        updateFooter();
        return;
      }
      if (await sessionValid()) {
        await enterApp();
        return;
      }
      showScreen('unlock');
      refreshKeyfileBlock();
      if (state.lockoutMsLeft > 0) {
        startLockoutTimer();
      }
      updateFooter();
      statusOf(el('unlockStatus'), 'warn', 'Требуется мастер-пароль');
    } catch (e) {
      el('statusLine').textContent = `Нет связи с устройством (${errMsg(e.code)}), повтор через 3 с…`;
      setTimeout(boot, 3000);
    }
  }

  async function enterApp() {
    showScreen('app');
    hideStatus(el('unlockStatus'));
    await loadEntries();
    updateFooter();
  }

  async function loadEntries() {
    try {
      const r = await api('/api/entries');
      state.entries = r.data.entries || [];
      render();
      updateFooter();
    } catch (e) {
      statusOf(el('appStatus'), 'error', `Не удалось загрузить записи: ${errMsg(e.code)}`);
    }
  }

  function h(tag, className, text) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = text;
    }
    return node;
  }

  function render() {
    const q = el('searchInput').value.trim().toLowerCase();
    const list = el('entriesList');
    list.textContent = '';
    const rows = state.entries.filter((e) => {
      if (!q) {
        return true;
      }
      const hay = `${e.title || ''}\n${e.login || ''}\n${e.url || ''}\n${e.tags || ''}`.toLowerCase();
      return hay.includes(q);
    });
    el('entriesEmpty').hidden = state.entries.length !== 0;
    for (const e of rows) {
      list.appendChild(card(e));
    }
  }

  function card(e) {
    const box = h('div', 'entry-card');
    const head = h('div', 'entry-card__header');
    head.appendChild(h('h3', 'entry-card__title', e.title || '(без названия)'));
    box.appendChild(head);

    const meta = h('div', 'entry-card__meta');
    if (e.login) {
      const row = h('div', 'entry-card__meta-row');
      row.appendChild(h('span', 'entry-card__label', 'Логин'));
      row.appendChild(h('span', 'entry-card__value entry-card__value--mono', e.login));
      meta.appendChild(row);
    }
    if (e.url) {
      const row = h('div', 'entry-card__meta-row');
      row.appendChild(h('span', 'entry-card__label', 'URL'));
      row.appendChild(h('span', 'entry-card__value', e.url));
      meta.appendChild(row);
    }
    box.appendChild(meta);

    const tagList = (e.tags || '').split(',').map((t) => t.trim()).filter(Boolean);
    if (tagList.length || e.hasTotp) {
      const badges = h('div', 'entry-card__badges');
      for (const t of tagList.slice(0, 8)) {
        badges.appendChild(h('span', 'badge', t));
      }
      if (e.hasTotp) {
        badges.appendChild(h('span', 'badge badge--totp', 'TOTP'));
      }
      box.appendChild(badges);
    }

    const actions = h('div', 'entry-card__actions');
    const bView = h('button', 'btn btn--ghost btn--sm', 'Просмотр');
    bView.type = 'button';
    bView.addEventListener('click', () => openView(e.id));
    const bEdit = h('button', 'btn btn--ghost btn--sm', 'Редактировать');
    bEdit.type = 'button';
    bEdit.addEventListener('click', () => openEdit(e.id));
    actions.appendChild(bView);
    actions.appendChild(bEdit);
    if (e.login) {
      const bCopy = h('button', 'btn btn--ghost btn--sm', 'Копировать логин');
      bCopy.type = 'button';
      bCopy.addEventListener('click', () => copyText(e.login, bCopy));
      actions.appendChild(bCopy);
    }
    box.appendChild(actions);
    return box;
  }

  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      if (btn) {
        const old = btn.textContent;
        btn.textContent = 'Скопировано';
        setTimeout(() => {
          btn.textContent = old;
        }, 1200);
      }
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
  }

  async function fileToB64(file) {
    const buf = new Uint8Array(await file.arrayBuffer());
    let s = '';
    for (let i = 0; i < buf.length; i += 1) {
      s += String.fromCharCode(buf[i]);
    }
    return btoa(s);
  }

  async function readKeyfile(input, maxBytes) {
    const file = input.files && input.files[0];
    if (!file) {
      return { absent: true };
    }
    if (file.size > maxBytes) {
      throw new ApiError(400, 'keyfile_too_large');
    }
    return { absent: false, b64: await fileToB64(file) };
  }

  function randInt(max) {
    const zone = Math.floor(0x10000 / max) * max;
    const a = new Uint16Array(1);
    for (;;) {
      crypto.getRandomValues(a);
      if (a[0] < zone) {
        return a[0] % max;
      }
    }
  }

  const SETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digits: '0123456789',
    sym: '!@#$%^&*()-_=+[]{};:,.?/',
  };

  function generatePassword() {
    const len = parseInt(el('genLen').value, 10) || 16;
    const chosen = [];
    for (const key of ['upper', 'lower', 'digits', 'sym']) {
      const cb = el(`gen${key.charAt(0).toUpperCase()}${key.slice(1)}`);
      if (cb.checked) {
        chosen.push(SETS[key]);
      }
    }
    if (chosen.length === 0) {
      chosen.push(SETS.lower);
      el('genLower').checked = true;
    }
    const union = chosen.join('');
    const out = [];
    for (const set of chosen) {
      out.push(set.charAt(randInt(set.length)));
    }
    while (out.length < len) {
      out.push(union.charAt(randInt(union.length)));
    }
    out.length = len;
    for (let i = out.length - 1; i > 0; i -= 1) {
      const j = randInt(i + 1);
      const t = out[i];
      out[i] = out[j];
      out[j] = t;
    }
    return out.join('');
  }

  async function doProvision() {
    const btn = el('btnProvision');
    const st = el('setupStatus');
    hideStatus(st);
    btn.disabled = true;
    try {
      const kf = await readKeyfile(el('inputSetupKeyfile'), state.keyFileMaxBytes);
      const body = {};
      if (!kf.absent) {
        body.keyfile = kf.b64;
      }
      const res = await submitJob('/api/auth/provision', body);
      state.masterShown = res.password || '';
      state.keyfileRequired = !kf.absent;
      el('masterPassword').value = state.masterShown;
      el('masterLen').textContent = String(state.masterShown.length);
      el('masterBlock').hidden = false;
      statusOf(st, 'ok', 'Хранилище создано. Сохраните мастер-пароль.');
      updateFooter();
    } catch (e) {
      statusOf(st, 'error', errMsg(e.code));
    } finally {
      btn.disabled = false;
    }
  }

  function toggleMaster() {
    const ta = el('masterPassword');
    if (ta.value && ta.value !== '•'.repeat(state.masterShown.length)) {
      ta.value = '•'.repeat(state.masterShown.length);
    } else {
      ta.value = state.masterShown;
    }
  }

  async function doUnlock(e) {
    if (e) {
      e.preventDefault();
    }
    const st = el('unlockStatus');
    const btn = el('btnUnlock');
    hideStatus(st);
    const pw = el('inputUnlock').value;
    if (!pw) {
      statusOf(st, 'error', 'Введите мастер-пароль');
      return;
    }
    btn.disabled = true;
    try {
      const body = { password: pw };
      if (state.keyfileRequired) {
        const kf = await readKeyfile(el('inputUnlockKeyfile'), state.keyFileMaxBytes);
        if (kf.absent) {
          statusOf(st, 'error', 'Выберите ключевой файл');
          return;
        }
        body.keyfile = kf.b64;
      }
      await submitJob('/api/auth/unlock', body);
      el('inputUnlock').value = '';
      const file = el('inputUnlockKeyfile');
      if (file) {
        file.value = '';
      }
      await fetchState();
      await enterApp();
    } catch (err) {
      statusOf(st, 'error', errMsg(err.code));
      try {
        await fetchState();
        updateFooter();
        if (state.lockoutMsLeft > 0) {
          startLockoutTimer();
        }
      } catch (e2) {
        /* состояние не обновилось — оставляем как есть */
      }
    } finally {
      btn.disabled = false;
    }
  }

  function refreshKeyfileBlock() {
    el('unlockKeyfileBlock').hidden = !state.keyfileRequired;
  }

  function startLockoutTimer() {
    stopLockoutTimer();
    el('lockoutBlock').hidden = false;
    let left = Math.ceil(state.lockoutMsLeft / 1000);
    el('lockoutLeft').textContent = String(left);
    state.lockoutTimer = setInterval(() => {
      left -= 1;
      el('lockoutLeft').textContent = String(Math.max(left, 0));
      if (left <= 0) {
        stopLockoutTimer();
        boot();
      }
    }, 1000);
  }

  function stopLockoutTimer() {
    if (state.lockoutTimer) {
      clearInterval(state.lockoutTimer);
      state.lockoutTimer = null;
    }
    el('lockoutBlock').hidden = true;
  }

  async function doLock() {
    try {
      await api('/api/auth/lock', { method: 'POST', body: {} });
    } catch (e) {
      /* блокировка не прошла — всё равно уходим на экран входа */
    }
    saveSession('');
    state.unlocked = false;
    showScreen('unlock');
    refreshKeyfileBlock();
    statusOf(el('unlockStatus'), 'ok', 'Хранилище заблокировано');
    updateFooter();
  }

  async function openEdit(id) {
    const st = el('appStatus');
    hideStatus(st);
    state.editingId = id;
    el('entryModalTitle').textContent = id ? 'Редактирование записи' : 'Новая запись';
    el('entryPasswordHint').hidden = !id;
    el('btnEntryDelete').hidden = !id;
    el('entryTitle').value = '';
    el('entryLogin').value = '';
    el('entryPassword').value = '';
    el('entryUrl').value = '';
    el('entryTags').value = '';
    el('entryTotp').value = '';
    el('entryNote').value = '';
    el('genOpts').hidden = true;
    if (id) {
      try {
        const r = await api(`/api/entries/${id}`);
        const d = r.data;
        el('entryTitle').value = d.title || '';
        el('entryLogin').value = d.login || '';
        el('entryUrl').value = d.url || '';
        el('entryTags').value = d.tags || '';
        el('entryTotp').value = d.totp || '';
        el('entryNote').value = d.note || '';
      } catch (e) {
        statusOf(st, 'error', `Не удалось открыть запись: ${errMsg(e.code)}`);
        return;
      }
    }
    el('modalEntry').showModal();
  }

  async function saveEntry(e) {
    if (e) {
      e.preventDefault();
    }
    const st = el('appStatus');
    const totp = el('entryTotp').value.trim().toUpperCase();
    if (totp && !BASE32_RE.test(totp)) {
      el('entryTotp').value = totp;
      statusOf(st, 'error', 'TOTP-секрет должен быть base32 (A–Z, 2–7)');
      return;
    }
    const body = {
      title: el('entryTitle').value,
      login: el('entryLogin').value,
      url: el('entryUrl').value,
      note: el('entryNote').value,
      tags: el('entryTags').value,
      totp: totp,
    };
    const pw = el('entryPassword').value;
    if (pw) {
      body.password = pw;
    }
    const btn = el('btnEntrySave');
    btn.disabled = true;
    try {
      const path = state.editingId ? `/api/entries/${state.editingId}` : '/api/entries';
      await api(path, { method: 'POST', body });
      el('modalEntry').close();
      await loadEntries();
    } catch (err) {
      statusOf(st, 'error', `Не удалось сохранить: ${errMsg(err.code)}`);
    } finally {
      btn.disabled = false;
    }
  }

  async function deleteEntry() {
    if (!state.editingId) {
      return;
    }
    if (!window.confirm('Удалить запись без возможности восстановления?')) {
      return;
    }
    const st = el('appStatus');
    try {
      await api(`/api/entries/${state.editingId}`, {
        method: 'DELETE',
        body: { confirm: 'DELETE' },
      });
      el('modalEntry').close();
      await loadEntries();
    } catch (e) {
      statusOf(st, 'error', `Не удалось удалить: ${errMsg(e.code)}`);
    }
  }

  async function openView(id) {
    const st = el('appStatus');
    hideStatus(st);
    state.viewId = id;
    const body = el('viewBody');
    body.textContent = '';
    el('btnViewTotp').hidden = true;
    stopTotpTimer();
    let d;
    try {
      const r = await api(`/api/entries/${id}`);
      d = r.data;
    } catch (e) {
      statusOf(st, 'error', `Не удалось открыть запись: ${errMsg(e.code)}`);
      return;
    }
    el('viewTitle').textContent = d.title || '(без названия)';

    const row = (label, value, mono) => {
      if (!value) {
        return;
      }
      const wrap = h('div', 'view-row');
      wrap.appendChild(h('div', 'view-row__label', label));
      wrap.appendChild(h('p', `view-row__value${mono ? ' view-row__value--mono' : ''}`, value));
      body.appendChild(wrap);
    };

    row('Логин', d.login, true);
    if (d.hasPassword) {
      const wrap = h('div', 'view-row');
      wrap.appendChild(h('div', 'view-row__label', 'Пароль'));
      const val = h('p', 'view-row__value view-row__value--mono', '••••••••••••');
      wrap.appendChild(val);
      const actions = h('div', 'view-actions');
      const bReveal = h('button', 'btn btn--ghost btn--sm', 'Показать пароль');
      bReveal.type = 'button';
      bReveal.addEventListener('click', async () => {
        try {
          const r = await api(`/api/entries/${id}/secret`);
          val.textContent = r.data.password || '';
          bReveal.remove();
          const bCopy = h('button', 'btn btn--ghost btn--sm', 'Скопировать');
          bCopy.type = 'button';
          bCopy.addEventListener('click', () => copyText(r.data.password || '', bCopy));
          actions.appendChild(bCopy);
        } catch (e2) {
          statusOf(st, 'error', errMsg(e2.code));
        }
      });
      actions.appendChild(bReveal);
      wrap.appendChild(actions);
      body.appendChild(wrap);
    }
    if (d.url) {
      const wrap = h('div', 'view-row');
      wrap.appendChild(h('div', 'view-row__label', 'URL'));
      const a = h('a', 'view-row__value', d.url);
      a.href = d.url;
      a.rel = 'noopener noreferrer';
      a.target = '_blank';
      wrap.appendChild(a);
      body.appendChild(wrap);
    }
    const tagList = (d.tags || '').split(',').map((t) => t.trim()).filter(Boolean);
    if (tagList.length) {
      const wrap = h('div', 'view-row');
      wrap.appendChild(h('div', 'view-row__label', 'Теги'));
      const badges = h('div', 'entry-card__badges');
      for (const t of tagList) {
        badges.appendChild(h('span', 'badge', t));
      }
      wrap.appendChild(badges);
      body.appendChild(wrap);
    }
    row('Заметки', d.note, false);

    const totpBox = h('div', 'totp-box');
    totpBox.hidden = true;
    const totpCode = h('span', 'totp-code', '------');
    const totpMeta = h('span', 'totp-meta', '');
    totpBox.appendChild(totpCode);
    totpBox.appendChild(totpMeta);
    body.appendChild(totpBox);

    if (d.hasTotp) {
      el('btnViewTotp').hidden = false;
      el('btnViewTotp').onclick = () => {
        if (totpBox.hidden) {
          totpBox.hidden = false;
          refreshTotp(id, totpCode, totpMeta);
        } else {
          totpBox.hidden = true;
          stopTotpTimer();
        }
      };
      state.totpBox = totpBox;
    }

    el('modalView').showModal();
  }

  function stopTotpTimer() {
    if (state.totpTimer) {
      clearInterval(state.totpTimer);
      state.totpTimer = null;
    }
  }

  function refreshTotp(id, codeNode, metaNode) {
    stopTotpTimer();
    let left = 0;
    const tick = async () => {
      if (left <= 0) {
        try {
          const r = await api(`/api/entries/${id}/totp?t=${Math.floor(Date.now() / 1000)}`);
          codeNode.textContent = r.data.code || '------';
          left = r.data.expiresInSec || 30;
        } catch (e) {
          codeNode.textContent = '------';
          metaNode.textContent = errMsg(e.code);
          stopTotpTimer();
          return;
        }
      }
      left -= 1;
      metaNode.textContent = `обновится через ${Math.max(left, 0)} с`;
    };
    tick();
    state.totpTimer = setInterval(tick, 1000);
  }

  async function rekeyGenPhrase() {
    const btn = el('btnRekeyGen');
    btn.disabled = true;
    try {
      const r = await api('/api/auth/password');
      el('inputRekeyPassword').value = r.data.password || '';
      el('inputRekeyPassword').type = 'text';
      el('btnRekeyToggle').textContent = 'Скрыть';
    } catch (e) {
      statusOf(el('rekeyStatus'), 'error', errMsg(e.code));
    } finally {
      btn.disabled = false;
    }
  }

  function rekeyKeyfileHint() {
    const hasNew = el('inputRekeyKeyfile').files && el('inputRekeyKeyfile').files.length > 0;
    let text;
    if (state.keyfileRequired && hasNew) {
      text = 'Файл будет заменён на выбранный; для входа потребуется новый файл.';
    } else if (state.keyfileRequired && !hasNew) {
      text = 'Текущий ключевой файл останется прежним.';
    } else if (!state.keyfileRequired && hasNew) {
      text = 'После смены вход будет требовать этот файл.';
    } else {
      text = 'Вход по паролю без файла — как сейчас.';
    }
    el('rekeyKeyfileHint').textContent = text;
  }

  async function doRekey(e) {
    if (e) {
      e.preventDefault();
    }
    const st = el('rekeyStatus');
    hideStatus(st);
    const oldPw = el('inputRekeyOldPassword').value;
    if (!oldPw) {
      statusOf(st, 'error', 'Введите текущий мастер-пароль');
      return;
    }
    const pw = el('inputRekeyPassword').value;
    if (!pw) {
      statusOf(st, 'error', 'Введите новый мастер-пароль');
      return;
    }
    if (pw.length < 12) {
      statusOf(st, 'error', 'Мастер-пароль должен быть не короче 12 символов');
      return;
    }
    const btn = el('btnRekeySubmit');
    btn.disabled = true;
    try {
      const body = { old_password: oldPw, password: pw };
      if (state.keyfileRequired) {
        const cur = await readKeyfile(el('inputRekeyCurrentKeyfile'), state.keyFileMaxBytes);
        if (cur.absent) {
          statusOf(st, 'error', 'Выберите текущий ключевой файл');
          return;
        }
        body.keyfile_current = cur.b64;
      }
      const kf = await readKeyfile(el('inputRekeyKeyfile'), state.keyFileMaxBytes);
      if (!kf.absent) {
        body.keyfile_action = 'set';
        body.keyfile_new = kf.b64;
      }
      await submitJob('/api/auth/rekey', body);
      await fetchState();
      statusOf(st, 'ok', 'Мастер-пароль изменён. Хранилище перешифровано.');
      el('inputRekeyOldPassword').value = '';
      el('inputRekeyPassword').value = '';
      updateFooter();
      setTimeout(() => {
        el('modalRekey').close();
      }, 1200);
    } catch (err) {
      statusOf(st, 'error', errMsg(err.code));
    } finally {
      btn.disabled = false;
    }
  }

  async function doExport() {
    const st = el('appStatus');
    hideStatus(st);
    try {
      const r = await api('/api/export');
      const text = JSON.stringify(r.data, null, 2);
      const blob = new Blob([text], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      a.href = url;
      a.download = `passmanager-${stamp}.pmx1.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      statusOf(st, 'ok', `Выгружено записей: ${r.data.count}`);
    } catch (e) {
      statusOf(st, 'error', `Экспорт не удался: ${errMsg(e.code)}`);
    }
  }

  async function doImport(file) {
    const st = el('appStatus');
    hideStatus(st);
    if (!file) {
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch (e) {
      statusOf(st, 'error', 'Файл не является корректным JSON');
      return;
    }
    if (!parsed || parsed.format !== 'PMX1' || parsed.version !== 1 || !Array.isArray(parsed.entries)) {
      statusOf(st, 'error', 'Файл не в формате PMX1 версии 1');
      return;
    }
    const all = parsed.entries;
    if (all.length === 0) {
      statusOf(st, 'warn', 'В файле нет записей');
      return;
    }
    try {
      const imported = await importChunks(all, (done, total) =>
        statusOf(st, 'warn', `Импорт: ${done} из ${total}…`)
      );
      statusOf(st, 'ok', `Импортировано записей: ${imported} из ${all.length}`);
      await loadEntries();
    } catch (e) {
      statusOf(st, 'error', `Импорт прерван: ${errMsg(e.code)}. Уже добавлено: ${e.imported | 0}`);
      await loadEntries();
    }
  }

  async function importChunks(all, onProgress) {
    let imported = 0;
    for (let i = 0; i < all.length; i += IMPORT_BATCH) {
      const chunk = all.slice(i, i + IMPORT_BATCH);
      if (onProgress) {
        onProgress(Math.min(i + chunk.length, all.length), all.length);
      }
      try {
        const r = await api('/api/import', {
          method: 'POST',
          body: { format: 'PMX1', version: 1, entries: chunk },
        });
        imported += r.data.imported | 0;
      } catch (e) {
        e.imported = imported;
        throw e;
      }
    }
    return imported;
  }

  async function doReset(e) {
    if (e) {
      e.preventDefault();
    }
    const st = el('resetStatus');
    hideStatus(st);
    const btn = el('btnResetConfirm');
    btn.disabled = true;
    try {
      await submitJob('/api/auth/reset', { confirm: 'RESET' });
      saveSession('');
      el('inputResetConfirm').value = '';
      el('modalReset').close();
      await fetchState();
      showScreen('setup');
      updateFooter();
      statusOf(el('setupStatus'), 'ok', 'Устройство сброшено. Создайте новое хранилище.');
    } catch (err) {
      // session_required уже отработал через handleSessionExpired(): модалка
      // закрыта, сообщение показано на экране разблокировки — дублировать его
      // в закрытой модалке не нужно.
      if (err.code !== 'session_required') {
        statusOf(st, 'error', errMsg(err.code));
      }
      btn.disabled = el('inputResetConfirm').value !== 'RESET';
    } finally {
      if (el('modalReset').open) {
        btn.disabled = el('inputResetConfirm').value !== 'RESET';
      }
    }
  }

  const KDBX_LIMITS = { title: 47, login: 95, password: 159, url: 191, note: 399, tags: 127 };
  const KDBX_KEYFILE_MAX = 1048576;

  let kdbxLibPromise = null;

  function ensureKdbx() {
    if (!kdbxLibPromise) {
      kdbxLibPromise = new Promise((resolve, reject) => {
        const fail = () => {
          kdbxLibPromise = null;
          reject(new ApiError(0, 'kdbx_load_failed'));
        };
        const s1 = document.createElement('script');
        s1.src = 'kdbxweb.min.js';
        s1.onload = () => {
          const s2 = document.createElement('script');
          s2.src = 'kdbx-shim.js';
          s2.onload = () => {
            if (!window.kdbxweb || !window.kdbxweb.Kdbx) {
              fail();
              return;
            }
            resolve(window.kdbxweb);
          };
          s2.onerror = fail;
          document.head.appendChild(s2);
        };
        s1.onerror = fail;
        document.head.appendChild(s1);
      });
    }
    return kdbxLibPromise;
  }

  function kdbxWalkEntries(group, path, acc) {
    (group.entries || []).forEach((entry) => acc.push({ entry, path }));
    (group.groups || []).forEach((g) => {
      kdbxWalkEntries(g, path.concat([String(g.name || '')]), acc);
    });
  }

  function kdbxField(fields, key) {
    const v = fields.get(key);
    if (v == null) {
      return '';
    }
    if (typeof v === 'string') {
      return v;
    }
    if (typeof v.getText === 'function') {
      return v.getText();
    }
    return '';
  }

  function kdbxToPmx(db) {
    const found = [];
    kdbxWalkEntries(db.getDefaultGroup(), [], found);
    const entries = [];
    const skipped = [];
    let truncated = 0;
    for (const item of found) {
      const f = item.entry.fields;
      const title = kdbxField(f, 'Title');
      const login = kdbxField(f, 'UserName');
      const password = kdbxField(f, 'Password');
      const url = kdbxField(f, 'URL');
      let note = kdbxField(f, 'Notes');
      const tagParts = kdbxField(f, 'Tags')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const pathTag = item.path.filter(Boolean).join('/');
      if (pathTag) {
        tagParts.push(pathTag);
      }
      let tags = tagParts.join(',');
      const over = [];
      if (title.length > KDBX_LIMITS.title) {
        over.push('заголовок');
      }
      if (login.length > KDBX_LIMITS.login) {
        over.push('логин');
      }
      if (password.length > KDBX_LIMITS.password) {
        over.push('пароль');
      }
      if (url.length > KDBX_LIMITS.url) {
        over.push('URL');
      }
      if (over.length) {
        skipped.push({ title: title || login || url || '(без имени)', reason: over.join(', ') });
        continue;
      }
      if (note.length > KDBX_LIMITS.note) {
        note = note.slice(0, KDBX_LIMITS.note);
        truncated += 1;
      }
      if (tags.length > KDBX_LIMITS.tags) {
        tags = tags.slice(0, KDBX_LIMITS.tags);
      }
      const finalTitle = title || login || url || '(без имени)';
      if (!title && !login && !password && !url && !note && !tags) {
        skipped.push({ title: '(пустая запись)', reason: 'пустая' });
        continue;
      }
      let totp = '';
      const otp = kdbxField(f, 'otp');
      if (otp) {
        const secret = otp.indexOf('otpauth://') === 0
          ? (function () {
              try {
                return new URL(otp).searchParams.get('secret') || '';
              } catch (err) {
                return '';
              }
            })()
          : otp;
        const norm = secret.toUpperCase();
        if (BASE32_RE.test(norm)) {
          totp = norm;
        }
      }
      entries.push({ title: finalTitle, login, password, url, note, tags, totp });
    }
    return { entries, skipped, truncated };
  }

  const kdbxImportState = { entries: [], skipped: [], truncated: 0, phase: 1 };

  function kdbxImportPhase(n) {
    kdbxImportState.phase = n;
    el('kdbxImportPhase1').hidden = n !== 1;
    el('kdbxImportPhase2').hidden = n !== 2;
    el('btnKdbxImportBack').hidden = n !== 2;
    const next = el('btnKdbxImportNext');
    if (n === 1) {
      next.textContent = 'Открыть базу';
      next.disabled = false;
    } else {
      const cnt = kdbxImportState.entries.length;
      next.textContent = `Импортировать (${cnt})`;
      next.disabled = cnt === 0;
    }
  }

  function kdbxImportReset() {
    kdbxImportState.entries = [];
    kdbxImportState.skipped = [];
    kdbxImportState.truncated = 0;
    el('inputKdbxFile').value = '';
    el('inputKdbxPassword').value = '';
    el('inputKdbxKeyfile').value = '';
    el('kdbxImportList').textContent = '';
    hideStatus(el('kdbxImportStatus'));
    hideStatus(el('kdbxImportStatus2'));
    kdbxImportPhase(1);
  }

  async function kdbxOpenPreview() {
    const st = el('kdbxImportStatus');
    hideStatus(st);
    const file = el('inputKdbxFile').files[0];
    if (!file) {
      statusOf(st, 'error', errMsg('kdbx_no_file'));
      return;
    }
    const pw = el('inputKdbxPassword').value;
    const kfFile = el('inputKdbxKeyfile').files[0];
    const btn = el('btnKdbxImportNext');
    btn.disabled = true;
    statusOf(st, 'warn', 'Открытие базы… KDF может занять несколько секунд');
    try {
      const K = await ensureKdbx();
      let kfBuf;
      if (kfFile) {
        if (kfFile.size > KDBX_KEYFILE_MAX) {
          throw new ApiError(400, 'kdbx_open_failed');
        }
        kfBuf = await kfFile.arrayBuffer();
      }
      const creds = new K.Credentials(K.ProtectedValue.fromString(pw), kfBuf);
      const buf = await file.arrayBuffer();
      const db = await K.Kdbx.load(buf, creds);
      const res = kdbxToPmx(db);
      kdbxImportState.entries = res.entries;
      kdbxImportState.skipped = res.skipped;
      kdbxImportState.truncated = res.truncated;
      const summary = [`Найдено записей: ${res.entries.length}`];
      if (res.truncated) {
        summary.push(`заметок усечено до ${KDBX_LIMITS.note} симв.: ${res.truncated}`);
      }
      el('kdbxImportSummary').textContent = summary.join(' · ');
      const list = el('kdbxImportList');
      list.textContent = '';
      res.entries.slice(0, 30).forEach((item) => {
        const b = document.createElement('span');
        b.className = 'badge';
        b.textContent = item.title;
        list.appendChild(b);
      });
      if (res.entries.length > 30) {
        const b = document.createElement('span');
        b.className = 'badge';
        b.textContent = `…ещё ${res.entries.length - 30}`;
        list.appendChild(b);
      }
      const skip = el('kdbxImportSkip');
      if (res.skipped.length) {
        const detail = res.skipped
          .slice(0, 5)
          .map((s) => `${s.title} — ${s.reason}`)
          .join('; ');
        skip.hidden = false;
        skip.textContent = `Пропущено записей: ${res.skipped.length}${res.skipped.length > 5 ? '' : ` (${detail})`}. Причина: поле длиннее лимита хранилища.`;
      } else {
        skip.hidden = true;
        skip.textContent = '';
      }
      hideStatus(st);
      kdbxImportPhase(2);
      if (res.entries.length === 0 && res.skipped.length === 0) {
        statusOf(el('kdbxImportStatus2'), 'warn', 'В базе нет записей');
      }
    } catch (err) {
      statusOf(
        st,
        'error',
        err instanceof ApiError && err.code !== 'kdbx_open_failed'
          ? errMsg(err.code)
          : errMsg('kdbx_open_failed')
      );
      kdbxImportState.entries = [];
      btn.disabled = false;
    }
  }

  async function kdbxDoImport() {
    const st = el('kdbxImportStatus2');
    hideStatus(st);
    const all = kdbxImportState.entries;
    if (!all.length) {
      return;
    }
    const btn = el('btnKdbxImportNext');
    btn.disabled = true;
    try {
      const imported = await importChunks(all, (done, total) =>
        statusOf(st, 'warn', `Импорт: ${done} из ${total}…`)
      );
      statusOf(st, 'ok', `Импортировано: ${imported} из ${all.length}`);
      await loadEntries();
      setTimeout(() => el('modalKdbxImport').close(), 1200);
    } catch (e) {
      statusOf(st, 'error', `Импорт прерван: ${errMsg(e.code)}. Уже добавлено: ${e.imported | 0}`);
      btn.disabled = false;
      await loadEntries();
    }
  }

  async function doExportKdbx(e) {
    if (e) {
      e.preventDefault();
    }
    const st = el('kdbxExportStatus');
    hideStatus(st);
    const pw = el('inputKdbxExportPassword').value;
    if (!pw) {
      statusOf(st, 'error', errMsg('kdbx_no_password'));
      return;
    }
    const btn = el('btnKdbxExportSubmit');
    btn.disabled = true;
    statusOf(st, 'warn', 'Формирование файла…');
    try {
      const K = await ensureKdbx();
      const r = await api('/api/export');
      const pmx = r.data || {};
      const creds = new K.Credentials(K.ProtectedValue.fromString(pw));
      const db = K.Kdbx.create(creds, '/PassManager');
      const root = db.getDefaultGroup();
      const items = Array.isArray(pmx.entries) ? pmx.entries : [];
      for (const it of items) {
        const en = db.createEntry(root);
        en.fields.set('Title', it.title || '');
        en.fields.set('UserName', it.login || '');
        en.fields.set('Password', K.ProtectedValue.fromString(it.password || ''));
        en.fields.set('URL', it.url || '');
        en.fields.set('Notes', it.note || '');
        if (it.tags) {
          en.fields.set('Tags', it.tags);
        }
        if (it.totp) {
          en.fields.set(
            'otp',
            `otpauth://totp/${encodeURIComponent(it.title || 'entry')}?secret=${it.totp}&digits=6&period=30`
          );
        }
      }
      const saved = await db.save();
      const blob = new Blob([saved], { type: 'application/x-keepass2' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'passmanager.kdbx';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      statusOf(st, 'ok', `Файл .kdbx сформирован: ${items.length} записей`);
      el('inputKdbxExportPassword').value = '';
      setTimeout(() => el('modalKdbxExport').close(), 1000);
    } catch (err) {
      statusOf(
        st,
        'error',
        err instanceof ApiError && err.code !== 'kdbx_make_failed' && !err.code.startsWith('http_')
          ? errMsg(err.code)
          : errMsg('kdbx_make_failed')
      );
    } finally {
      btn.disabled = false;
    }
  }

  function wire() {
    el('btnProvision').addEventListener('click', doProvision);
    el('btnCopyMaster').addEventListener('click', () => copyText(state.masterShown, el('btnCopyMaster')));
    el('btnHideMaster').addEventListener('click', toggleMaster);
    el('btnDoneMaster').addEventListener('click', async () => {
      el('masterBlock').hidden = true;
      state.masterShown = '';
      el('masterPassword').value = '';
      await enterApp();
    });

    el('formUnlock').addEventListener('submit', doUnlock);
    el('btnUnlockRetry').addEventListener('click', boot);

    el('btnLock').addEventListener('click', doLock);
    el('btnRefresh').addEventListener('click', loadEntries);
    el('btnNew').addEventListener('click', () => openEdit(null));
    el('searchInput').addEventListener('input', render);

    el('btnExport').addEventListener('click', doExport);
    el('inputImportFile').addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      e.target.value = '';
      doImport(file);
    });

    el('btnEntryClose').addEventListener('click', () => el('modalEntry').close());
    el('btnEntryCancel').addEventListener('click', () => el('modalEntry').close());
    el('formEntry').addEventListener('submit', saveEntry);
    el('btnEntryDelete').addEventListener('click', deleteEntry);
    el('btnGenPass').addEventListener('click', () => {
      el('genOpts').hidden = false;
      el('entryPassword').value = generatePassword();
      el('entryPassword').type = 'text';
      el('btnTogglePass').textContent = 'Скрыть';
    });
    for (const id of ['genUpper', 'genLower', 'genDigits', 'genSym', 'genLen']) {
      el(id).addEventListener('input', () => {
        el('genLenVal').textContent = el('genLen').value;
        if (!el('genOpts').hidden) {
          el('entryPassword').value = generatePassword();
        }
      });
    }
    el('btnGenPhrase').addEventListener('click', async () => {
      const btn = el('btnGenPhrase');
      btn.disabled = true;
      try {
        const r = await api('/api/auth/password');
        el('entryPassword').value = r.data.password || '';
        el('entryPassword').type = 'text';
        el('btnTogglePass').textContent = 'Скрыть';
      } catch (e) {
        statusOf(el('appStatus'), 'error', errMsg(e.code));
      } finally {
        btn.disabled = false;
      }
    });
    el('btnTogglePass').addEventListener('click', () => {
      const inp = el('entryPassword');
      if (inp.type === 'password') {
        inp.type = 'text';
        el('btnTogglePass').textContent = 'Скрыть';
      } else {
        inp.type = 'password';
        el('btnTogglePass').textContent = 'Показать';
      }
    });
    el('btnCopyPass').addEventListener('click', () => copyText(el('entryPassword').value, el('btnCopyPass')));

    el('btnViewClose').addEventListener('click', () => el('modalView').close());
    el('btnViewClose2').addEventListener('click', () => el('modalView').close());
    el('btnViewEdit').addEventListener('click', () => {
      const id = state.viewId;
      el('modalView').close();
      openEdit(id);
    });
    el('modalView').addEventListener('close', () => {
      stopTotpTimer();
      el('viewBody').textContent = '';
      state.viewId = null;
    });

    el('btnRekey').addEventListener('click', () => {
      el('inputRekeyOldPassword').value = '';
      el('inputRekeyPassword').value = '';
      el('inputRekeyPassword').type = 'password';
      el('btnRekeyToggle').textContent = 'Показать';
      el('inputRekeyCurrentKeyfile').value = '';
      el('inputRekeyKeyfile').value = '';
      el('rekeyCurrentKeyfileBlock').hidden = !state.keyfileRequired;
      hideStatus(el('rekeyStatus'));
      rekeyKeyfileHint();
      el('modalRekey').showModal();
    });
    el('inputRekeyKeyfile').addEventListener('change', rekeyKeyfileHint);
    el('btnRekeyClose').addEventListener('click', () => el('modalRekey').close());
    el('btnRekeyCancel').addEventListener('click', () => el('modalRekey').close());
    el('formRekey').addEventListener('submit', doRekey);
    el('btnRekeyGen').addEventListener('click', rekeyGenPhrase);
    el('btnRekeyToggle').addEventListener('click', () => {
      const inp = el('inputRekeyPassword');
      if (inp.type === 'password') {
        inp.type = 'text';
        el('btnRekeyToggle').textContent = 'Скрыть';
      } else {
        inp.type = 'password';
        el('btnRekeyToggle').textContent = 'Показать';
      }
    });

    el('btnReset').addEventListener('click', () => {
      el('inputResetConfirm').value = '';
      el('btnResetConfirm').disabled = true;
      hideStatus(el('resetStatus'));
      el('modalReset').showModal();
    });
    el('inputResetConfirm').addEventListener('input', (e) => {
      el('btnResetConfirm').disabled = e.target.value !== 'RESET';
    });
    el('btnResetClose').addEventListener('click', () => el('modalReset').close());
    el('btnResetCancel').addEventListener('click', () => el('modalReset').close());
    el('formReset').addEventListener('submit', doReset);

    el('btnExportKdbx').addEventListener('click', () => {
      el('inputKdbxExportPassword').value = '';
      hideStatus(el('kdbxExportStatus'));
      el('modalKdbxExport').showModal();
    });
    el('btnKdbxExportClose').addEventListener('click', () => el('modalKdbxExport').close());
    el('btnKdbxExportCancel').addEventListener('click', () => el('modalKdbxExport').close());
    el('formKdbxExport').addEventListener('submit', doExportKdbx);
    el('btnKdbxExportGen').addEventListener('click', () => {
      el('inputKdbxExportPassword').value = generatePassword();
    });
    el('btnKdbxExportToggle').addEventListener('click', () => {
      const inp = el('inputKdbxExportPassword');
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      el('btnKdbxExportToggle').textContent = show ? 'Скрыть' : 'Показать';
    });

    el('inputImportKdbxFile').addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      e.target.value = '';
      if (!file) {
        return;
      }
      kdbxImportReset();
      const dt = new DataTransfer();
      dt.items.add(file);
      el('inputKdbxFile').files = dt.files;
      el('modalKdbxImport').showModal();
      el('inputKdbxPassword').focus();
    });
    el('btnKdbxImportClose').addEventListener('click', () => el('modalKdbxImport').close());
    el('btnKdbxImportCancel').addEventListener('click', () => el('modalKdbxImport').close());
    el('btnKdbxImportBack').addEventListener('click', () => kdbxImportPhase(1));
    el('formKdbxImport').addEventListener('submit', (ev) => {
      ev.preventDefault();
      if (kdbxImportState.phase === 1) {
        kdbxOpenPreview();
      } else {
        kdbxDoImport();
      }
    });
    el('modalKdbxImport').addEventListener('close', kdbxImportReset);
  }

  document.addEventListener('DOMContentLoaded', () => {
    wire();
    boot();
  });
})();
