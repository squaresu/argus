// Argus page: pick what to scan and which tools, follow the job, show the report.
const TOKEN = document.querySelector('meta[name=argus-token]').content;

// words in the page's language: the server puts {lang, html, catalog} in <script id="i18n">.
// t('有 {n} 項', { n }) looks the source sentence up (falling back to it), picks one/other by n, fills {name}s.
const I18N = (() => {
  try { return JSON.parse(document.getElementById('i18n').textContent); } catch { return { lang: 'zh-TW', html: 'zh-Hant', catalog: {} }; }
})();
function t(text, kw = {}) {
  let found = (I18N.catalog || {})[text];
  if (found && typeof found === 'object') found = kw.n === 1 && found.one ? found.one : found.other;
  if (typeof found !== 'string' || !found) found = text;
  const fill = (s) => s.replace(/\{(\w+)\}/g, (m, k) => (k in kw ? String(kw[k]) : m));
  // a translation naming a placeholder the sentence doesn't have shouldn't break the page
  const names = (s) => (s.match(/\{\w+\}/g) || []).filter((m) => !(m.slice(1, -1) in kw));
  return fill(names(found).length && !names(text).length ? text : found);
}
const join = (items) => items.join(t('、'));
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const VERDICT_CLASS = { SAFE: 'safe', CAUTION: 'caution', DO_NOT_INSTALL: 'danger', ERROR: 'error' };
const VERDICT_ZH = { SAFE: t('安全'), CAUTION: t('注意'), DO_NOT_INSTALL: t('不建議安裝'), ERROR: t('沒掃完') };
const ADVICE_CLASS = { ok: 'safe', ask: 'caution', no: 'danger' };
const adviceWord = (a, installed) => (a === 'ask' ? t('先問人') : installed ? { ok: t('可以繼續用'), no: t('不建議用') }[a] : { ok: t('可以裝'), no: t('不建議裝') }[a]);

let state = null;
let picked = { folder: '', zip: '' };
let checked = null;           // scanner ids the person ticked (null until the list first loads)
let installing = null;        // { id, job } while a scanner installs

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: { 'X-Argus-Token': TOKEN, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || t('發生錯誤（{status}）', { status: res.status }));
  return data;
}

// 6. a question in Argus's own dialog (the browser's confirm box looks like a web page's warning)
function ask(message, { title = t('確定嗎？'), ok = t('確定'), danger = false } = {}) {
  const d = $('#confirm');
  $('#confirm-title').textContent = title;
  $('#confirm-text').textContent = message;
  $('#confirm-ok').textContent = ok;
  $('#confirm-ok').classList.toggle('danger', danger);
  d.returnValue = '';
  d.showModal();
  return new Promise((resolve) => d.addEventListener('close', () => resolve(d.returnValue === 'ok'), { once: true }));
}

// 5. an error stays on screen, with a way to copy it, until the person closes it
function showError(message) {
  $('#error-text').textContent = message;
  $('#error-box').hidden = false;
  $('#error-box').scrollIntoView({ block: 'nearest' });
}

function toast(text, ms = 4000) {
  const el = document.createElement('div');
  el.className = 'toast'; el.textContent = text;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

function show(view) {
  for (const v of ['form', 'progress', 'report']) $(`#view-${v}`).hidden = v !== view;
  $('#hero').hidden = view !== 'form';
  document.body.classList.toggle('report-mode', view === 'report');
  window.scrollTo(0, 0);
}

const kind = () => document.querySelector('input[name=kind]:checked').value;

// --- the form ---
function renderTarget() {
  const k = kind();
  $('#detail-claude').hidden = k !== 'claude';
  $('#detail-pick').hidden = k !== 'folder' && k !== 'zip';
  $('#detail-github').hidden = k !== 'github';
  $('#detail-mcp').hidden = k !== 'mcp';
  $('#tools-card').hidden = k === 'mcp';   // the MCP check is Argus's own; no scanners involved
  if (k === 'folder' || k === 'zip') {
    $('#pick').textContent = k === 'folder' ? t('選擇資料夾…') : t('選擇 zip 檔…');
    $('#picked').textContent = picked[k] || t('還沒選擇');
    $('#picked').classList.toggle('set', !!picked[k]);
  }
  if (k === 'github') $('#url').focus();
  validate();
}

// a list rebuilt from new state keeps keyboard focus on the same control (or its row's nearest one)
function keepFocus(box, build) {
  const el = document.activeElement;
  const attrs = ['data-id', 'data-install', 'data-del', 'data-file'];
  const at = el && box.contains(el) ? attrs.find((a) => el.hasAttribute(a)) : null;
  const value = at ? el.getAttribute(at) : null;
  build();
  if (at) {
    const again = [...box.querySelectorAll(`[${at}]`)].find((x) => x.getAttribute(at) === value);
    (again || box.querySelector('button:not([disabled]), input, [tabindex="0"]'))?.focus();
  }
}

function renderScanners() { keepFocus($('#scanners'), drawScanners); }
function drawScanners() {
  const list = state.scanners;
  if (checked === null) checked = new Set(list.filter((s) => s.default_on).map((s) => s.id));
  $('#scanners').innerHTML = list.map((s) => {
    const busy = installing && installing.id === s.id;
    const button = (label) => `<button class="btn" type="button" data-install="${esc(s.id)}" ${installing ? 'disabled' : ''}>${esc(label)}</button>`;
    const right = busy
      ? `<span class="installing"><span class="spinner"></span><span id="inst-text">${esc(t('安裝中…'))}</span></span>`
      : s.status === 'ok' && s.outdated ? `<span class="fix"><span class="newer" title="${esc(t('現在的版本：{version}', { version: s.version }))}">${esc(t('可更新到 {version}', { version: s.newest }))}</span>${button(t('更新'))}</span>`
      : s.status === 'ok' ? `<span class="badge ok" title="${esc(s.version)}">${esc(t('已安裝'))}</span>`
      : s.status === 'checking' ? `<span class="badge" title="${esc(t('正在確認這個工具能不能正常啟動'))}">${esc(t('確認中…'))}</span>`
      : s.status === 'broken' ? `<span class="fix"><span class="badge bad">${esc(t('打不開'))}</span>${button(t('重新安裝'))}</span>`
      : button(t('安裝'));
    return `<li class="scanner ${s.installed ? '' : 'off'}">
      <input type="checkbox" data-id="${esc(s.id)}" ${s.installed && checked.has(s.id) ? 'checked' : ''} ${s.installed ? '' : 'disabled'} aria-label="${esc(s.name)}">
      <div><span class="name">${esc(s.name)}</span><span class="vendor">${esc(s.vendor)} · ${esc(s.license)}</span><p>${esc(s.summary)}</p></div>
      ${right}</li>`;
  }).join('');
  renderToolsCard();
  validate();
}

let toolsOpen = false;    // the person opened the folded tool list
function renderToolsCard() {
  const list = state.scanners;
  const missing = list.filter((s) => s.status === 'missing' || s.status === 'broken');
  const outdated = list.filter((s) => s.status === 'ok' && s.outdated);
  const ready = !missing.length && !list.some((s) => s.status === 'checking');
  // 全部安裝 for what's missing; once everything is there, 全部更新 for what has a newer version
  const todo = missing.length ? missing : outdated;
  const all = $('#install-all');
  all.hidden = !todo.length || !!installing;
  all.dataset.ids = todo.map((s) => s.id).join(',');
  all.textContent = missing.length
    ? t('全部安裝（{n} 個，約 {minutes} 分鐘）', { n: missing.length, minutes: Math.max(1, missing.length * 2) })
    : t('全部更新（{n} 個）', { n: outdated.length });
  // folded: one line saying what will be used; 調整 opens the list
  const folded = ready && !toolsOpen && !installing;
  const used = list.filter((s) => s.installed && checked.has(s.id)).length;
  $('#tools-summary').hidden = !ready;
  $('#tools-summary').setAttribute('aria-expanded', String(!folded));
  $('#tools-detail').hidden = folded;
  $('#tools-summary-text').textContent = (used === list.length ? t('{n} 個工具都裝好了，全部會用來檢查', { n: list.length })
    : t('會用 {used} / {n} 個工具檢查', { used, n: list.length }))
    + (outdated.length ? t('　·　{n} 個有新版', { n: outdated.length }) : '');
  $('#tools-summary-link').textContent = folded ? t('調整') : t('收起');
}

function installAll() {
  if (installing) return;
  const ids = $('#install-all').dataset.ids.split(',').filter(Boolean);
  return once(async () => {
    try {
      const job = await api('/api/install-all', { ids });
      watchInstall(job.target, job.id, ids);
    } catch (err) { showError(err.message); }
  });
}

// "有新版本" notice; 稍後再說 hides it for that version only
function renderUpdate() {
  const u = state.update || {};
  let dismissed = '';
  try { dismissed = localStorage.getItem('argus-update-dismissed') || ''; } catch {}
  $('#update').hidden = !((u.newer && u.latest !== dismissed) || state.updating || updating);
  $('#update-now').hidden = !u.auto;
  $('#about-open').classList.toggle('has-update', !!u.newer);
  $('#update-why').hidden = u.auto || !u.why_manual;
  $('#update-why').textContent = u.why_manual || '';
  if (state.updating && !updating) watchUpdate(state.updating);
  $('#update-version').textContent = u.latest || '';
  $('#update-current').textContent = state.app.version;
  document.querySelectorAll('.update-download').forEach((a) => { a.href = u.url || 'https://github.com/squaresu/argus/releases/latest'; });
  $('#about-update').textContent = !u.checked ? t('正在檢查有沒有新版本…')
    : u.newer ? t('有新版本 {version} 可以更新', { version: u.latest })
    : u.latest ? t('已經是最新版')
    : u.failed ? t('沒辦法檢查新版本：{err}', { err: u.error || t('連不上 GitHub') }) : '';
  // the check runs in the background right after Argus starts; look again until it has answered
  clearTimeout(renderUpdate.timer);
  if (!u.checked) renderUpdate.timer = setTimeout(() => loadState().catch(() => {}), 1000);
}

let updating = null;

// 和 Claude 一起用
function renderCompanion() {
  const c = state.companion || {};
  $('#skill-toggle').checked = !!c.skill;
  $('#auto-toggle').checked = !!c.autocheck;
  $('#auto-toggle').disabled = !c.autocheck_supported;
  const el = $('#auto-text');
  el.dataset.mac = el.dataset.mac || el.textContent;
  el.textContent = c.autocheck_supported ? el.dataset.mac
    : t('自動檢查目前只有 Mac 版，Windows 版之後會加上。打開 Argus 時的「重新檢查提醒」一樣會告訴你哪些技能有更新。');
}
async function toggleCompanion(el, path, question) {
  const on = el.checked;
  if (on && question && !(await ask(question, { title: t('開啟自動檢查？'), ok: t('開啟') }))) { el.checked = false; return; }
  el.disabled = true;
  try {
    const r = await api(path, { on });
    toast(path === '/api/claude-skill'
      ? (r.skill ? t('已經加到 Claude ✓ 下次在 Claude Code 說「幫我檢查這個技能」就會用 Argus。') : t('已經從 Claude 移除。'))
      : (r.autocheck ? t('已開啟自動檢查 ✓') : t('已關閉自動檢查。')), 6000);
  } catch (err) { el.checked = !on; showError(err.message); }
  el.disabled = false;
  loadState().catch(() => {});
}

// 「該重新檢查了」: a skill changed or arrived since its last scan, or hasn't been scanned for a month
function renderReminder() {
  const r = state.reminder || {};
  let dismissed = '';
  try { dismissed = localStorage.getItem('argus-remind-dismissed') || ''; } catch {}
  const [sig, until] = dismissed.split('|');
  const snoozed = sig === r.signature && Date.now() < +until;
  $('#remind').hidden = !r.checked || !r.show || snoozed || !!state.running;
  if ($('#remind').hidden) {
    clearTimeout(renderReminder.timer);
    if (!r.checked) renderReminder.timer = setTimeout(() => loadState().catch(() => {}), 2000);
    return;
  }
  const names = (list, count) => (count > list.length ? t('{names} 等 {n} 個', { names: join(list), n: count }) : join(list));
  const parts = [];
  if (r.changed_count) parts.push(t('{n} 個在上次檢查後有更新（{names}）', { n: r.changed_count, names: names(r.changed, r.changed_count) }));
  if (r.new_count && !r.never) parts.push(t('{n} 個是新裝的（{names}）', { n: r.new_count, names: names(r.new, r.new_count) }));
  if (r.stale_count) parts.push(t('{n} 個超過 30 天沒檢查', { n: r.stale_count }));
  $('#remind-title').textContent = r.never ? t('還沒檢查過這台電腦上的 Claude 技能（共 {n} 個）', { n: r.total }) : t('你的 Claude 技能該重新檢查了');
  $('#remind-text').textContent = r.never ? t('檢查一次，之後技能有更新時 Argus 會提醒你。') : t('其中 {parts}。', { parts: parts.join(t('，')) });
}

async function startUpdate() {
  if (!(await ask(t('Argus 會下載新版、換掉現在這一版，再自動重新打開。正在進行的工作會被中斷。'),
    { title: t('更新到 Argus {version}？', { version: state.update.latest }), ok: t('立即更新') }))) return;
  try { watchUpdate((await api('/api/update', {})).id); } catch (err) { showError(err.message); }
}

async function watchUpdate(jobId) {
  updating = jobId;
  $('#update').hidden = false;
  $('#update-actions').hidden = true;
  $('#update-progress').hidden = false;
  for (;;) {
    await sleep(1000);
    let j;
    try { j = await api(`/api/job/${jobId}`); } catch { continue; }
    $('#update-text').textContent = j.current;
    if (j.status === 'running') continue;
    updating = null;
    $('#update-progress').hidden = true;
    $('#update-actions').hidden = false;
    if (j.status === 'error') { showError(j.error); return; }
    try {
      await api('/api/relaunch', {});
      $('#updated').showModal();
    } catch (err) {
      $('#updated-title').textContent = t('更新完成，請重新打開 Argus');
      $('#updated-text').textContent = t('新版已經裝好了。關掉這個分頁，再從「應用程式」點兩下 Argus 就好。');
      $('#updated').showModal();
    }
    return;
  }
}

const TRASH = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/></svg>';
// the report's conclusion in a few words, like the line at the top of the report
// a GitHub link as owner/repo (plus the folder inside), without tracking strings like ?fbclid=…
function sourceName(title) {
  const m = /^https?:\/\/(?:www\.)?github\.com\/([^?#]+)/.exec(title || '');
  return m ? m[1].replace(/\/(?:tree|blob)\/[^/]+/, '').replace(/\.git$|\/+$/g, '') : title;
}
function historyLine(r) {
  const a = r.advice;
  if (!a) return sourceName(r.title);
  if (r.skills === 1) return adviceWord(a.no ? 'no' : a.ask ? 'ask' : 'ok', r.installed);
  const used = r.installed;   // 用 for skills already installed, 裝 for ones not yet installed
  if (a.no && a.ask) return used ? t('{n} 個不建議用、{ask} 個先問人', { n: a.no, ask: a.ask }) : t('{n} 個不建議裝、{ask} 個先問人', { n: a.no, ask: a.ask });
  if (a.no) return used ? t('{n} 個不建議用', { n: a.no }) : t('{n} 個不建議裝', { n: a.no });
  if (a.ask) return used ? t('{n} 個先問人，其他可以繼續用', { n: a.ask }) : t('{n} 個先問人，其他可以裝', { n: a.ask });
  return used ? t('全部可以繼續用') : t('全部可以裝');
}

let historyAll = false;
const historyHome = document.createComment('history card');   // where the card sits with few reports
$('#history-card').after(historyHome);
function renderHistory() {
  const had = $('#history').contains(document.activeElement);
  keepFocus($('#history'), drawHistory);
  // the report just deleted had focus: go to the next one, or the list's card
  if (had && !$('#history').contains(document.activeElement)) ($('#history li') || $('#start'))?.focus();
}
function drawHistory() {
  const h = state.history || [];
  $('#history-card').hidden = !h.length;
  document.body.classList.toggle('returning', h.length > 0);
  // used a few times: the reports come first, three of them, with the rest a click away
  const upFront = h.length >= 3;
  const card = $('#history-card');
  if (upFront && card.nextElementSibling !== $('#targets-card')) $('#targets-card').before(card);
  if (!upFront && card.nextSibling !== historyHome) historyHome.before(card);
  const shown = upFront && !historyAll ? h.slice(0, 3) : h.slice(0, 12);
  $('#history-more').hidden = !upFront || h.length <= 3;
  $('#history-more').textContent = historyAll ? t('收起') : t('看全部 {n} 份', { n: Math.min(h.length, 12) });
  $('#history').innerHTML = shown.map((r) => {
    const dots = r.advice
      ? ['no', 'ask', 'ok'].filter((a) => r.advice[a]).map((a) => `<span class="dot ${ADVICE_CLASS[a]}" title="${adviceWord(a, r.installed)}">${r.advice[a]}</span>`).join('')
      : ['DO_NOT_INSTALL', 'CAUTION', 'SAFE', 'ERROR']
        .filter((v) => r.counts?.[v]).map((v) => `<span class="dot ${VERDICT_CLASS[v]}" title="${VERDICT_ZH[v]}">${r.counts[v]}</span>`).join('');
    // the MCP report's title: in the language it was made in (older reports: always Chinese)
    const isMcp = r.title === t('我的 MCP 伺服器')
      || r.title === '我的 MCP 伺服器';   // i18n: keep (a stored title from before Argus spoke other languages)
    const count = isMcp ? t('{n} 個 MCP 伺服器', { n: r.skills }) : t('{n} 個技能', { n: r.skills });
    const line = historyLine(r);
    const source = sourceName(r.title);
    // an older report has no conclusion line: its source is the title, so don't say it twice
    const sub = [line === source ? '' : source, r.when, count].filter(Boolean).join(' · ');
    return `<li data-file="${esc(r.file)}" tabindex="0" role="button" aria-label="${esc(t('打開報告：{name}，{when}', { name: line, when: r.when }))}" title="${esc(r.title)}">
      <div class="h-main"><span class="h-title">${esc(line)}</span>
        <span class="h-when">${esc(sub)}</span></div>
      <span class="dots">${dots}</span>
      <button class="h-del" type="button" data-del="${esc(r.file)}" aria-label="${esc(t('刪除這份報告'))}" title="${esc(t('刪除這份報告'))}">${TRASH}</button></li>`;
  }).join('');
}

// before a scan: how many skills and roughly how long (asked again when the target or the tools change)
// short: 約 instead of 大約, where the sentence already says 預估
const minutes = (s, short = false) => (s < 60 ? t('不到 1 分鐘')
  : s < 3600 ? (short ? t('約 {n} 分鐘', { n: Math.round(s / 60) }) : t('大約 {n} 分鐘', { n: Math.round(s / 60) }))
  : (short ? t('約 {n} 小時', { n: (s / 3600).toFixed(1) }) : t('大約 {n} 小時', { n: (s / 3600).toFixed(1) })));
async function renderEstimate() {
  const k = kind();
  const el = $('#start-estimate');
  const tools = state ? state.scanners.filter((s) => s.installed && checked?.has(s.id)).map((s) => s.id) : [];
  if (!state || k === 'mcp' || !tools.length || ((k === 'folder' || k === 'zip') && !picked[k])) { renderEstimate.ask = null; el.textContent = ''; return; }
  const ask = `${k}|${picked[k] || ''}|${tools.join(',')}`;
  renderEstimate.ask = ask;
  try {
    const e = await api('/api/estimate', { kind: k, value: picked[k] || '', scanners: tools });
    if (renderEstimate.ask !== ask) return;   // the choice changed while asking
    el.textContent = e.skills === null
      ? t('下載後才知道有幾個技能；每個技能{time}。', { time: minutes(e.per_skill) })
      : e.skills ? t('共 {n} 個技能，預估{time}。', { n: e.skills, time: minutes(e.seconds) }) : '';
  } catch { el.textContent = ''; }
}

function validate() {
  const k = kind();
  const tools = state ? state.scanners.filter((s) => s.installed && checked?.has(s.id)) : [];
  let hint = '';
  let blocked = false;   // the hint names something to do first
  const need = (text) => { blocked = true; return text; };
  if (!state) hint = '';
  else if (k === 'mcp') hint = '';
  else if (!state.scanners.some((s) => s.installed)) hint = need(t('先安裝至少一個掃描工具（建議從 SkillSpector 開始）。'));
  else if (!tools.length) hint = need(t('請至少勾選一個工具。'));
  else if ((k === 'folder' || k === 'zip') && !picked[k]) hint = need(k === 'folder' ? t('請先選擇資料夾。') : t('請先選擇 zip 檔。'));
  else if (k === 'github' && !/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/.test($('#url').value.trim())) hint = need(t('請貼上 GitHub 網址。'));
  else if (k === 'claude' && !state.claude_found) hint = t('這台電腦上好像沒有 Claude 的技能資料夾，不過還是可以試試看。');
  if (state?.running) hint = t('有工作正在進行…');
  $('#start-hint').textContent = hint;
  $('#start').disabled = !!state?.running || (k !== 'mcp' && !tools.length) || blocked;
  clearTimeout(validate.timer);
  validate.timer = setTimeout(renderEstimate, 300);
}

async function loadState() {
  const n = (loadState.seq = (loadState.seq || 0) + 1);
  const fresh = await api('/api/state');
  if (n !== loadState.seq) return;   // a newer request is on its way: an older answer mustn't overwrite it
  state = fresh;
  $('#copyright').textContent = state.app.copyright;
  // wording for this system: Finder or 檔案總管, and which manual-update steps to show
  const win = state.app.platform === 'win';
  document.querySelectorAll('.file-manager').forEach((el) => { el.textContent = win ? t('檔案總管') : ' Finder '; });
  document.querySelectorAll('[data-os]').forEach((el) => { el.hidden = el.dataset.os !== (win ? 'win' : 'mac'); });
  $('#disclaimer-short').textContent = `⚠︎ ${state.app.disclaimer_short}`;
  $('#about-disclaimer').textContent = state.app.disclaimer;
  $('#about-copyright').textContent = state.app.copyright;
  $('#about-version').textContent = t('{tagline} · 版本 {version}', { tagline: state.app.tagline, version: state.app.version });
  $('#licences').innerHTML = state.scanners.map((s) =>
    `<li><a href="${esc(s.homepage)}" target="_blank" rel="noopener">${esc(s.name)}</a>${esc(t('（{vendor}）— {license}', { vendor: s.vendor, license: s.license }))}</li>`).join('');
  renderLang();
  renderUpdate();
  renderReminder();
  renderCompanion();
  // an install that was going on when the page was (re)loaded: keep showing it next to its tool
  if (state.installing && !installing) watchInstall(state.installing.id, state.installing.job, state.installing.ids);
  renderScanners();
  renderHistory();
  if (state.running && !following) follow(state.running);
  // tools still being checked: look again shortly
  clearTimeout(loadState.timer);
  if (state.scanners.some((s) => s.status === 'checking') || !state.newest_checked) loadState.timer = setTimeout(() => loadState().catch(() => {}), 3000);
}

// --- jobs ---
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

let following = null;

const ITEM_WORD = { ok: t('可以'), ask: t('先問人'), no: t('不建議') };
function renderItems(items) {
  $('#p-items').hidden = items.length < 2;
  $('#p-items').innerHTML = items.map((it) => {
    const right = it.advice ? `<span class="pill-sm ${ADVICE_CLASS[it.advice]}">${ITEM_WORD[it.advice]}</span>`
      : it.done ? `<span class="p-run"><span class="spinner"></span>${it.done} / ${it.total}</span>`
      : `<span class="p-wait">${esc(t('等待中'))}</span>`;
    return `<li class="${it.advice ? 'done' : it.done ? 'run' : ''}"><span class="p-name">${esc(it.name)}</span>${right}</li>`;
  }).join('');
}

async function follow(jobId) {
  following = jobId;
  show('progress');
  $('#p-back').hidden = true;
  for (;;) {
    if (following !== jobId) return;
    let job;
    try { job = await api(`/api/job/${jobId}`); } catch (err) { await sleep(1500); continue; }
    $('#p-title').textContent = job.status === 'running' ? (job.cancelled ? t('正在停止…') : t('正在檢查…')) : job.status === 'done' ? t('檢查完成') : t('沒有完成');
    $('#p-stop').hidden = job.status !== 'running' || job.kind !== 'scan';
    $('#p-stop').disabled = !!job.cancelled;
    if (job.status === 'running' && !job.total) $('#p-bar').style.width = '4%';
    $('#p-current').textContent = job.status === 'error' ? job.error : job.current;
    $('#p-bar').style.width = job.total ? `${Math.round((job.done / job.total) * 100)}%` : '4%';
    const clock = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
    const left = job.remaining == null ? '' : ' · ' + (job.remaining < 60 ? t('快好了') : t('預估還要{time}', { time: minutes(job.remaining, true) }));
    $('#p-count').textContent = job.status === 'running'
      ? (job.total ? `${job.done} / ${job.total} · ` : '') + t('已經過 {time}', { time: clock(job.elapsed) }) + left
      : (job.total ? `${job.done} / ${job.total}` : '');
    $('#p-log').textContent = job.log.join('\n');
    renderItems(job.items || []);
    if (job.status !== 'running') {
      following = null;
      if ($('#confirm').open) $('#confirm').close();   // the 停止檢查？ question no longer applies
      await loadState().catch(() => {});
      if (job.status === 'done' && job.result) { openReport(job.result); return; }
      $('#p-back').hidden = false;   // never leave the person on this screen without a way back
      if (job.status === 'error') { show('form'); showError(job.error); }
      return;
    }
    await sleep(800);
  }
}

// one request at a time: a second click while the first is on its way would only get 「已經有工作在進行」
let sending = false;
async function once(fn) {
  if (sending) return;
  sending = true;
  try { await fn(); } finally { sending = false; }
}

function install(id) {
  if (installing) return;
  return once(async () => {
    try {
      const job = await api('/api/install', { id });
      watchInstall(id, job.id);
    } catch (err) { showError(err.message); }
  });
}

// follow an install next to its tool; the server has the tool's status ready by the time the job ends
// follow an install next to its tool; 全部安裝 moves from tool to tool, so the spinner follows job.target
async function watchInstall(id, jobId, ids = [id]) {
  installing = { id, job: jobId };
  renderScanners();
  for (;;) {
    await sleep(1000);
    let j;
    try { j = await api(`/api/job/${jobId}`); } catch { continue; }
    if (j.target && j.target !== installing.id && j.status === 'running') { installing.id = j.target; renderScanners(); }
    const text = $('#inst-text'); if (text) text.textContent = j.current;
    if (j.status !== 'running') {
      installing = null;
      ids.forEach((x) => checked.add(x));
      await loadState().catch(() => {});
      if (j.status === 'done') toast(ids.length > 1 ? t('全部安裝完成 ✓') : t('安裝完成 ✓')); else showError(j.error);
      return;
    }
  }
}

function start() {
  if (following) return;
  const k = kind();
  const value = k === 'github' ? $('#url').value.trim() : picked[k] || '';
  return once(async () => {
    $('#start').disabled = true;
    try {
      const job = await api('/api/scan', { kind: k, value, scanners: [...checked] });
      follow(job.id);
    } catch (err) { showError(err.message); validate(); }
  });
}

function openReport(file) {
  const url = `/reports/${encodeURIComponent(file)}?t=${encodeURIComponent(TOKEN)}`;
  $('#report-frame').src = url;
  $('#report-tab').href = url;
  $('#report-finder').onclick = () => api('/api/open', { file }).catch((e) => toast(e.message));
  show('report');
}

// --- wiring ---
document.querySelectorAll('input[name=kind]').forEach((r) => r.addEventListener('change', renderTarget));
$('#url').addEventListener('input', validate);
$('#pick').addEventListener('click', async () => {
  const k = kind();
  $('#pick').disabled = true;
  try {
    const { path } = await api('/api/pick', { kind: k });
    if (path) picked[k] = path;
    renderTarget();
  } catch (err) { showError(err.message); }
  $('#pick').disabled = false;
});
$('#scanners').addEventListener('change', (ev) => {
  const id = ev.target.dataset.id;
  if (!id) return;
  ev.target.checked ? checked.add(id) : checked.delete(id);
  validate();
});
$('#scanners').addEventListener('click', (ev) => {
  const id = ev.target.dataset?.install;
  if (id) install(id);
});
$('#start').addEventListener('click', start);
$('#back').addEventListener('click', () => { show('form'); validate(); });
$('#p-back').addEventListener('click', () => { show('form'); validate(); });
$('#update-how').addEventListener('click', () => $('#update-steps').showModal());
$('#update-now').addEventListener('click', startUpdate);
$('#check-update').addEventListener('click', async () => {
  $('#check-update').disabled = true;
  $('#about-update').textContent = t('正在檢查…');
  try {
    state.update = await api('/api/check-update', {});
    try { localStorage.removeItem('argus-update-dismissed'); } catch {}   // asked on purpose: show it even if dismissed
    renderUpdate();
    if (state.update.newer) { $('#about').close(); window.scrollTo(0, 0); }
  } catch (err) { $('#about-update').textContent = err.message; }
  $('#check-update').disabled = false;
});
$('#remind-now').addEventListener('click', () => {
  document.querySelector('input[name=kind][value=claude]').checked = true;
  renderTarget();
  $('#remind').hidden = true;
  $('#start').scrollIntoView({ behavior: 'smooth', block: 'center' });
  $('#start').focus();
});
$('#remind-later').addEventListener('click', () => {
  try { localStorage.setItem('argus-remind-dismissed', `${state.reminder.signature}|${Date.now() + 7 * 864e5}`); } catch {}
  $('#remind').hidden = true;
});
$('#skill-toggle').addEventListener('change', (ev) => toggleCompanion(ev.target, '/api/claude-skill'));
$('#auto-toggle').addEventListener('change', (ev) => toggleCompanion(ev.target, '/api/autocheck',
  t('開啟後，從現在開始新裝或更新的 Claude 技能會在背景自動檢查。\n\n現在已經裝好的技能不會自動重掃；想檢查的話，用「我的 Claude 技能」掃一次就好。')));
$('#update-later').addEventListener('click', () => {
  try { localStorage.setItem('argus-update-dismissed', state.update.latest); } catch {}
  $('#update').hidden = true;
});
$('#quit').addEventListener('click', async () => {
  if (!(await ask(t('正在進行的掃描或安裝會被中斷。之後點兩下 Argus 就能重新打開。'), { title: t('結束 Argus？'), ok: t('結束'), danger: true }))) return;
  try { await api('/api/quit', {}); } catch {}
  document.body.innerHTML = `<p style="text-align:center;margin-top:30vh;font-size:16px">${esc(t('Argus 已經結束，可以關掉這個分頁了。'))}</p>`;
});
$('#history').addEventListener('click', async (ev) => {
  const del = ev.target.closest('[data-del]');
  if (del) {
    if (!(await ask(t('刪除後就找不回來了。'), { title: t('刪除這份報告？'), ok: t('刪除'), danger: true }))) return;
    try { await api('/api/delete-report', { file: del.dataset.del }); await loadState(); toast(t('已刪除。')); } catch (err) { showError(err.message); }
    return;
  }
  const li = ev.target.closest('li[data-file]');
  if (li) openReport(li.dataset.file);
});
$('#history').addEventListener('keydown', (ev) => {
  const li = ev.target.closest('li[data-file]');
  if (li && ev.target === li && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); openReport(li.dataset.file); }
});
$('#install-all').addEventListener('click', installAll);
$('#history-more').addEventListener('click', () => { historyAll = !historyAll; renderHistory(); });
$('#tools-summary').addEventListener('click', () => { toolsOpen = $('#tools-summary').getAttribute('aria-expanded') !== 'true'; renderToolsCard(); });
$('#open-reports').addEventListener('click', () => api('/api/open', {}).catch((e) => toast(e.message)));
// About: three tabs, so nothing needs a long scroll; the footer link opens straight onto 隱私
function showTab(name) {
  document.querySelectorAll('#about [role=tab]').forEach((tab) => {
    const on = tab.dataset.tab === name;
    tab.setAttribute('aria-selected', on);
    tab.tabIndex = on ? 0 : -1;
    $(`#panel-${tab.dataset.tab}`).hidden = !on;
  });
  $('#about-body').scrollTop = 0;
}
function openAbout(tab = 'intro') { showTab(tab); $('#about').showModal(); }
$('#about-open').addEventListener('click', () => openAbout());
$('#about-open-2').addEventListener('click', () => openAbout('privacy'));
const tabs = [...document.querySelectorAll('#about [role=tab]')];
tabs.forEach((tab, i) => {
  tab.addEventListener('click', () => showTab(tab.dataset.tab));
  tab.addEventListener('keydown', (ev) => {   // arrow keys move between tabs
    const step = { ArrowRight: 1, ArrowLeft: -1 }[ev.key];
    if (!step) return;
    const next = tabs[(i + step + tabs.length) % tabs.length];
    showTab(next.dataset.tab); next.focus(); ev.preventDefault();
  });
});
// a click on the dimmed backdrop closes a dialog
document.querySelectorAll('dialog').forEach((d) => d.addEventListener('click', (ev) => { if (ev.target === d) d.close(); }));

// 深色 (default) or 淺色; remembered on this computer, and passed on to a report open in the frame
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const label = theme === 'dark' ? t('切換成淺色模式') : t('切換成深色模式');
  $('#theme').setAttribute('aria-label', label);
  $('#theme').title = label;
  try { $('#report-frame').contentDocument?.documentElement.setAttribute('data-theme', theme); } catch {}
}
applyTheme(document.documentElement.dataset.theme || 'dark');
$('#theme').addEventListener('click', () => {
  const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('argus-theme', theme); } catch {}
  applyTheme(theme);
});

// 語言: 跟隨系統, or one of Argus's languages, each written in its own script; the page reloads in it
function renderLang() {
  const l = state.lang;
  const sel = $('#lang');
  if (!l || sel.disabled) return;
  if (sel.options.length === 1) {
    for (const [code, name] of Object.entries(l.all)) {
      const o = new Option(name, code);
      o.lang = code;
      sel.add(o);
    }
  }
  sel.value = l.chosen || '';
}
$('#lang').addEventListener('change', async (ev) => {
  const sel = ev.target;
  sel.disabled = true;
  try {
    await api('/api/lang', { lang: sel.value || null });
    location.reload();
  } catch (err) {
    sel.disabled = false;
    sel.value = state?.lang?.chosen || '';
    showError(err.message);
  }
});

// keep the local server alive while this page is open; say so if it has gone away
setInterval(async () => {
  try { await api('/api/alive'); $('#offline').hidden = true; } catch { $('#offline').hidden = false; }
}, 20000);

renderTarget();
loadState().catch((err) => showError(err.message));
$('#error-close').addEventListener('click', () => { $('#error-box').hidden = true; });
$('#error-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#error-text').textContent); $('#error-copy').textContent = t('已複製 ✓'); }
  catch { $('#error-copy').textContent = t('複製失敗，請手動選取'); }
  setTimeout(() => { $('#error-copy').textContent = t('複製錯誤訊息'); }, 2500);
});
// 4. 停止檢查: what finished becomes the report
$('#p-stop').addEventListener('click', async () => {
  const id = following;
  if (!id) return;
  if (!(await ask(t('已經檢查完的技能會做成報告；還沒檢查的就不檢查了。'), { title: t('停止檢查？'), ok: t('停止'), danger: true }))) return;
  if (following !== id) return;   // it finished while the question was open
  $('#p-stop').disabled = true;
  try { await api('/api/cancel', { id }); } catch (err) { showError(err.message); $('#p-stop').disabled = false; }
});
