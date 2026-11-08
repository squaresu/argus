// Argus page: pick what to scan and which tools, follow the job, show the report.
const TOKEN = document.querySelector('meta[name=argus-token]').content;
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const VERDICT_CLASS = { SAFE: 'safe', CAUTION: 'caution', DO_NOT_INSTALL: 'danger', ERROR: 'error' };
const VERDICT_ZH = { SAFE: '安全', CAUTION: '注意', DO_NOT_INSTALL: '不建議安裝', ERROR: '沒掃完' };

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
  if (!res.ok) throw new Error(data.error || `發生錯誤（${res.status}）`);
  return data;
}

function toast(text, ms = 4000) {
  const t = document.createElement('div');
  t.className = 'toast'; t.textContent = text;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

function show(view) {
  for (const v of ['form', 'progress', 'report']) $(`#view-${v}`).hidden = v !== view;
  $('#hero').hidden = view !== 'form';
  window.scrollTo(0, 0);
}

const kind = () => document.querySelector('input[name=kind]:checked').value;

// --- the form ---
function renderTarget() {
  const k = kind();
  $('#detail-claude').hidden = k !== 'claude';
  $('#detail-pick').hidden = k !== 'folder' && k !== 'zip';
  $('#detail-github').hidden = k !== 'github';
  if (k === 'folder' || k === 'zip') {
    $('#pick').textContent = k === 'folder' ? '選擇資料夾…' : '選擇 zip 檔…';
    $('#picked').textContent = picked[k] || '還沒選擇';
    $('#picked').classList.toggle('set', !!picked[k]);
  }
  if (k === 'github') $('#url').focus();
  validate();
}

function renderScanners() {
  const list = state.scanners;
  if (checked === null) checked = new Set(list.filter((s) => s.default_on).map((s) => s.id));
  $('#scanners').innerHTML = list.map((s) => {
    const busy = installing && installing.id === s.id;
    const button = (label) => `<button class="btn" type="button" data-install="${esc(s.id)}" ${installing ? 'disabled' : ''}>${label}</button>`;
    const right = busy
      ? `<span class="installing"><span class="spinner"></span><span id="inst-text">安裝中…</span></span>`
      : s.status === 'ok' ? `<span class="badge ok" title="${esc(s.version)}">已安裝</span>`
      : s.status === 'checking' ? `<span class="badge" title="正在確認這個工具能不能正常啟動">確認中…</span>`
      : s.status === 'broken' ? `<span class="fix"><span class="badge bad">打不開</span>${button('重新安裝')}</span>`
      : button('安裝');
    return `<li class="scanner ${s.installed ? '' : 'off'}">
      <input type="checkbox" data-id="${esc(s.id)}" ${checked.has(s.id) ? 'checked' : ''} ${s.installed ? '' : 'disabled'} aria-label="${esc(s.name)}">
      <div><span class="name">${esc(s.name)}</span><span class="vendor">${esc(s.vendor)} · ${esc(s.license)}</span><p>${esc(s.summary)}</p></div>
      ${right}</li>`;
  }).join('');
  validate();
}

// "有新版本" notice; 稍後再說 hides it for that version only
function renderUpdate() {
  const u = state.update || {};
  let dismissed = '';
  try { dismissed = localStorage.getItem('argus-update-dismissed') || ''; } catch {}
  $('#update').hidden = !((u.newer && u.latest !== dismissed) || state.updating || updating);
  $('#update-now').hidden = !u.auto;
  $('#update-why').hidden = u.auto || !u.why_manual;
  $('#update-why').textContent = u.why_manual || '';
  if (state.updating && !updating) watchUpdate(state.updating);
  $('#update-version').textContent = u.latest || '';
  $('#update-current').textContent = state.app.version;
  $('#update-download').href = u.url || 'https://github.com/squaresu/argus/releases/latest';
  $('#about-update').textContent = !u.checked ? '' : u.newer ? `有新版本 ${u.latest} 可以下載` : u.latest ? '已經是最新版' : '';
  // the check runs in the background right after Argus starts; look again until it has answered
  clearTimeout(renderUpdate.timer);
  if (!u.checked) renderUpdate.timer = setTimeout(() => loadState().catch(() => {}), 4000);
}

let updating = null;

async function startUpdate() {
  if (!confirm(`要更新到 Argus ${state.update.latest} 嗎？\n\nArgus 會下載新版、換掉現在這一版，再自動重新打開。正在進行的工作會被中斷。`)) return;
  try { watchUpdate((await api('/api/update', {})).id); } catch (err) { toast(err.message, 8000); }
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
    if (j.status === 'error') { toast(j.error, 12000); return; }
    try {
      await api('/api/relaunch', {});
      $('#updated').showModal();
    } catch (err) {
      $('#updated-title').textContent = '更新完成，請重新打開 Argus';
      $('#updated-text').textContent = '新版已經裝好了。關掉這個分頁，再從「應用程式」點兩下 Argus 就好。';
      $('#updated').showModal();
    }
    return;
  }
}

function renderHistory() {
  const h = state.history || [];
  $('#history-card').hidden = !h.length;
  $('#history').innerHTML = h.slice(0, 8).map((r) => {
    const dots = ['DO_NOT_INSTALL', 'CAUTION', 'SAFE', 'ERROR']
      .filter((v) => r.counts?.[v]).map((v) => `<span class="dot ${VERDICT_CLASS[v]}" title="${VERDICT_ZH[v]}">${r.counts[v]}</span>`).join('');
    return `<li data-file="${esc(r.file)}"><span class="h-title">${esc(r.title)}</span><span class="dots">${dots}</span><span class="h-when">${esc(r.when)} · ${r.skills} 個技能</span></li>`;
  }).join('');
}

function validate() {
  const k = kind();
  const tools = state ? state.scanners.filter((s) => s.installed && checked?.has(s.id)) : [];
  let hint = '';
  if (!state) hint = '';
  else if (!state.scanners.some((s) => s.installed)) hint = '先安裝至少一個掃描工具（建議從 SkillSpector 開始）。';
  else if (!tools.length) hint = '請至少勾選一個工具。';
  else if ((k === 'folder' || k === 'zip') && !picked[k]) hint = k === 'folder' ? '請先選擇資料夾。' : '請先選擇 zip 檔。';
  else if (k === 'github' && !/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/.test($('#url').value.trim())) hint = '請貼上 GitHub 網址。';
  else if (k === 'claude' && !state.claude_found) hint = '這台電腦上好像沒有 Claude 的技能資料夾，不過還是可以試試看。';
  if (state?.running) hint = '有工作正在進行…';
  $('#start-hint').textContent = hint;
  $('#start').disabled = !!state?.running || !tools.length || /^請|^先/.test(hint);
}

async function loadState() {
  state = await api('/api/state');
  $('#copyright').textContent = state.app.copyright;
  $('#disclaimer-short').textContent = `⚠︎ ${state.app.disclaimer_short}`;
  $('#about-disclaimer').textContent = state.app.disclaimer;
  $('#about-copyright').textContent = state.app.copyright;
  $('#about-version').textContent = `${state.app.tagline} · 版本 ${state.app.version}`;
  $('#licences').innerHTML = state.scanners.map((s) =>
    `<li><a href="${esc(s.homepage)}" target="_blank" rel="noopener">${esc(s.name)}</a>（${esc(s.vendor)}）— ${esc(s.license)}</li>`).join('');
  renderUpdate();
  // an install that was going on when the page was (re)loaded: keep showing it next to its tool
  if (state.installing && !installing) watchInstall(state.installing.id, state.installing.job);
  renderScanners();
  renderHistory();
  if (state.running && !following) follow(state.running);
  // tools still being checked: look again shortly
  clearTimeout(loadState.timer);
  if (state.scanners.some((s) => s.status === 'checking')) loadState.timer = setTimeout(() => loadState().catch(() => {}), 3000);
}

// --- jobs ---
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

let following = null;

async function follow(jobId) {
  following = jobId;
  show('progress');
  $('#p-back').hidden = true;
  for (;;) {
    if (following !== jobId) return;
    let job;
    try { job = await api(`/api/job/${jobId}`); } catch (err) { await sleep(1500); continue; }
    $('#p-title').textContent = job.status === 'running' ? '正在檢查…' : job.status === 'done' ? '檢查完成' : '沒有完成';
    $('#p-current').textContent = job.status === 'error' ? job.error : job.current;
    $('#p-bar').style.width = job.total ? `${Math.round((job.done / job.total) * 100)}%` : '4%';
    $('#p-count').textContent = job.total ? `${job.done} / ${job.total}` : '';
    $('#p-log').textContent = job.log.join('\n');
    if (job.status !== 'running') {
      following = null;
      await loadState().catch(() => {});
      if (job.status === 'done' && job.result) { openReport(job.result); return; }
      $('#p-back').hidden = false;   // never leave the person on this screen without a way back
      if (job.status === 'error') { show('form'); toast(job.error, 9000); }
      return;
    }
    await sleep(800);
  }
}

async function install(id) {
  try {
    const job = await api('/api/install', { id });
    watchInstall(id, job.id);
  } catch (err) { toast(err.message, 8000); }
}

// follow an install next to its tool; the server has the tool's status ready by the time the job ends
async function watchInstall(id, jobId) {
  installing = { id, job: jobId };
  renderScanners();
  for (;;) {
    await sleep(1000);
    let j;
    try { j = await api(`/api/job/${jobId}`); } catch { continue; }
    const t = $('#inst-text'); if (t) t.textContent = j.current;
    if (j.status !== 'running') {
      installing = null;
      if (j.status === 'done') checked.add(id);
      await loadState().catch(() => {});
      toast(j.status === 'done' ? '安裝完成 ✓' : j.error, j.status === 'done' ? 4000 : 9000);
      return;
    }
  }
}

async function start() {
  const k = kind();
  const value = k === 'github' ? $('#url').value.trim() : picked[k] || '';
  try {
    const job = await api('/api/scan', { kind: k, value, scanners: [...checked] });
    follow(job.id);
  } catch (err) { toast(err.message, 8000); }
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
  } catch (err) { toast(err.message); }
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
$('#update-later').addEventListener('click', () => {
  try { localStorage.setItem('argus-update-dismissed', state.update.latest); } catch {}
  $('#update').hidden = true;
});
$('#quit').addEventListener('click', async () => {
  if (!confirm('要結束 Argus 嗎？正在進行的掃描或安裝會被中斷。之後點兩下 Argus 就能重新打開。')) return;
  try { await api('/api/quit', {}); } catch {}
  document.body.innerHTML = '<p style="text-align:center;margin-top:30vh;font-size:16px">Argus 已經結束，可以關掉這個分頁了。</p>';
});
$('#history').addEventListener('click', (ev) => {
  const li = ev.target.closest('li[data-file]');
  if (li) openReport(li.dataset.file);
});
$('#open-reports').addEventListener('click', () => api('/api/open', {}).catch((e) => toast(e.message)));
for (const b of ['#about-open', '#about-open-2']) $(b).addEventListener('click', () => $('#about').showModal());

// keep the local server alive while this page is open; say so if it has gone away
setInterval(async () => {
  try { await api('/api/alive'); $('#offline').hidden = true; } catch { $('#offline').hidden = false; }
}, 20000);

renderTarget();
loadState().catch((err) => toast(err.message, 8000));
