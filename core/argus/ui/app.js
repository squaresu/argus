// Argus page: pick what to scan and which tools, follow the job, show the report.
const TOKEN = document.querySelector('meta[name=argus-token]').content;
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const VERDICT_CLASS = { SAFE: 'safe', CAUTION: 'caution', DO_NOT_INSTALL: 'danger', ERROR: 'error' };
const VERDICT_ZH = { SAFE: '安全', CAUTION: '注意', DO_NOT_INSTALL: '不建議安裝', ERROR: '沒掃完' };
const ADVICE_CLASS = { ok: 'safe', ask: 'caution', no: 'danger' };
const adviceWord = (a, installed) => (a === 'ask' ? '先問人' : installed ? { ok: '可以繼續用', no: '不建議用' }[a] : { ok: '可以裝', no: '不建議裝' }[a]);

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
  $('#detail-mcp').hidden = k !== 'mcp';
  $('#tools-card').hidden = k === 'mcp';   // the MCP check is Argus's own; no scanners involved
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
      : s.status === 'ok' && s.outdated ? `<span class="fix"><span class="badge new" title="現在的版本：${esc(s.version)}">有新版 ${esc(s.newest)}</span>${button('更新')}</span>`
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
  $('#about-open').classList.toggle('has-update', !!u.newer);
  $('#update-why').hidden = u.auto || !u.why_manual;
  $('#update-why').textContent = u.why_manual || '';
  if (state.updating && !updating) watchUpdate(state.updating);
  $('#update-version').textContent = u.latest || '';
  $('#update-current').textContent = state.app.version;
  document.querySelectorAll('.update-download').forEach((a) => { a.href = u.url || 'https://github.com/squaresu/argus/releases/latest'; });
  $('#about-update').textContent = !u.checked ? '正在檢查有沒有新版本…' : u.newer ? `有新版本 ${u.latest} 可以更新` : u.latest ? '已經是最新版' : u.failed ? `沒辦法檢查新版本：${u.error || '連不上 GitHub'}` : '';
  // the check runs in the background right after Argus starts; look again until it has answered
  clearTimeout(renderUpdate.timer);
  if (!u.checked) renderUpdate.timer = setTimeout(() => loadState().catch(() => {}), 1000);
}

let updating = null;

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
  const names = (list, count) => list.join('、') + (count > list.length ? ` 等 ${count} 個` : '');
  const parts = [];
  if (r.changed_count) parts.push(`${r.changed_count} 個在上次檢查後有更新（${names(r.changed, r.changed_count)}）`);
  if (r.new_count && !r.never) parts.push(`${r.new_count} 個是新裝的（${names(r.new, r.new_count)}）`);
  if (r.stale_count) parts.push(`${r.stale_count} 個超過 30 天沒檢查`);
  $('#remind-title').textContent = r.never ? `還沒檢查過這台電腦上的 Claude 技能（共 ${r.total} 個）` : '你的 Claude 技能該重新檢查了';
  $('#remind-text').textContent = r.never ? '檢查一次，之後技能有更新時 Argus 會提醒你。' : `其中 ${parts.join('，')}。`;
}

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
    const dots = r.advice
      ? ['no', 'ask', 'ok'].filter((a) => r.advice[a]).map((a) => `<span class="dot ${ADVICE_CLASS[a]}" title="${adviceWord(a, r.installed)}">${r.advice[a]}</span>`).join('')
      : ['DO_NOT_INSTALL', 'CAUTION', 'SAFE', 'ERROR']
        .filter((v) => r.counts?.[v]).map((v) => `<span class="dot ${VERDICT_CLASS[v]}" title="${VERDICT_ZH[v]}">${r.counts[v]}</span>`).join('');
    return `<li data-file="${esc(r.file)}"><span class="h-title">${esc(r.title)}</span><span class="dots">${dots}</span><span class="h-when">${esc(r.when)} · ${r.skills} 個技能</span></li>`;
  }).join('');
}

// before a scan: how many skills and roughly how long (asked again when the target or the tools change)
const minutes = (s) => (s < 60 ? '不到 1 分鐘' : s < 3600 ? `大約 ${Math.round(s / 60)} 分鐘` : `大約 ${(s / 3600).toFixed(1)} 小時`);
async function renderEstimate() {
  const k = kind();
  const el = $('#start-estimate');
  const tools = state ? state.scanners.filter((s) => s.installed && checked?.has(s.id)).map((s) => s.id) : [];
  if (!state || k === 'mcp' || !tools.length || ((k === 'folder' || k === 'zip') && !picked[k])) { el.textContent = ''; return; }
  const ask = `${k}|${picked[k] || ''}|${tools.join(',')}`;
  renderEstimate.ask = ask;
  try {
    const e = await api('/api/estimate', { kind: k, value: picked[k] || '', scanners: tools });
    if (renderEstimate.ask !== ask) return;   // the choice changed while asking
    el.textContent = e.skills === null
      ? `下載後才知道有幾個技能；每個技能${minutes(e.per_skill)}。`
      : e.skills ? `共 ${e.skills} 個技能，預估${minutes(e.seconds)}。` : '';
  } catch { el.textContent = ''; }
}

function validate() {
  const k = kind();
  const tools = state ? state.scanners.filter((s) => s.installed && checked?.has(s.id)) : [];
  let hint = '';
  if (!state) hint = '';
  else if (k === 'mcp') hint = '';
  else if (!state.scanners.some((s) => s.installed)) hint = '先安裝至少一個掃描工具（建議從 SkillSpector 開始）。';
  else if (!tools.length) hint = '請至少勾選一個工具。';
  else if ((k === 'folder' || k === 'zip') && !picked[k]) hint = k === 'folder' ? '請先選擇資料夾。' : '請先選擇 zip 檔。';
  else if (k === 'github' && !/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/.test($('#url').value.trim())) hint = '請貼上 GitHub 網址。';
  else if (k === 'claude' && !state.claude_found) hint = '這台電腦上好像沒有 Claude 的技能資料夾，不過還是可以試試看。';
  if (state?.running) hint = '有工作正在進行…';
  $('#start-hint').textContent = hint;
  $('#start').disabled = !!state?.running || (k !== 'mcp' && !tools.length) || /^請|^先/.test(hint);
  clearTimeout(validate.timer);
  validate.timer = setTimeout(renderEstimate, 300);
}

async function loadState() {
  state = await api('/api/state');
  $('#copyright').textContent = state.app.copyright;
  // wording for this system: Finder or 檔案總管, and which manual-update steps to show
  const win = state.app.platform === 'win';
  document.querySelectorAll('.file-manager').forEach((el) => { el.textContent = win ? '檔案總管' : ' Finder '; });
  document.querySelectorAll('[data-os]').forEach((el) => { el.hidden = el.dataset.os !== (win ? 'win' : 'mac'); });
  $('#disclaimer-short').textContent = `⚠︎ ${state.app.disclaimer_short}`;
  $('#about-disclaimer').textContent = state.app.disclaimer;
  $('#about-copyright').textContent = state.app.copyright;
  $('#about-version').textContent = `${state.app.tagline} · 版本 ${state.app.version}`;
  $('#licences').innerHTML = state.scanners.map((s) =>
    `<li><a href="${esc(s.homepage)}" target="_blank" rel="noopener">${esc(s.name)}</a>（${esc(s.vendor)}）— ${esc(s.license)}</li>`).join('');
  renderUpdate();
  renderReminder();
  // an install that was going on when the page was (re)loaded: keep showing it next to its tool
  if (state.installing && !installing) watchInstall(state.installing.id, state.installing.job);
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

async function follow(jobId) {
  following = jobId;
  show('progress');
  $('#p-back').hidden = true;
  for (;;) {
    if (following !== jobId) return;
    let job;
    try { job = await api(`/api/job/${jobId}`); } catch (err) { await sleep(1500); continue; }
    $('#p-title').textContent = job.status === 'running' ? '正在檢查…' : job.status === 'done' ? '檢查完成' : '沒有完成';
    if (job.status === 'running' && !job.total) $('#p-bar').style.width = '4%';
    $('#p-current').textContent = job.status === 'error' ? job.error : job.current;
    $('#p-bar').style.width = job.total ? `${Math.round((job.done / job.total) * 100)}%` : '4%';
    const clock = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
    const left = job.remaining == null ? '' : job.remaining < 60 ? ' · 快好了' : ` · 預估還要${minutes(job.remaining).replace('大約', '約')}`;
    $('#p-count').textContent = job.status === 'running'
      ? `${job.total ? `${job.done} / ${job.total} · ` : ''}已經過 ${clock(job.elapsed)}${left}` : (job.total ? `${job.done} / ${job.total}` : '');
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
$('#check-update').addEventListener('click', async () => {
  $('#check-update').disabled = true;
  $('#about-update').textContent = '正在檢查…';
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
