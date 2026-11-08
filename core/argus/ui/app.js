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
    const right = busy
      ? `<span class="installing"><span class="spinner"></span><span id="inst-text">安裝中…</span></span>`
      : s.installed
        ? `<span class="badge ok" title="${esc(s.version)}">已安裝</span>`
        : `<button class="btn" type="button" data-install="${esc(s.id)}" ${installing ? 'disabled' : ''}>安裝</button>`;
    return `<li class="scanner ${s.installed ? '' : 'off'}">
      <input type="checkbox" data-id="${esc(s.id)}" ${checked.has(s.id) ? 'checked' : ''} ${s.installed ? '' : 'disabled'} aria-label="${esc(s.name)}">
      <div><span class="name">${esc(s.name)}</span><span class="vendor">${esc(s.vendor)} · ${esc(s.license)}</span><p>${esc(s.summary)}</p></div>
      ${right}</li>`;
  }).join('');
  validate();
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
  $('#about-copyright').textContent = state.app.copyright;
  $('#about-version').textContent = `${state.app.tagline} · 版本 ${state.app.version}`;
  $('#licences').innerHTML = state.scanners.map((s) =>
    `<li><a href="${esc(s.homepage)}" target="_blank" rel="noopener">${esc(s.name)}</a>（${esc(s.vendor)}）— ${esc(s.license)}</li>`).join('');
  renderScanners();
  renderHistory();
  if (state.running && !installing) follow(state.running);
}

// --- jobs ---
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function follow(jobId) {
  show('progress');
  for (;;) {
    let job;
    try { job = await api(`/api/job/${jobId}`); } catch (err) { await sleep(1500); continue; }
    $('#p-title').textContent = job.status === 'running' ? '正在檢查…' : job.status === 'done' ? '檢查完成' : '沒有完成';
    $('#p-current').textContent = job.status === 'error' ? job.error : job.current;
    $('#p-bar').style.width = job.total ? `${Math.round((job.done / job.total) * 100)}%` : '4%';
    $('#p-count').textContent = job.total ? `${job.done} / ${job.total}` : '';
    $('#p-log').textContent = job.log.join('\n');
    if (job.status === 'done' && job.result) { await loadState(); openReport(job.result); return; }
    if (job.status === 'error') {
      await loadState();
      setTimeout(() => show('form'), 0);
      toast(job.error, 8000);
      return;
    }
    await sleep(800);
  }
}

async function install(id) {
  try {
    const job = await api('/api/install', { id });
    installing = { id, job: job.id };
    renderScanners();
    for (;;) {
      await sleep(1000);
      const j = await api(`/api/job/${job.id}`);
      const t = $('#inst-text'); if (t) t.textContent = j.current;
      if (j.status !== 'running') {
        installing = null;
        await sleep(1500);   // the server re-checks the tool's version right after
        await loadState();
        if (j.status === 'error') toast(j.error, 9000);
        else { checked.add(id); renderScanners(); toast('安裝完成 ✓'); }
        return;
      }
    }
  } catch (err) {
    installing = null; renderScanners(); toast(err.message, 8000);
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
