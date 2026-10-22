'use strict';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const state = {
  docs: [],          // [{name, text}]
  analysis: null,    // last /api/analyze response
  snapshot: null,    // account auth-details JSON for Org tab
  aiEnabled: false,
  hosted: false,     // shared demo mode (HOSTED=1, e.g. Docker) — auto-runs + privacy banner
  demoRunning: false,
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html != null) e.innerHTML = html;
  return e;
};
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(path, body) {
  const resp = await fetch(path, body
    ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
    : undefined);
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

// Minimal markdown: bold, code, bullets, line breaks — output is escaped first.
function md(text) {
  const lines = esc(text).split('\n');
  let out = '';
  let inList = false;
  for (const line of lines) {
    const bullet = line.match(/^\s*- (.*)$/);
    if (bullet) {
      if (!inList) { out += '<ul>'; inList = true; }
      out += `<li>${inline(bullet[1])}</li>`;
    } else {
      if (inList) { out += '</ul>'; inList = false; }
      if (line.trim()) out += `<p>${inline(line)}</p>`;
    }
  }
  if (inList) out += '</ul>';
  return out;

  function inline(s) {
    return s
      .replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
      .replace(/_(.+?)_/g, '<i>$1</i>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\[(S\d+)( · [^\]]+)?\]/g, (m, sid, rest) =>
        `<span class="cite" data-stmt="${sid}">[${sid}${rest || ''}]</span>`);
  }
}

// ---------------------------------------------------------------------------
// Blast-radius formatting (catalogue-backed grant scope from the API)
// ---------------------------------------------------------------------------
const fmtNum = (n) => Number(n).toLocaleString('en-GB');

// One-line "grants N actions · X write · Y permissions-management" summary.
function blastLine(b) {
  if (!b || b.unavailable || !b.total) return '';
  const bits = [`${fmtNum(b.total)} action${b.total === 1 ? '' : 's'}`];
  if (b.byLevel && b.byLevel.Write) bits.push(`${fmtNum(b.byLevel.Write)} write`);
  if (b.permissionsManagement) bits.push(`${fmtNum(b.permissionsManagement)} permissions-management`);
  return bits.join(' · ');
}

// Compact cell for the Statements table: total, with write/permissions counts.
function grantsCell(s) {
  if (s.provider !== 'aws' || !s.blast || s.blast.unavailable) return '—';
  const b = s.blast;
  if (!b.total) return '0';
  const parts = [];
  if (b.byLevel.Write) parts.push(`${fmtNum(b.byLevel.Write)}W`);
  if (b.permissionsManagement) parts.push(`<span class="pm">${fmtNum(b.permissionsManagement)}P</span>`);
  const detail = parts.length ? ` <span class="grants-detail">${parts.join(' ')}</span>` : '';
  return `${fmtNum(b.total)}${detail}`;
}

// Show the aggregate grant scope banner in the Ask panel (or hide it).
function renderAskScope(blast) {
  const el = $('#askScope');
  if (!el) return;
  const line = blastLine(blast);
  if (!line) { el.hidden = true; return; }
  const tone = blast.permissionsManagement ? 'scope-high' : (blast.mutating ? 'scope-warn' : '');
  el.className = `scope-banner ${tone}`;
  el.innerHTML = `Allow statements in these policies grant <b>${line}</b> across the resources they cover.`;
  el.hidden = false;
}

// ---------------------------------------------------------------------------
// Input panel
// ---------------------------------------------------------------------------
function renderDocChips() {
  const wrap = $('#docChips');
  wrap.innerHTML = '';
  for (const d of state.docs) {
    const chip = el('span', 'doc-chip', `${esc(d.name)} <span class="x" title="Remove">×</span>`);
    chip.querySelector('.x').onclick = () => {
      state.docs = state.docs.filter((x) => x !== d);
      renderDocChips();
    };
    wrap.appendChild(chip);
  }
}

function addDoc(name, text) {
  if (!text.trim()) return;
  state.docs = state.docs.filter((d) => d.name !== name);
  state.docs.push({ name, text });
  renderDocChips();
}

$('#addPaste').onclick = () => {
  const text = $('#pasteBox').value;
  if (!text.trim()) return;
  addDoc($('#pasteName').value.trim() || 'pasted-policy.json', text);
  $('#pasteBox').value = '';
};

$('#fileInput').onchange = async (e) => {
  for (const f of e.target.files) addDoc(f.name, await f.text());
  e.target.value = '';
};

async function loadSamples() {
  try {
    const samples = await api('/api/samples');
    const sel = $('#sampleSelect');
    for (const s of samples) {
      const opt = el('option');
      opt.value = s.name;
      // Server may send a human label; fall back to filename
      opt.textContent = s.label || s.name;
      sel.appendChild(opt);
    }
    sel.onchange = async () => {
      if (!sel.value) return;
      const text = await (await fetch(`/samples/${sel.value}`)).text();
      addDoc(sel.value, text);
      sel.value = '';
    };
  } catch { /* samples are optional */ }
}

/** Load the baked-in demo snapshot; returns principal count or throws. */
async function loadDemoSnapshot() {
  state.snapshot = await (await fetch('/samples/aws-account-snapshot.json')).json();
  const n = (state.snapshot.UserDetailList || []).length + (state.snapshot.RoleDetailList || []).length;
  setSnapshotStatus(`Sample snapshot loaded: ${n} principals.`, true);
  return n;
}

function setDemoStatus(msg, done) {
  const el = $('#demoStatus');
  if (!el) return;
  el.hidden = !msg;
  el.textContent = msg || '';
  el.classList.toggle('done', !!done);
}

/**
 * One-click stranger path: Org tab → who-can → reach-admin → resource scan.
 * Uses GET /api/demo/run so hosted-demo visitors don't upload the snapshot 3×.
 */
async function runNinetySecondDemo() {
  if (state.demoRunning) return;
  state.demoRunning = true;
  const btn = $('#runDemoBtn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spin">◐</span> Running checks…'; }

  try {
    activateTab('org');
    setDemoStatus('Running checks on the sample account…');

    const demo = await api('/api/demo/run');
    // Keep a live snapshot in memory so they can re-query who-can themselves
    await loadDemoSnapshot();
    $('#orgAction').value = demo.action;
    $('#orgResource').value = demo.resource;
    renderWhoCan(demo.who);
    renderReachAdmin(demo.reach);
    renderResourceExposure(demo.exposure);

    const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
    setDemoStatus(
      `Done. ${plural(demo.who.rows.length, 'principal', 'principals')} can delete prod-1, ${plural(demo.reach.results.length, 'principal', 'principals')} can reach administrator, ${plural(demo.exposure.findings.length, 'resource exposure', 'resource exposures')}. Try another action below or upload your own snapshot.`,
      true,
    );
    const hero = $('#hero');
    if (hero) hero.classList.add('hero-compact');
  } catch (e) {
    setDemoStatus(`Sample check failed: ${e.message}`, false);
    alert(`Sample check failed: ${e.message}`);
  } finally {
    state.demoRunning = false;
    if (btn) { btn.disabled = false; btn.textContent = 'Run sample account check'; }
  }
}

// ---------------------------------------------------------------------------
// Analyze + findings
// ---------------------------------------------------------------------------
$('#analyzeBtn').onclick = analyze;

async function analyze() {
  // Convenience: analyze pasted text directly without pressing Add first
  if (!state.docs.length && $('#pasteBox').value.trim()) $('#addPaste').onclick();
  if (!state.docs.length) { alert('Add at least one policy document first.'); return; }
  const btn = $('#analyzeBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin">◐</span> Analysing…';
  try {
    state.analysis = await api('/api/analyze', { documents: state.docs });
    renderFindings();
    renderStatements();
    activateTab('findings');
  } catch (e) {
    alert(`Analysis failed: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyse policies';
  }
}

function snippetHtml(ev) {
  const lines = ev.snippet.split('\n');
  let html = '<pre class="snippet">';
  lines.forEach((ln, i) => {
    html += `<span class="cl"><span class="ln">${ev.line + i}</span>${esc(ln)}</span>`;
  });
  if (ev.truncated) html += `<span class="cl"><span class="ln">…</span>(truncated; the statement ends at line ${ev.endLine})</span>`;
  return html + '</pre>';
}

function renderFindings() {
  const a = state.analysis;
  const wrap = $('#findingsList');
  const sum = $('#severitySummary');
  wrap.innerHTML = '';
  sum.innerHTML = '';

  const real = a.findings.filter((f) => f.severity !== 'info');
  $('#findingCount').textContent = real.length || '';

  for (const [sev, n] of Object.entries(a.counts)) {
    if (!n) continue;
    sum.appendChild(el('span', `sev-chip sev-${sev}`, `${n} ${sev}`));
  }
  sum.appendChild(el('span', 'sev-chip', `${a.statements.length} statements · ${a.documents.map((d) => `${esc(d.name)} (${d.provider})`).join(', ')}`));

  // At-a-glance grant scope from the action catalogue.
  if (a.blast && a.blast.total) {
    const tone = a.blast.permissionsManagement ? 'sev-high' : (a.blast.mutating ? 'sev-medium' : '');
    sum.appendChild(el('span', `sev-chip ${tone}`, `grants ${blastLine(a.blast)}`));
  }
  renderAskScope(a.blast);

  if (!a.findings.length) {
    wrap.appendChild(el('p', 'empty', 'The rule engine found nothing. The rules check known risky patterns, so a clean result does not prove the policy is safe. The Statements tab shows the full permission model.'));
    return;
  }

  for (const f of a.findings) wrap.insertAdjacentHTML('beforeend', findingCardHtml(f));
  wireCites(wrap);
}

// Build a finding card's HTML — shared by the Findings tab and the Org tab's
// resource-policy exposures so both render identically.
function findingCardHtml(f) {
  const evidence = f.evidence.map((ev) => `
    <div class="evidence">
      <div class="evidence-label">${esc(ev.doc)}, lines ${ev.line}–${ev.endLine}</div>
      ${snippetHtml(ev)}
    </div>`).join('');
  const rem = f.remediation ? `
    <details class="remediation"><summary>Suggested fix</summary>
      <div class="rem-body">${md(f.remediation.summary || '')}
      ${f.remediation.rewrite ? `<pre>${esc(f.remediation.rewrite)}</pre>` : ''}</div>
    </details>` : '';
  return `<div class="finding ${f.severity}">
    <h3><span class="badge ${f.severity}">${f.severity}</span> ${esc(f.title)} <span class="rule-id">${esc(f.ruleId)}</span></h3>
    <p class="desc">${md(f.description)}</p>
    ${evidence}${rem}</div>`;
}

// ---------------------------------------------------------------------------
// Statements tab
// ---------------------------------------------------------------------------
function renderStatements() {
  const a = state.analysis;
  $('#stmtEmpty').style.display = 'none';
  const rows = a.statements.map((s) => `
    <tr id="stmt-${s.id}">
      <td>${s.id}</td>
      <td>${esc(s.doc)}:${s.line}</td>
      <td>${esc(s.provider)}/${esc(s.kind)}</td>
      <td class="effect-${esc(s.effect)}">${esc(s.effect)}</td>
      <td>${s.principals.map((p) => esc(p.id)).join('<br>') || '<i>(attached identity)</i>'}</td>
      <td>${s.actions.map(esc).join('<br>') || (s.notActions.length ? `<b>NOT:</b> ${s.notActions.map(esc).join(', ')}` : '')}</td>
      <td class="grants" title="Concrete AWS actions this statement grants (W = write, P = permissions-management)">${grantsCell(s)}</td>
      <td>${s.resources.map(esc).join('<br>')}</td>
      <td>${s.conditions ? esc(JSON.stringify(s.conditions)) : '—'}</td>
    </tr>`).join('');
  $('#stmtTableWrap').innerHTML = `<table class="stmt">
    <thead><tr><th>ID</th><th>Source</th><th>Type</th><th>Effect</th><th>Principals</th><th>Actions / Roles</th><th>Grants</th><th>Resources</th><th>Conditions</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function wireCites(container) {
  container.querySelectorAll('.cite').forEach((c) => {
    c.onclick = () => {
      activateTab('statements');
      const row = document.getElementById(`stmt-${c.dataset.stmt}`);
      if (row) {
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        row.classList.remove('flash');
        void row.offsetWidth;
        row.classList.add('flash');
      }
    };
  });
}

// ---------------------------------------------------------------------------
// Ask tab
// ---------------------------------------------------------------------------
$('#askBtn').onclick = ask;
$('#askInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') ask(); });
document.querySelectorAll('.suggest-chip').forEach((c) => {
  c.onclick = () => { $('#askInput').value = c.textContent; ask(); };
});

async function ask() {
  const q = $('#askInput').value.trim();
  if (!q) return;
  if (!state.docs.length) { alert('Add at least one policy document first.'); return; }
  $('#askInput').value = '';
  const log = $('#chatLog');
  log.appendChild(el('div', 'msg q', esc(q)));
  const pending = el('div', 'msg a', '<span class="spin">◐</span> Analysing…');
  log.appendChild(pending);
  pending.scrollIntoView({ behavior: 'smooth' });
  try {
    const r = await api('/api/ask', {
      documents: state.docs,
      question: q,
      redactIdentifiers: $('#redactToggle').checked,
    });
    const modeHtml = r.mode === 'ai'
      ? `<span class="m-ai">◆ Claude (${esc(r.aiModel || '')})</span> · explaining the engine's results`
      : `<span class="m-det">◆ deterministic engine</span> · no AI used`;
    let inner = `<div class="mode">${modeHtml}</div>${md(r.text)}`;
    if (r.mode === 'ai' && r.engineText && r.engineText !== r.text) {
      inner += `<details class="facts"><summary>Show the engine's answer</summary>${md(r.engineText)}</details>`;
    }
    if (r.aiError) inner += `<div class="ai-error">AI unavailable (${esc(r.aiError)}). Showing the engine's answer.</div>`;
    pending.innerHTML = inner;
    wireCites(pending);
    renderAskScope(r.blast);
    if (!state.analysis) { state.analysis = await api('/api/analyze', { documents: state.docs }); renderStatements(); renderFindings(); }
  } catch (e) {
    pending.innerHTML = `<div class="ai-error">${esc(e.message)}</div>`;
  }
  pending.scrollIntoView({ behavior: 'smooth' });
}

// ---------------------------------------------------------------------------
// Compare tab
// ---------------------------------------------------------------------------
let changeRevision = 0;
let correctionRevision = 0;
let changeRecord = null;
let changeBusy = false;

function changeError(message, target = '#compareResult') {
  $(target).innerHTML = `<p class="ai-error" role="alert">${esc(message)} Repair the inputs and run the check again.</p>`;
}

function invalidateChange() {
  changeRevision += 1;
  correctionRevision += 1;
  changeRecord = null;
  $('#exportChange').disabled = true;
  $('#changeStatus').textContent = 'Inputs changed. Previous results are stale; review this change again.';
  $('#compareResult').classList.add('stale');
  if (!$('#compareResult .stale-label')) $('#compareResult').insertAdjacentHTML('afterbegin', '<p class="stale-label">Stale result — inputs changed. Run a new review.</p>');
  $('#correctionResult').innerHTML = '';
  $('#correctionCheck').hidden = true;
  $('#candidateHint').hidden = false;
}

function invalidateCorrection() {
  correctionRevision += 1;
  if (changeRecord) changeRecord.correction = null;
  $('#correctionResult').innerHTML = '<p class="change-status">Correction inputs changed. Verify again before relying on this candidate.</p>';
}

async function fingerprint(inputs) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(inputs)));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function currentChangeInputs() {
  const context = JSON.parse($('#compareContext').value);
  if (!context || typeof context !== 'object' || Array.isArray(context)) throw new Error('Condition context must be a JSON object.');
  const inputs = { before: $('#beforeBox').value, after: $('#afterBox').value, action: $('#compareAction').value.trim(), resource: $('#compareResource').value.trim(), context, useAI: $('#changeUseAI').checked };
  if (!inputs.before.trim() || !inputs.after.trim()) throw new Error('Paste both the current and proposed policies.');
  if (!inputs.action || !inputs.resource) throw new Error('Declare both the sensitive action and resource.');
  JSON.parse(inputs.before); JSON.parse(inputs.after);
  return inputs;
}

function evidenceLines(evaluation) {
  const matches = [...(evaluation.allowMatches || []), ...(evaluation.conditionalAllows || []), ...(evaluation.denyMatches || [])];
  return matches.length ? matches.map(item => `<li><code>${esc(item.id)}</code> ${esc(item.doc)}:${esc(item.line)}${item.sid ? ` · ${esc(item.sid)}` : ''}</li>`).join('') : '<li>No matching statement; implicit deny in the supplied document.</li>';
}

$('#compareBtn').onclick = async () => {
  if (changeBusy) return;
  const revision = changeRevision;
  changeBusy = true;
  changeRecord = null;
  $('#exportChange').disabled = true;
  $('#correctionResult').innerHTML = '';
  $('#correctionCheck').hidden = true;
  const btn = $('#compareBtn');
  btn.disabled = true; btn.textContent = 'Reviewing…';
  try {
    const inputs = currentChangeInputs();
    const inputIdentity = await fingerprint(inputs);
    const r = await api('/api/change/review', { ...inputs, redactIdentifiers: true });
    if (revision !== changeRevision) return;
    changeRecord = { schemaVersion: r.schemaVersion, engine: r.engine, inputIdentity, inputs, review: r, correction: null, createdAt: new Date().toISOString() };
    const accessTone = r.verdict.status === 'stop' ? 'review-stop' : r.verdict.status === 'review' ? 'review-context' : 'review-pass';
    const evidence = r.evidence.length ? r.evidence.map(item => {
      const statement = r.statements.after.find(s => s.id === item.id);
      return `<li><code>${esc(item.id)}</code> ${esc(item.doc)}:${esc(item.line)} · ${esc(item.sid || 'Unnamed statement')}${statement ? `<pre>${esc(JSON.stringify({ Sid: statement.sid, Effect: statement.effect, Action: statement.actions, Resource: statement.resources, ...(statement.notActions?.length ? { NotAction: statement.notActions } : {}), ...(statement.notResources?.length ? { NotResource: statement.notResources } : {}), ...(Object.keys(statement.conditions || {}).length ? { Condition: statement.conditions } : {}) }, null, 2))}</pre>` : ''}</li>`;
    }).join('') : '<li>No matching allow or deny statement for this request.</li>';
    $('#compareResult').classList.remove('stale');
    $('#compareResult').innerHTML = `<div class="verdict ${accessTone}"><span>${esc(r.verdict.label)}</span><b>${esc(r.access.before.decision)} → ${esc(r.access.after.decision)}</b><p>${esc(r.verdict.reason)}</p></div>
      <h4>Granting evidence</h4><ul class="grant-evidence">${evidence}</ul>
      <details><summary>Rule findings and suggested corrections</summary>${md(r.suggestedCorrections.map(item => `- ${item.title}: ${item.summary || 'Inspect the introduced statement.'}`).join('\n') || 'No automatic rewrite is offered.')}${r.findings.introduced.map(f => `<p>${esc(f.ruleId)}: ${esc(f.title)}</p>`).join('')}</details>
      <p class="input-identity">Input SHA-256 <code>${esc(inputIdentity)}</code></p>
      ${r.ai ? `<details class="review-explanation"><summary>Optional AI explanation · ${esc(r.ai.model)}</summary>${md(r.ai.text)}</details>` : r.aiError ? `<p class="ai-error">Optional AI explanation unavailable: ${esc(r.aiError)} Engine result remains available.</p>` : ''}`;
    $('#changeStatus').textContent = 'Current deterministic result. The original proposal remains separate from any corrected candidate.';
    $('#correctionCheck').hidden = false;
    $('#candidateHint').hidden = true;
    $('#changeInputs').open = false;
    $('#exportChange').disabled = false;
  } catch (e) {
    if (revision === changeRevision) { changeError(e.message); $('#changeStatus').textContent = 'Review incomplete. No current verdict or export is available.'; }
  } finally {
    changeBusy = false; btn.disabled = false; btn.textContent = 'Review this change';
  }
};

$('#loadChangeExample').onclick = async () => {
  if ($('#beforeBox').value.trim() && !confirm('Replace the policies and request fields with the synthetic example?')) return;
  const button = $('#loadChangeExample'); button.disabled = true;
  try {
    const values = await Promise.all(['before', 'after', 'corrected'].map(async name => {
      const response = await fetch(`/samples/aws-change-${name}.json`);
      if (!response.ok) throw new Error('The example could not load. Retry or paste two policies.');
      return response.text();
    }));
    invalidateChange();
    $('#beforeBox').value = values[0]; $('#afterBox').value = values[1]; $('#candidateBox').value = values[2];
    $('#compareAction').value = 'rds:DeleteDBInstance'; $('#compareResource').value = 'arn:aws:rds:eu-west-1:111122223333:db:prod-1';
    $('#compareContext').value = '{}'; $('#requiredAction').value = 's3:GetObject'; $('#requiredResource').value = 'arn:aws:s3:::reports/daily.csv';
    $('#changeUseAI').checked = false;
    await $('#compareBtn').onclick();
  } catch (e) { changeError(e.message); }
  finally { button.disabled = false; }
};

$('#verifyCorrectionBtn').onclick = async () => {
  const record = changeRecord;
  if (!record) { changeError('Review the current proposal before verifying a correction.', '#correctionResult'); return; }
  const revision = changeRevision, candidateRevision = correctionRevision;
  const button = $('#verifyCorrectionBtn'); button.disabled = true;
  record.correction = null;
  $('#correctionResult').innerHTML = '';
  try {
    const candidate = $('#candidateBox').value;
    const requiredAction = $('#requiredAction').value.trim(), requiredResource = $('#requiredResource').value.trim();
    if (!candidate.trim() || !requiredAction || !requiredResource) throw new Error('Supply a corrected policy and both required action and resource.');
    JSON.parse(candidate);
    const inputs = { proposed: record.inputs.after, candidate, riskRequest: { action: record.inputs.action, resource: record.inputs.resource, context: record.inputs.context }, requiredAccess: [{ action: requiredAction, resource: requiredResource, context: record.inputs.context }] };
    const inputIdentity = await fingerprint(inputs);
    const r = await api('/api/change/verify', inputs);
    if (revision !== changeRevision || candidateRevision !== correctionRevision || record !== changeRecord) return;
    record.correction = { inputIdentity, inputs, result: r };
    $('#correctionResult').innerHTML = `<div class="verdict ${r.verified ? 'review-pass' : 'review-stop'}"><span>${r.verified ? 'Correction verified for declared requests' : 'Correction not verified'}</span><b>${esc(r.risk.proposed.decision)} → ${esc(r.risk.candidate.decision)}</b><p>Risk closed: ${r.riskClosed ? 'yes' : 'no'} · required access preserved: ${r.requiredPreserved ? 'yes' : 'no'}</p></div>
      <p>New high or critical findings: ${r.introducedSevere.length}</p>${r.introducedSevere.map(finding => `<p class="ai-error">${esc(finding.ruleId)}: ${esc(finding.title)}</p>`).join('')}
      <h4>Risk request in corrected policy</h4><ul>${evidenceLines(r.risk.candidate)}</ul>
      ${r.preservation.map(item => `<h4>Required: ${esc(item.request.action)}</h4><p>${esc(item.before.decision)} → ${esc(item.after.decision)}</p><ul>${evidenceLines(item.after)}</ul>`).join('')}
      <p class="review-limits">${r.limits.map(esc).join(' ')}</p>`;
    if (r.verified) $('#correctionCheck').open = false;
  } catch (e) {
    if (revision === changeRevision && candidateRevision === correctionRevision) changeError(e.message, '#correctionResult');
  } finally { button.disabled = false; }
};

$('#exportChange').onclick = () => {
  if (!changeRecord) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(changeRecord, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'policylens-review.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
['beforeBox', 'afterBox', 'compareAction', 'compareResource', 'compareContext', 'changeUseAI'].forEach(id => $(`#${id}`).addEventListener('input', invalidateChange));
['candidateBox', 'requiredAction', 'requiredResource'].forEach(id => $(`#${id}`).addEventListener('input', invalidateCorrection));
document.querySelectorAll('[data-editor]').forEach(button => button.addEventListener('click', () => {
  document.querySelector('.compare-inputs').dataset.editorPane = button.dataset.editor;
  document.querySelectorAll('[data-editor]').forEach(other => other.setAttribute('aria-pressed', String(other === button)));
}));

// ---------------------------------------------------------------------------
// Org tab — whole-account reachability over a snapshot
// ---------------------------------------------------------------------------

// Shape a citation object {doc,line,sid} as clickable-looking evidence text.
// (These reference statements inside the snapshot's policies, so we show the
// source location rather than cross-linking to the single-policy Statements tab.)
function citeText(v) {
  return `<span class="org-cite">${esc(v.doc)}:${v.line}${v.sid ? ` (${esc(v.sid)})` : ''}</span>`;
}

function setSnapshotStatus(text, ok) {
  const el = $('#snapshotStatus');
  el.textContent = text;
  el.classList.toggle('loaded', !!ok);
  $('#orgCaveat').hidden = !ok;
}

function orgApiReady() {
  if (!state.snapshot) { alert('Load a snapshot first, for example with "Load sample snapshot".'); return false; }
  return true;
}

$('#loadDemoSnapshot').onclick = async () => {
  try {
    await loadDemoSnapshot();
  } catch (e) {
    setSnapshotStatus(`Could not load the sample snapshot: ${e.message}`, false);
  }
};

$('#runDemoBtn').onclick = () => runNinetySecondDemo();
$('#heroAnalyzeHint').onclick = () => {
  activateTab('findings');
  $('#pasteBox')?.focus();
};

$('#snapshotFile').onchange = async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    state.snapshot = JSON.parse(await file.text());
    const n = (state.snapshot.UserDetailList || []).length + (state.snapshot.RoleDetailList || []).length;
    setSnapshotStatus(`${esc(file.name)} loaded: ${n} principals.`, true);
  } catch (err) {
    setSnapshotStatus(`Invalid snapshot JSON: ${err.message}`, false);
  }
  e.target.value = '';
};

$('#orgWhoCanBtn').onclick = async () => {
  if (!orgApiReady()) return;
  const action = $('#orgAction').value.trim();
  if (!action) { alert('Enter an action, e.g. rds:DeleteDBInstance'); return; }
  const resource = $('#orgResource').value.trim();
  const wrap = $('#orgWhoCanResult');
  wrap.innerHTML = '<p class="empty"><span class="spin">◐</span> Checking every principal…</p>';
  try {
    const r = await api('/api/org/whocan', { snapshot: state.snapshot, action, resource: resource || undefined });
    renderWhoCan(r);
  } catch (e) {
    wrap.innerHTML = `<div class="ai-error">${esc(e.message)}</div>`;
  }
};

function renderWhoCan(r) {
  const wrap = $('#orgWhoCanResult');
  const head = `<div class="org-result-head"><b>${r.rows.length}</b> of ${r.principals} principals can run <code>${esc(r.action)}</code> on <code>${esc(r.resource)}</code>.</div>`;
  if (!r.rows.length) {
    wrap.innerHTML = `${head}<p class="empty">No principal in the snapshot is granted this. <span class="org-caveat-inline">${esc(r.caveat)}</span></p>`;
    return;
  }
  const rows = r.rows.map((row) => {
    const badge = row.decision === 'ConditionalAllow'
      ? '<span class="badge medium" title="Allowed only when a condition holds">conditional</span>'
      : '<span class="badge high">allowed</span>';
    const vis = row.incompleteVisibility
      ? `<div class="org-warn">Some managed-policy documents are missing from the snapshot, so this may under-report: ${row.incompleteVisibility.map(esc).join(', ')}</div>`
      : '';
    return `<tr>
      <td>${esc(row.name)} <span class="org-type">${esc(row.type)}</span></td>
      <td>${badge}</td>
      <td>${row.via.map(citeText).join('<br>') || '—'}${vis}</td>
    </tr>`;
  }).join('');
  wrap.innerHTML = `${head}
    <div class="tablewrap"><table class="stmt">
      <thead><tr><th>Principal</th><th>Decision</th><th>Granted by</th></tr></thead>
      <tbody>${rows}</tbody></table></div>
    <p class="org-caveat-inline">${esc(r.caveat)}</p>`;
}

$('#orgReachBtn').onclick = async () => {
  if (!orgApiReady()) return;
  const wrap = $('#orgReachResult');
  wrap.innerHTML = '<p class="empty"><span class="spin">◐</span> Finding admin paths…</p>';
  try {
    const r = await api('/api/org/reach-admin', { snapshot: state.snapshot });
    renderReachAdmin(r);
  } catch (e) {
    wrap.innerHTML = `<div class="ai-error">${esc(e.message)}</div>`;
  }
};

function renderReachAdmin(r) {
  const wrap = $('#orgReachResult');
  const head = `<div class="org-result-head"><b>${r.results.length}</b> of ${r.principals} principals can reach administrator.</div>`;
  if (!r.results.length) {
    wrap.innerHTML = `${head}<p class="empty">No principal can reach administrator through the modelled routes. <span class="org-caveat-inline">${esc(r.caveat)}</span></p>`;
    return;
  }
  const nodeLabel = (a) => (a === '__admin__' ? 'administrator' : esc(a.split('/').pop()));
  const cards = r.results.map((res) => {
    // Render the path as node →[how] node →[how] node, where each "how" labels
    // the edge (assume / escalation step) between principals.
    let chain = `<span class="path-node">${nodeLabel(res.path[0].arn)}</span>`;
    for (let i = 1; i < res.path.length; i++) {
      const step = res.path[i];
      chain += `<span class="path-edge"><span class="path-arrow">→</span><span class="path-how">${esc(step.how || '')}</span></span>`;
      chain += `<span class="path-node">${nodeLabel(step.arn)}</span>`;
    }
    // Collect the unique granting statements across every step of the path.
    const cites = [];
    const seen = new Set();
    for (const step of res.path) for (const v of (step.via || [])) {
      const key = `${v.doc}:${v.line}`;
      if (!seen.has(key)) { seen.add(key); cites.push(v); }
    }
    const citeLine = cites.length ? `<div class="reach-cites">granted by ${cites.map(citeText).join(', ')}</div>` : '';
    const hops = res.hops ? `<span class="reach-hops">${res.hops} hop${res.hops > 1 ? 's' : ''}</span>` : '';
    return `<div class="reach-card">
      <div class="reach-head"><b>${esc(res.name)}</b> <span class="org-type">${esc(res.type)}</span> <span class="reach-reason">${esc(res.reason)}</span>${hops}</div>
      <div class="reach-path">${chain}</div>
      ${citeLine}
    </div>`;
  }).join('');
  wrap.innerHTML = `${head}${cards}<p class="org-caveat-inline">${esc(r.caveat)}</p>`;
}

$('#orgResourceBtn').onclick = async () => {
  if (!orgApiReady()) return;
  const wrap = $('#orgResourceResult');
  wrap.innerHTML = '<p class="empty"><span class="spin">◐</span> Scanning resource policies…</p>';
  try {
    const r = await api('/api/org/resource-exposure', { snapshot: state.snapshot });
    renderResourceExposure(r);
  } catch (e) {
    wrap.innerHTML = `<div class="ai-error">${esc(e.message)}</div>`;
  }
};

function renderResourceExposure(r) {
  const wrap = $('#orgResourceResult');
  const acct = r.accountId ? ` in account ${esc(r.accountId)}` : '';
  const head = `<div class="org-result-head">Scanned <b>${r.supplied}</b> resource ${r.supplied === 1 ? 'policy' : 'policies'}${acct}. Found <b>${r.findings.length}</b> ${r.findings.length === 1 ? 'exposure' : 'exposures'}.</div>`;
  if (!r.supplied) {
    wrap.innerHTML = `${head}<p class="empty">This snapshot has no resource policies. Add a <code>ResourcePolicies</code> array (KMS key policies, S3 bucket policies and so on) to scan them.</p>`;
    return;
  }
  if (!r.findings.length) {
    wrap.innerHTML = `${head}<p class="empty">No external or public grants found in the supplied resource policies. <span class="org-caveat-inline">${esc(r.caveat)}</span></p>`;
    return;
  }
  wrap.innerHTML = `${head}${r.findings.map(findingCardHtml).join('')}<p class="org-caveat-inline">${esc(r.caveat)}</p>`;
}

// ---------------------------------------------------------------------------
// Tabs + boot
// ---------------------------------------------------------------------------
function activateTab(name) {
  document.body.classList.toggle('change-view', name === 'compare');
  document.querySelectorAll('.tab').forEach((t) => {
    t.classList.toggle('active', t.dataset.tab === name);
    if (t.dataset.tab === name) t.setAttribute('aria-current', 'page'); else t.removeAttribute('aria-current');
  });
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === `panel-${name}`));
}
document.querySelectorAll('.tab').forEach((t) => { t.onclick = () => activateTab(t.dataset.tab); });

(async function boot() {
  loadSamples();
  const params = new URLSearchParams(location.search);
  const wantDemo = params.has('demo') || params.get('auto') === '1';
  activateTab(wantDemo || params.get('view') === 'org' ? 'org' : 'compare');

  try {
    const h = await api('/api/health');
    state.aiEnabled = h.ai;
    state.hosted = !!h.hosted;
    const pill = $('#aiPill');
    if (h.ai) { pill.textContent = `AI: ${h.model}`; pill.classList.add('on'); }
    else { pill.textContent = 'AI off: engine answers only'; pill.title = 'Set ANTHROPIC_API_KEY and restart to enable free-form questions.'; }

    // Public demo: swap the “local” claim so hosted-demo visitors aren't misled
    const localPill = document.querySelector('.pill.local');
    if (state.hosted && localPill) {
      localPill.textContent = 'Public demo: do not paste secrets';
      localPill.classList.remove('local');
      localPill.classList.add('warn');
    }
    const banner = $('#hostedBanner');
    if (banner) banner.hidden = !state.hosted;

    // Hosted demo link is /?demo=1 — auto-run so one click = value
    // Hosted cold start also auto-runs unless ?skipdemo=1
    const skip = params.has('skipdemo');
    if (wantDemo || (state.hosted && !skip && params.get('view') === 'org')) {
      await runNinetySecondDemo();
    }
  } catch { $('#aiPill').textContent = 'Server unreachable'; }
})();
