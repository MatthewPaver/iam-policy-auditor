import { createWalkthrough } from './walkthrough.js';
import { createDiagram } from './diagram.js';
const $ = selector => document.querySelector(selector);
const reduced = matchMedia('(prefers-reduced-motion: reduce)');
const riskRequest = { action: 'rds:DeleteDBInstance', resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1', context: {} };
const requiredAccess = [{ action: 's3:GetObject', resource: 'arn:aws:s3:::reports/daily.csv', context: {} }];
const blockAll = JSON.stringify({ Version: '2012-10-17', Statement: [{ Sid: 'BlockAllAccess', Effect: 'Deny', Action: '*', Resource: '*' }] }, null, 2);
const names = { keep: 'Proposed access', block: 'Block everything', reports: 'Keep report access only' };
const initialRows = ['Structure package', 'Services package', 'Fit-out package'];
let texts, record, original = null, choice = 'keep', revision = 0, acting = false;
let comparisons = {};
const flat = createDiagram($('#diagram'));
let sandbox = freshSandbox();
let guide, guided = new URLSearchParams(location.search).get('mode') !== 'manual';
function freshSandbox() { return { reportOpened: false, rows: [...initialRows], actions: [] }; }
const hash = async input => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(input))))].map(x => x.toString(16).padStart(2, '0')).join('');
const describe = decision => ({ Allow: 'Allowed', ExplicitDeny: 'Blocked', ImplicitDeny: 'Blocked', ConditionalAllow: 'Needs information' })[decision] || 'Not determined';
const completed = () => sandbox.actions.length === 2;

async function load() {
  $('#error').hidden = true; $('#attempt').disabled = true;
  try {
    texts = await Promise.all(['before', 'after', 'corrected'].map(async name => {
      const response = await fetch(`../samples/aws-change-${name}.json`);
      if (!response.ok) throw new Error('The sample policies could not load.');
      return response.text();
    }));
    if (!window.PolicyLensLocalAPI) throw new Error('The policy engine did not load.');
    await prepareComparisons();
    await selectChoice('keep');
    if (!guide) initializeWalkthrough();
  } catch (error) { fail(error); }
}
function fail(error) {
  record = null; $('#rehearsal').dataset.ready = 'false';
  $('#error').hidden = false; $('#error p').textContent = `${error.message} No current check is available. Retry the example.`;
  $('#attempt').disabled = true; $('#download').disabled = true; $('#choices').disabled = true;
  $('#actionStatus').textContent = 'Check unavailable.';
}
function syncControls() {
  $('#attempt').disabled = acting || !record || guided;
  $('#choices').disabled = acting || !record || !original || guided;
  $('#rewind').disabled = acting || !record || guided;
  $('#reset').disabled = acting || guided;
}
async function prepareComparisons() {
  comparisons = {};
  for (const key of ['keep', 'block', 'reports']) {
    const candidate = key === 'keep' ? texts[1] : key === 'block' ? blockAll : texts[2];
    const inputs = { proposed: texts[1], candidate, riskRequest, requiredAccess };
    const result = await window.PolicyLensLocalAPI('/api/change/verify', inputs);
    comparisons[key] = { inputs, result, inputIdentity: await hash(inputs) };
  }
}
async function selectChoice(value) {
  if (acting) return;
  const current = ++revision; choice = value; record = null; sandbox = freshSandbox();
  $('#rehearsal').dataset.ready = 'false'; $('#attempt').disabled = true; $('#download').disabled = true; $('#choices').disabled = true;
  $('#downloadStatus').textContent = ''; $('#actionStatus').textContent = 'Checking the selected policy…';
  renderSandbox(); renderComparison(); renderConclusion(); renderEvidence();
  $('#sourceMeaning').textContent = 'Checking the selected candidate. Previous candidate verification is cleared.';
  $('#statementChanges').replaceChildren();
  try {
    const candidate = value === 'keep' ? texts[1] : value === 'block' ? blockAll : texts[2];
    const inputs = { before: texts[0], after: texts[1], ...riskRequest, useAI: false };
    const correctionInputs = { proposed: texts[1], candidate, riskRequest, requiredAccess };
    const review = await window.PolicyLensLocalAPI('/api/change/review', inputs);
    const result = await window.PolicyLensLocalAPI('/api/change/verify', correctionInputs);
    const inputIdentity = await hash(inputs), correctionIdentity = await hash(correctionInputs);
    if (current !== revision) return;
    record = { schemaVersion: review.schemaVersion, engine: review.engine, inputIdentity, inputs, review, correction: { inputIdentity: correctionIdentity, inputs: correctionInputs, result }, createdAt: new Date().toISOString() };
    $('#rehearsal').dataset.ready = 'true'; $('#rehearsal').dataset.choice = choice;
    $('#attempt').disabled = false; $('#download').disabled = false; $('#rewind').disabled = false; $('#choices').disabled = !original;
    $('#runTitle').textContent = names[choice];
    $('#actionStatus').textContent = original ? 'Same starting data. Try both tasks again.' : 'The role needs its report. Try opening it.';
    $('#sceneStatus').textContent = guided ? 'The guide will try both requests.' : 'Use Open sample report, or select its request above.';
    renderSandbox(); renderComparison(); renderEvidence(); renderConclusion();
  } catch (error) { if (current === revision) fail(error); }
}

function renderSandbox() {
  $('#rehearsal').dataset.actions = String(sandbox.actions.length); $('#rehearsal').dataset.acting = String(acting);
  $('#reportPreview').hidden = !sandbox.reportOpened;
  $('#databasePreview').hidden = !sandbox.actions.some(a => a.task === 'database');
  $('#databaseRows').hidden = sandbox.rows.length === 0; $('#databaseEmpty').hidden = sandbox.rows.length > 0;
  $('#diagramDatabase').textContent = sandbox.rows.length ? `${sandbox.rows.length} fictional rows` : 'Example data removed';
  $('#diagramReports').textContent = sandbox.reportOpened ? 'Sample report open' : 'daily.csv';
  $('#diagramPolicyName').textContent = names[choice];
  for (const [index, subject, target] of [[0, 'reports', '#diagramReadDecision'], [1, 'database', '#diagramDeleteDecision']]) {
    const action = sandbox.actions[index], element = $(`[data-task=${subject}]`);
    $(target).textContent = action ? describe(action.decision) : 'Not tried';
    element.dataset.decision = action?.decision || ''; element.dataset.complete = String(Boolean(action));
  }
  $('#reportTaskState').textContent = sandbox.actions[0] ? describe(sandbox.actions[0].decision) : 'Ready';
  $('#databaseTaskState').textContent = sandbox.actions[1] ? describe(sandbox.actions[1].decision) : sandbox.actions.length ? 'Ready' : 'Next';
  $('#reportTask').setAttribute('aria-current', sandbox.actions.length === 0 ? 'step' : 'false'); $('#databaseTask').setAttribute('aria-current', sandbox.actions.length === 1 ? 'step' : 'false');
  if (!sandbox.actions.length) {
    $('#taskTitle').textContent = 'Start with the work that matters.';
    $('#taskDescription').textContent = 'Open daily.csv, the stored report this role needs to read.';
    $('#attempt').textContent = 'Open sample report';
  } else if (sandbox.actions.length === 1) {
    $('#attempt').textContent = 'Try deletion in sandbox';
  } else {
    $('#attempt').textContent = choice === 'keep' ? 'Try a correction' : 'Try another correction';
  }
  syncControls();
}
async function attempt({ signal, checkpoint } = {}) {
  if (!record || acting || (guided && !signal)) return;
  if (completed()) { $('#intervention').scrollIntoView({ block: 'center', behavior: reduced.matches ? 'instant' : 'smooth' }); $('[name=candidate]:checked').focus({ preventScroll: true }); return; }
  acting = true;
  $('#rehearsal').dataset.acting = 'true';
  $('#choices').disabled = true; $('#attempt').disabled = true; $('#rewind').disabled = true; $('#reset').disabled = true; $('#download').disabled = true;
  const task = sandbox.actions.length === 0 ? 'reports' : 'database';
  const decision = task === 'reports' ? record.correction.result.preservation[0].after.decision : record.correction.result.risk.candidate.decision;
  const permitted = decision === 'Allow';
  $('#actionStatus').textContent = task === 'reports' ? 'Following the report request through the policy…' : 'Following the deletion request through the policy…';
  $('#sceneStatus').textContent = task === 'reports' ? 'Request: open daily.csv' : 'Request: delete prod-1 in the sandbox';
  try {
    if (!reduced.matches) await flat.run(task);
    if (signal?.aborted) return;
    if (checkpoint) await checkpoint();
    if (signal?.aborted) return;
    if (task === 'reports') {
      sandbox.reportOpened = permitted;
      $('#taskTitle').textContent = permitted ? 'The sample report opens.' : 'The report cannot open.';
      $('#taskDescription').textContent = permitted ? 'The supplied policy allows this read. Now try the permission that should be absent.' : 'This policy stops legitimate work too. Now check what happens to database deletion.';
    } else {
      if (permitted) sandbox.rows = [];
      $('#taskTitle').textContent = permitted ? 'The sandbox data is removed.' : 'The sandbox data stays.';
      $('#taskDescription').textContent = permitted ? 'The policy permits deletion. This fictional sandbox enacts that consequence; no AWS request is made.' : decision === 'ConditionalAllow' ? 'Missing information prevents a definite decision. The sandbox leaves data unchanged.' : 'The policy does not permit the checked deletion request. The sandbox leaves all three rows in place.';
    }
    sandbox.actions.push({ task: task === 'reports' ? 'report' : 'database', decision, permissionSource: 'PolicyLens deterministic engine', sandboxEffect: task === 'reports' ? permitted ? 'sample report revealed' : 'sample report withheld' : permitted ? 'fictional rows cleared' : 'fictional rows retained' });
    if (!guided) $('#sampleData').open = true;
    if (completed() && !original) original = { policy: 'Proposed access', engineRecord: structuredClone(record), sandbox: structuredClone(sandbox) };
    renderSandbox(); renderComparison(); renderEvidence(); renderConclusion();
    $('#actionStatus').textContent = completed() ? 'Run complete. Change the policy or rewind from the same starting data.' : 'One task remains. Try deletion in the sandbox.';
    $('#sceneStatus').textContent = task === 'reports' ? permitted ? 'Report request allowed. Sample file open.' : 'Report request denied. Sample file withheld.' : permitted ? 'Deletion permitted. Fictional rows cleared in this sandbox.' : 'Deletion not permitted. Fictional rows retained.';
    $('#intervention').hidden = !original;
  } finally {
    acting = false; $('#choices').disabled = !original; $('#rewind').disabled = !record; $('#reset').disabled = false; $('#download').disabled = !record; renderSandbox();
  }
}
function initializeWalkthrough() {
  const steps = [
    { id: 'start', title: 'A new permission', intro: 'A report reader needs the report, but should never delete the database.', duration: 2000 },
    { id: 'proposed', title: 'Expose the risk', intro: 'Try both requests under the proposed access.', lead: 1600, outcome: () => record.correction.result.risk.candidate.decision === 'Allow' ? 'The report opens. Deletion is also allowed; the sandbox loses its fictional data.' : 'Inspect both request results. The expected deletion permission was not found.', duration: 3500 },
    { id: 'reports', title: 'Narrow the permission', intro: 'Remove the deletion grant. Keep report access. Start with the same fictional data.', duration: 2000 },
    { id: 'corrected', title: 'Check the correction', intro: 'Try the same two requests again.', lead: 1600, outcome: () => record.correction.result.verified ? 'Report allowed. Deletion not allowed. Both checked requirements pass.' : 'The correction is not verified. Inspect the two checked outcomes.', duration: 3000 },
    { id: 'finish', title: 'Compare the choices', intro: 'Compare all three policy choices below. Try another choice or inspect the rule.', duration: 3500 },
  ];
  guide = createWalkthrough({ steps, manual: !guided,
    motion: action => { flat[action]?.(); },
    modeChanged(value) { guided = value; $('#rehearsal').dataset.guided = String(value); syncControls(); if (value) $('#sampleData').open = false; },
    async perform(id, context) {
      if (id === 'start') { original = null; $('#intervention').hidden = true; $('[value=keep]').checked = true; await selectChoice('keep'); }
      else if (id === 'block' || id === 'reports') { $(`[value=${id}]`).checked = true; await selectChoice(id); }
      else if (id === 'proposed' || id === 'corrected') { await attempt(context); await context.checkpoint(); await attempt(context); }
      if (!record) throw new Error('The current policy check is unavailable.');
    },
  });
}
function renderConclusion() {
  const title = $('#resultTitle'), text = $('#resultDescription'); title.className = '';
  if (!completed()) { title.textContent = sandbox.actions.length ? `Report ${sandbox.reportOpened ? 'allowed' : 'blocked'}. Deletion check next.` : 'Ready to check both requests.'; text.textContent = guided ? 'The guide runs each request against the selected policy.' : 'Use the task button to check report access, then deletion.'; return; }
  const result = record.correction.result;
  title.className = result.verified ? 'good' : 'bad';
  title.textContent = result.verified ? 'The report works. The deletion is stopped.' : !result.riskClosed ? 'The report works. The deletion permission remains.' : 'The deletion stops. The report breaks too.';
  text.textContent = result.verified ? 'Verified for these two requests. Compare the three policies below.' : !result.riskClosed ? 'Needed work is allowed, but so is deletion. The correction must check both.' : 'Removing every permission also removes the read this role needs. Try preserving the report access.';
}
function renderComparison() {
  for (const [key, ids] of Object.entries({ keep: ['originalReport', 'originalDatabase', 'originalData'], block: ['blockedReport', 'blockedDatabase', 'blockedResult'], reports: ['candidateReport', 'candidateDatabase', 'candidateData'] })) {
    const check = comparisons[key]?.result;
    document.querySelector(`[data-comparison=${key}]`).setAttribute('aria-current', String(key === choice));
    if (!check) continue;
    const read = check.preservation[0].after.decision, deletion = check.risk.candidate.decision;
    const report = document.getElementById(ids[0]), database = document.getElementById(ids[1]), result = document.getElementById(ids[2]);
    report.textContent = describe(read); report.className = read === 'Allow' ? 'good' : 'bad';
    database.textContent = describe(deletion); database.className = check.riskClosed ? 'good' : 'bad';
    result.textContent = check.verified ? 'Yes · both pass' : !check.riskClosed ? 'No · deletion allowed' : 'No · report blocked';
    result.className = check.verified ? 'good' : 'bad';
  }
}
function exportedRecord() {
  if (!record) return null;
  return { ...record, comparisons: structuredClone(comparisons), simulation: { choice, synthetic: true, cloudActionsPerformed: false, model: 'Two-task authored in-memory sandbox. Engine Allow enables the authored sample action; AWS execution conditions are not modelled.', reportDependsOnDatabase: false, currentRun: structuredClone(sandbox), originalRun: original ? structuredClone(original) : null } };
}
function renderEvidence() {
  if (!record) { $('#recordJSON').textContent = ''; return; }
  const lastTask = sandbox.actions.at(-1)?.task;
  const evaluated = lastTask === 'report' ? record.correction.result.preservation[0].after : record.correction.result.risk.candidate;
  const match = [...evaluated.allowMatches, ...evaluated.denyMatches, ...evaluated.conditionalAllows][0];
  const originalEvidence = record.review.evidence.find(item => item.sid === 'DeleteProductionDatabase') || record.review.evidence[0];
  const evidence = match || originalEvidence;
  const citation = item => `${item.id} · ${item.doc}:${item.line} · ${item.sid}`;
  $('#sourceCitation').textContent = evidence ? citation(evidence) + (match?.sid === originalEvidence?.sid ? ` · Original: ${citation(originalEvidence)}` : '') : 'Inspect the exact record below.';
  $('#sourceTitle').textContent = lastTask === 'report' ? 'The rule behind report access' : match ? 'The rule behind deletion access' : 'The removed deletion grant';
  $('#sourceMeaning').textContent = lastTask === 'report' ? choice === 'block' ? 'BlockAllAccess denies the report request. The correction removes access this role still needs.' : 'ReadReports grants the checked read of daily.csv. The stored report is independent of the example database.' : choice === 'keep' ? 'This added Allow statement grants the checked deletion request. The report grant remains separate.' : choice === 'block' ? 'BlockAllAccess denies both requests. Risk closure alone is insufficient: required report access must survive.' : 'The candidate has no grant for this deletion request. It removes the original deletion statement and keeps ReadReports. The engine checks both outcomes separately.';
  const sourcePolicy = JSON.parse(match ? record.correction.inputs.candidate : record.inputs.after);
  $('#sourceStatement').textContent = JSON.stringify(sourcePolicy.Statement.find(statement => statement.Sid === evidence?.sid), null, 2);
  $('#statementChanges').innerHTML = window.PolicyLensCorrectionView.render(record.inputs.after, record.correction.inputs.candidate);
  $('#recordJSON').textContent = JSON.stringify(exportedRecord(), null, 2);
}
function inspectRule() {
  guide?.pause('Paused for evidence. Resume the walkthrough when ready.');
  $('#rule').open = true; $('#rule').scrollIntoView({ block: 'start', behavior: reduced.matches ? 'instant' : 'smooth' });
}
function inspectObject(subject) {
  if (guided) { guide?.pause('Paused for inspection. Resume or take control.'); if (subject === 'policy') inspectRule(); return; }
  if (subject === 'policy') { inspectRule(); return; }
  if ((subject === 'reports' && sandbox.actions.length === 0) || (subject === 'database' && sandbox.actions.length === 1)) { attempt(); return; }
  $('#sceneStatus').textContent = subject === 'reports' ? 'The report store is independent of the example database.' : subject === 'database' ? `Example database: ${sandbox.rows.length} fictional rows remain.` : 'The same role makes both checked requests.';
}
$('#attempt').onclick = attempt;
$('#showRule').onclick = inspectRule;
document.querySelectorAll('[data-object]').forEach(button => { button.onclick = () => inspectObject(button.dataset.object); });
document.querySelectorAll('[name=candidate]').forEach(input => { input.onchange = () => { if (input.checked) { guide?.takeControl(); selectChoice(input.value); } }; });
$('#rewind').onclick = () => { if (!acting && record && !guided) selectChoice(choice); };
$('#reset').onclick = () => { if (acting || guided) return; guide?.takeControl(); original = null; $('#intervention').hidden = true; $('[value=keep]').checked = true; $('#rule').open = false; if (texts) selectChoice('keep'); else load(); };
$('#retry').onclick = load;
$('#download').onclick = () => {
  const output = exportedRecord(); if (!output || acting) return;
  const link = document.createElement('a'), url = URL.createObjectURL(new Blob([JSON.stringify(output, null, 2)], { type: 'application/json' }));
  link.href = url; link.download = `policylens-rehearsal-${choice}.json`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  $('#downloadStatus').textContent = 'Engine evidence and separately labelled sandbox activity prepared.';
};
window.addEventListener('pagehide', () => { guide?.dispose(); flat.dispose(); });
load();
