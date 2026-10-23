/* global api, fingerprint, esc, activateTab */
'use strict';

(() => {
  const find = selector => document.querySelector(selector);
  let sampleRecord = null;
  let sampleTexts = null;
  let verificationRevision = 0;
  let verifying = false;
  const request = { action: 'rds:DeleteDBInstance', resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1', context: {} };

  async function loadExample() {
    const status = find('#exampleStatus');
    try {
      const texts = await Promise.all(['before', 'after', 'corrected'].map(async name => {
        const response = await fetch(`samples/aws-change-${name}.json`);
        if (!response.ok) throw new Error('The example could not load.');
        return response.text();
      }));
      sampleTexts = texts;
      const inputs = { before: texts[0], after: texts[1], ...request, useAI: false };
      const review = await api('/api/change/review', inputs);
      sampleRecord = { schemaVersion: review.schemaVersion, engine: review.engine, inputIdentity: await fingerprint(inputs), inputs, review, correction: null, createdAt: new Date().toISOString() };
      find('.demo-desk').dataset.ready = 'true';
      find('#demoBefore').textContent = review.access.before.decision;
      find('#demoAfter').textContent = review.access.after.decision;
      find('#demoConsequence').textContent = 'The proposal allows database deletion';
      find('#demoReason').textContent = 'The supplied proposal introduces permission to delete prod-1.';
      const evidence = review.evidence[0];
      find('#demoCitation').textContent = `${evidence.id} · ${evidence.doc}:${evidence.line} · ${evidence.sid}`;
      renderSource(false);
      ['copyDemoRequest', 'copyDemoCitation', 'copyDemoSource'].forEach(id => { find(`#${id}`).disabled = false; });
      find('#demoCandidate').value = texts[2];
      find('#verifyDemoCorrection').disabled = false;
      find('.original-outcome').innerHTML = `Original proposal: <strong>${esc(review.verdict.label)} · ${esc(review.access.before.decision)} → ${esc(review.access.after.decision)}</strong>`;
      renderRecord();
      status.textContent = '';
    } catch (error) {
      status.innerHTML = `<span role="alert">${esc(error.message)} Use your own policies or try the example again.</span> <button type="button" class="text-control" id="retryExample">Retry example</button>`;
      find('#demoConsequence').textContent = 'Example unavailable';
      find('#retryExample').onclick = () => { status.textContent = 'Loading the example through the review engine…'; loadExample(); };
    }
  }

  function setChapter(name, focus = false) {
    const panels = { risk: '#demoRisk', correction: '#demoCorrection', export: '#demoExport' };
    if (!panels[name]) return;
    document.querySelectorAll('[data-chapter]').forEach(button => {
      const selected = button.dataset.chapter === name;
      button.setAttribute('aria-selected', String(selected));
      button.tabIndex = selected ? 0 : -1;
      find(panels[button.dataset.chapter]).hidden = !selected;
    });
    find('#viewDemoPolicy').hidden = name !== 'risk';
    find('#replayTrace').hidden = name !== 'risk';
    if (name === 'export') renderRecord();
    if (focus) find(panels[name]).focus({ preventScroll: true });
  }

  document.querySelectorAll('[data-chapter]').forEach(button => {
    button.onclick = () => setChapter(button.dataset.chapter);
    button.onkeydown = event => {
      const buttons = [...document.querySelectorAll('[data-chapter]')];
      const index = buttons.indexOf(button);
      const next = event.key === 'ArrowRight' ? (index + 1) % 3 : event.key === 'ArrowLeft' ? (index + 2) % 3 : event.key === 'Home' ? 0 : event.key === 'End' ? 2 : -1;
      if (next < 0) return;
      event.preventDefault();
      setChapter(buttons[next].dataset.chapter);
      buttons[next].focus();
    };
  });
  document.querySelectorAll('[data-next]').forEach(button => { button.onclick = () => setChapter(button.dataset.next, true); });

  function renderRecord() {
    if (!sampleRecord) return;
    const correction = sampleRecord.correction;
    find('#demoRecordSummary').innerHTML = `<div><span>Original proposal</span><strong>${esc(sampleRecord.review.verdict.label)}</strong><p>${esc(sampleRecord.review.access.before.decision)} → ${esc(sampleRecord.review.access.after.decision)}</p></div>
      <div><span>Corrected candidate</span><strong>${correction ? (correction.result.verified ? 'Verified for declared requests' : 'Not verified') : 'Not checked'}</strong><p>${correction ? `Risk closed: ${correction.result.riskClosed ? 'yes' : 'no'} · required access preserved: ${correction.result.requiredPreserved ? 'yes' : 'no'}` : 'This record contains the original review only.'}</p></div>
      <p class="record-identity">Input SHA-256 <code>${esc(sampleRecord.inputIdentity)}</code></p>`;
    find('#demoRecordJSON').textContent = JSON.stringify(sampleRecord, null, 2);
    find('#exportDemoReview').disabled = false;
  }

  function invalidateExampleCorrection() {
    verificationRevision += 1;
    if (sampleRecord) sampleRecord.correction = null;
    find('#demoVerification').className = 'verification-result';
    find('#demoVerification').innerHTML = '<h3>Correction changed</h3><p>Previous verification is stale. Run the check again before relying on this candidate. The export now contains the original review only.</p>';
    find('#demoExportStatus').textContent = '';
    const action = find('#demoRequiredAction').value.trim(), resource = find('#demoRequiredResource').value.trim();
    const declared = find('.declared-request');
    declared.querySelectorAll('code')[0].textContent = action || 'Required action missing';
    declared.querySelectorAll('code')[1].textContent = resource || 'Required resource missing';
    renderRecord();
  }
  ['demoCandidate', 'demoRequiredAction', 'demoRequiredResource'].forEach(id => find(`#${id}`).addEventListener('input', invalidateExampleCorrection));

  find('#verifyDemoCorrection').onclick = async () => {
    if (!sampleRecord || verifying) return;
    const record = sampleRecord, revision = verificationRevision;
    const button = find('#verifyDemoCorrection');
    verifying = true;
    button.disabled = true;
    button.textContent = 'Verifying…';
    record.correction = null;
    renderRecord();
    find('#demoVerification').className = 'verification-result';
    find('#demoVerification').textContent = 'Checking the risk, required access and introduced findings…';
    try {
      const candidate = find('#demoCandidate').value;
      const action = find('#demoRequiredAction').value.trim(), resource = find('#demoRequiredResource').value.trim();
      if (!candidate.trim() || !action || !resource) throw new Error('Supply a corrected policy and both required action and resource.');
      JSON.parse(candidate);
      const inputs = { proposed: record.inputs.after, candidate, riskRequest: { ...request }, requiredAccess: [{ action, resource, context: {} }] };
      const identity = await fingerprint(inputs);
      const result = await api('/api/change/verify', inputs);
      if (revision !== verificationRevision || record !== sampleRecord) return;
      record.correction = { inputIdentity: identity, inputs, result };
      find('#demoVerification').classList.add(result.verified ? 'verified' : 'not-verified');
      find('#demoVerification').innerHTML = `<h3>${result.verified ? 'Correction verified for declared requests' : 'Correction not verified'}</h3>
        <dl><div><dt>Risk closed</dt><dd>${result.riskClosed ? 'Yes' : 'No'} · ${esc(result.risk.proposed.decision)} → ${esc(result.risk.candidate.decision)}</dd></div><div><dt>Required access preserved</dt><dd>${result.requiredPreserved ? 'Yes' : 'No'}</dd></div><div><dt>New high or critical findings</dt><dd>${result.introducedSevere.length}</dd></div></dl>
        ${result.preservation.map(item => `<p><code>${esc(item.request.action)}</code>: ${esc(item.before.decision)} → ${esc(item.after.decision)}</p>`).join('')}
        <p>Original proposal: ${esc(record.review.verdict.label)}. This is a bounded check, not production approval.</p>`;
      renderRecord();
    } catch (error) {
      if (revision === verificationRevision) find('#demoVerification').innerHTML = `<h3>Check incomplete</h3><p role="alert">${esc(error.message)} Repair the inputs and verify again. No current correction is included in the export.</p>`;
    } finally {
      verifying = false;
      button.disabled = false;
      button.textContent = 'Verify correction';
    }
  };

  find('#exportDemoReview').onclick = () => {
    if (!sampleRecord) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(sampleRecord, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'policylens-example-review.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    find('#demoExportStatus').textContent = 'Review JSON prepared for download. It includes the exact inputs, results, identities and stated limits.';
  };

  function applyRoute(focus = false) {
    const params = new URLSearchParams(location.search);
    const tools = params.get('view') === 'review' || params.get('view') === 'org' || params.has('demo') || params.get('auto') === '1';
    document.body.classList.toggle('product-home', !tools);
    find('.skip-link').href = tools ? '#tools' : '#productContent';
    if (tools) activateTab(!window.PolicyLensLocalAPI && (params.get('view') === 'org' || params.has('demo') || params.get('auto') === '1') ? 'org' : 'compare');
    if (focus) {
      window.scrollTo(0, 0);
      const heading = find(tools ? '#tools .workflow-intro h1' : '.landing-intro h1');
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
  }
  function navigate(view) {
    const url = new URL(location.href);
    url.search = view ? `?view=${view}` : '';
    url.hash = '';
    history.pushState({}, '', url);
    applyRoute(true);
  }
  document.querySelectorAll('[data-own-policies]').forEach(link => { link.onclick = event => { event.preventDefault(); navigate('review'); }; });
  document.querySelectorAll('[data-product-home]').forEach(link => { link.onclick = event => { event.preventDefault(); navigate(null); }; });
  find('[data-how]').onclick = event => { if (!document.body.classList.contains('product-home')) { event.preventDefault(); navigate(null); find('#how-it-works').scrollIntoView(); } };
  window.addEventListener('popstate', () => applyRoute());
  find('#tryPermission').onclick = event => {
    event.preventDefault();
    setChapter('risk');
    find('#guidedReview').scrollIntoView({ block: 'start' });
    find('#demoConsequence').focus({ preventScroll: true });
    replayTrace();
  };
  let traceTimer;
  function replayTrace() {
    if (!sampleRecord) return;
    const desk = find('.demo-desk');
    clearTimeout(traceTimer);
    desk.classList.remove('trace-running');
    requestAnimationFrame(() => {
      desk.classList.add('trace-running');
      find('#demoTraceStatus').textContent = 'The proposed Allow result comes from statement S2, after.json line 10. Inspect the correction next.';
      traceTimer = setTimeout(() => desk.classList.remove('trace-running'), 1250);
    });
  }
  find('#replayTrace').onclick = replayTrace;
  if (!window.PolicyLensLocalAPI) find('#productPrivacy').textContent = 'Runs on your PolicyLens server. AI off for this example.';
  else {
    find('#localAccountTools').hidden = true;
    find('#reviewPrivacy').textContent = 'Checks run in this browser. Policy files are not uploaded. AI and account-analysis services are available only in the local server version.';
  }

  [['beforeFile', 'beforeBox'], ['afterFile', 'afterBox']].forEach(([fileId, textId]) => {
    find(`#${fileId}`).onchange = async () => {
      const file = find(`#${fileId}`).files[0], field = find(`#${textId}`), previous = field.value;
      if (!file) return;
      try {
        const text = await file.text();
        if (find(`#${fileId}`).files[0] !== file || field.value !== previous) return;
        field.value = text;
        field.dispatchEvent(new Event('input', { bubbles: true }));
        find('#changeStatus').textContent = `${file.name} loaded. Review the declared request and run the check.`;
      } catch { find('#changeStatus').textContent = 'The file could not be read. Try another JSON file or paste the policy.'; }
    };
  });
  applyRoute();

  function renderSource(full) {
    if (!sampleTexts) return;
    const lines = sampleTexts[1].trimEnd().split('\n');
    const first = full ? 0 : sampleRecord.review.evidence[0].line - 1;
    const last = full ? lines.length : first + 6;
    const citedStart = sampleRecord.review.evidence[0].line - 1;
    find('#copyDemoSource').setAttribute('aria-label', full ? 'Copy proposed policy' : 'Copy cited statement');
    find('#demoSource').innerHTML = lines.slice(first, last).map((line, index) => {
      const sourceIndex = index + first;
      const value = line.match(/:\s*("(?:[^"\\]|\\.)*")/)?.[1];
      let content = esc(full ? line : line.replace(/^ {4}/, ''));
      if (value && sourceIndex >= citedStart && sourceIndex < citedStart + 6) content = content.replace(esc(value), `<span class="source-risk">${esc(value)}</span>`);
      return `<span class="source-line"><span class="line-number">${sourceIndex + 1}</span>${content}</span>`;
    }).join('');
  }

  async function copyExample(kind) {
    if (!sampleRecord) return;
    const full = find('#viewDemoPolicy').getAttribute('aria-pressed') === 'true';
    const first = sampleRecord.review.evidence[0].line - 1;
    const text = kind === 'request' ? sampleRecord.inputs.action : kind === 'citation' ? find('#demoCitation').textContent : full ? sampleTexts[1] : sampleTexts[1].trimEnd().split('\n').slice(first, first + 6).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      find('#demoCopyStatus').textContent = `Copied ${kind === 'source' ? (full ? 'proposed policy' : 'cited statement') : kind === 'request' ? 'checked request' : 'evidence citation'}.`;
    } catch { find('#demoCopyStatus').textContent = 'Clipboard unavailable. Select and copy the visible value.'; }
  }
  find('#copyDemoRequest').onclick = () => copyExample('request');
  find('#copyDemoCitation').onclick = () => copyExample('citation');
  find('#copyDemoSource').onclick = () => copyExample('source');

  find('#viewDemoPolicy').onclick = () => {
    const button = find('#viewDemoPolicy');
    const full = button.getAttribute('aria-pressed') !== 'true';
    button.setAttribute('aria-pressed', String(full));
    button.querySelector('span').textContent = full ? 'View excerpt' : 'View policy';
    renderSource(full);
  };
  loadExample();
})();
