'use strict';

// A document comparison is not an access decision. Only the existing engine
// verifies risk closure and required access; this view shows the exact edits.
(() => {
  const escape = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value);
  function statements(text) {
    const policy = JSON.parse(text);
    if (!policy || typeof policy !== 'object' || !policy.Statement) throw new Error('Supply a policy with a Statement object or array.');
    const array = Array.isArray(policy.Statement);
    const values = array ? policy.Statement : [policy.Statement];
    if (values.some(value => !value || typeof value !== 'object' || Array.isArray(value))) throw new Error('Each policy statement must be an object.');
    return values.map((value, index) => ({ value, pointer: array ? `/Statement/${index}` : '/Statement', key: canonical(value) }));
  }
  function compare(proposed, candidate) {
    const original = statements(proposed), remaining = statements(candidate);
    const removed = [], retained = [];
    for (const statement of original) {
      const index = remaining.findIndex(item => item.key === statement.key);
      if (index < 0) removed.push(statement);
      else retained.push({ ...statement, candidatePointer: remaining.splice(index, 1)[0].pointer });
    }
    return { removed, retained, added: remaining };
  }
  const values = value => (Array.isArray(value) ? value : [value]).map(item => escape(typeof item === 'string' ? item : JSON.stringify(item))).join(', ');
  function entry(statement, kind) {
    const value = statement.value;
    const actions = value.Action !== undefined ? `Action: ${values(value.Action)}` : value.NotAction !== undefined ? `NotAction: ${values(value.NotAction)}` : 'Action not specified';
    const resources = value.Resource !== undefined ? `Resource: ${values(value.Resource)}` : value.NotResource !== undefined ? `NotResource: ${values(value.NotResource)}` : 'Resource not specified';
    const source = kind === 'added' ? 'candidate.json' : 'proposed.json';
    return `<li><p class="statement-name"><strong>${escape(value.Sid || 'Unnamed statement')}</strong><span>${escape(value.Effect || 'Effect not specified')}</span></p><code class="statement-action">${actions}</code><code class="statement-resource">${resources}</code><details><summary>Exact statement</summary><p class="statement-location">${source} · ${escape(statement.pointer)}${statement.candidatePointer ? `<br>candidate.json · ${escape(statement.candidatePointer)}` : ''}</p><pre>${escape(JSON.stringify(value, null, 2))}</pre></details></li>`;
  }
  function render(proposed, candidate) {
    try {
      const changes = compare(proposed, candidate);
      return `<section class="policy-changes" aria-label="Candidate statement changes"><h3>What changes in the policy</h3>${['removed', 'retained', 'added'].map(kind => {
        const list = changes[kind];
        if (kind === 'added' && !list.length) return '';
        const name = { removed: 'Removed', retained: 'Retained', added: 'Added' }[kind];
        return `<div class="statement-group statement-${kind}" data-change-kind="${kind}"><h4>${name}<span>${list.length} statement${list.length === 1 ? '' : 's'}</span></h4>${list.length ? `<ul>${list.map(item => entry(item, kind)).join('')}</ul>` : `<p>No ${kind} statements.</p>`}</div>`;
      }).join('')}<p class="changes-note">Statement comparison only. Verification checks access for the declared requests.</p></section>`;
    } catch {
      return '<p class="changes-note">Fix the candidate JSON to compare its statements. No correction has been verified.</p>';
    }
  }
  const describe = decision => ({ Allow: 'Allowed', ImplicitDeny: 'Not allowed', ExplicitDeny: 'Explicitly denied', ConditionalAllow: 'Needs context' })[decision] || 'Not determined';
  const view = { compare, render, describe };
  if (typeof module !== 'undefined' && module.exports) module.exports = view;
  else window.PolicyLensCorrectionView = view;
})();
