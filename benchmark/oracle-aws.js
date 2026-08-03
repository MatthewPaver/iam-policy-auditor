'use strict';

// Pluggable AWS ground-truth oracle. Shells out to `aws iam simulate-custom-policy`
// (no SDK dependency). This is the G1 correctness gate: diff our offline
// evaluator against AWS's own authorization engine on a real policy corpus.
//
// It degrades gracefully: if the AWS CLI or credentials are absent, isAvailable()
// returns a reason and the benchmark runs corpus-only. When available, the same
// SimulateCustomPolicy call underpins building a much larger labelled eval corpus
// (the dataset HuggingFace lacks) by pairing generated policies with AWS verdicts.

const { execFileSync } = require('child_process');

function run(args) {
  return execFileSync('aws', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 20000 });
}

function isAvailable() {
  try { run(['--version']); } catch { return { ok: false, reason: 'AWS CLI not found on PATH' }; }
  try { run(['sts', 'get-caller-identity']); } catch (e) {
    return { ok: false, reason: `AWS credentials not usable: ${String(e.stderr || e.message).split('\n')[0]}` };
  }
  return { ok: true };
}

// Infer the SimulateCustomPolicy context key type from the key name so
// condition operators evaluate correctly on the AWS side.
function contextType(key) {
  const k = key.toLowerCase();
  if (k.includes('sourceip') || k === 'aws:sourceip') return 'ip';
  if (k.includes('currenttime') || k.includes('epochtime') || k.includes('tokenissuetime')) return 'date';
  if (k.includes('age') || k.includes('max') || k.includes('count') || k.includes('numeric')) return 'numeric';
  if (k.includes('arn')) return 'string'; // ARN condition ops take string values
  if (k.includes('multifactorauthpresent') || k.includes('secureTransport') || k.includes('viaawsservice')) return 'boolean';
  return 'string';
}

const TYPE_MAP = {
  string: 'string', boolean: 'boolean', numeric: 'numeric', ip: 'ip', date: 'date',
};

function contextEntries(context) {
  return Object.entries(context || {}).map(([key, val]) => {
    const values = Array.isArray(val) ? val.join(',') : String(val);
    const type = TYPE_MAP[contextType(key)] || 'string';
    // CLI shorthand: ContextKeyName=..,ContextKeyValues=..,ContextKeyType=..
    return `ContextKeyName=${key},ContextKeyValues=${values},ContextKeyType=${type}`;
  });
}

// Map AWS EvalDecision to our vocabulary.
const DECISION_MAP = { allowed: 'Allow', explicitDeny: 'ExplicitDeny', implicitDeny: 'ImplicitDeny' };

// Evaluate one request. Returns { decision, raw } or throws.
function simulate({ policyText, action, resource, context }) {
  const args = [
    'iam', 'simulate-custom-policy',
    '--policy-input-list', policyText,
    '--action-names', action,
    '--output', 'json',
  ];
  if (resource && resource !== '*') args.push('--resource-arns', resource);
  const entries = contextEntries(context);
  if (entries.length) { args.push('--context-entries'); args.push(...entries); }

  const out = JSON.parse(run(args));
  const res = (out.EvaluationResults || [])[0];
  if (!res) throw new Error('No EvaluationResults returned');
  return { decision: DECISION_MAP[res.EvalDecision] || `AWS:${res.EvalDecision}`, raw: res.EvalDecision };
}

module.exports = { isAvailable, simulate, contextEntries, DECISION_MAP };
