#!/usr/bin/env node
'use strict';

// G1 correctness benchmark.
//
//   node benchmark/run.js               # corpus-only: engine vs documented AWS semantics
//   node benchmark/run.js --oracle aws  # also diff engine vs live AWS SimulateCustomPolicy
//   node benchmark/run.js --json        # machine-readable summary
//
// Exit code is non-zero if engine↔corpus agreement is below --threshold (default 100),
// so this can gate CI. When the AWS oracle is available it additionally reports
// engine↔AWS agreement — the metric the roadmap's G1 exit criterion is written against.

const fs = require('fs');
const path = require('path');
const { analyzeDocuments } = require('../src/engine');
const { evaluateRequest } = require('../src/evaluate');

const args = process.argv.slice(2);
const useOracle = args.includes('--oracle') && args[args.indexOf('--oracle') + 1] === 'aws';
if (args.includes('--oracle') && !useOracle) {
  console.error('--oracle requires the supported value: aws');
  process.exit(1);
}
const asJson = args.includes('--json');
const threshold = args.includes('--threshold') ? Number(args[args.indexOf('--threshold') + 1]) : 100;
if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
  console.error('--threshold must be a number between 0 and 100');
  process.exit(1);
}

const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'corpus.json'), 'utf8'));
const extendedCases = require('./extended-cases');
const benchmarkCases = [...corpus.cases, ...extendedCases];

function evalCase(c) {
  const text = JSON.stringify(c.policy, null, 2);
  const model = analyzeDocuments([{ name: `${c.id}.json`, text }]);
  const r = evaluateRequest(model, c.request);
  return { text, decision: r.decision, explanation: r.explanation };
}

// --- corpus comparison (always runs) ---------------------------------------
const rows = [];
let agree = 0;
for (const c of benchmarkCases) {
  const got = evalCase(c);
  const ok = got.decision === c.expected;
  if (ok) agree++;
  rows.push({ id: c.id, note: c.note, expected: c.expected, got: got.decision, ok, text: got.text, request: c.request, oracleSkip: !!c.oracleSkip, oracleReason: c.oracleReason });
}
const pct = (agree / benchmarkCases.length) * 100;

// --- optional AWS oracle diff ----------------------------------------------
let oracle = { status: 'not-requested', available: false };
if (useOracle) {
  const adapter = require('./oracle-aws');
  const avail = adapter.isAvailable();
  if (!avail.ok) {
    oracle = { status: 'not-run', available: false, reason: avail.reason };
  } else {
    const o = { available: true, checked: 0, engineVsAws: 0, mismatches: [], skipped: [], blocked: null };
    for (const row of rows) {
      if (row.oracleSkip) { o.skipped.push({ id: row.id, reason: row.oracleReason }); continue; }
      try {
        const res = adapter.simulate({ policyText: row.text, action: row.request.action, resource: row.request.resource, context: row.request.context });
        o.checked++;
        if (res.decision === row.got) o.engineVsAws++;
        else o.mismatches.push({ id: row.id, engine: row.got, aws: res.decision, expected: row.expected });
      } catch (e) {
        const msg = String(e.stderr || e.message);
        const line = msg.split('\n').map((s) => s.trim()).find((s) => /AccessDenied|not authorized|error occurred|ExpiredToken|InvalidClientTokenId|ValidationError/i.test(s)) || msg.split('\n')[0];
        // Fail fast on an account-wide block (missing permission / bad creds) — don't
        // hammer the account with 20+ identical denied calls.
        if (/AccessDenied|not authorized|ExpiredToken|InvalidClientTokenId/i.test(line)) {
          o.blocked = line;
          break;
        }
        o.mismatches.push({ id: row.id, error: line });
      }
    }
    o.agreementPct = o.checked ? (o.engineVsAws / o.checked) * 100 : null;
    o.status = o.blocked ? 'blocked' : o.mismatches.some((row) => row.error) ? 'incomplete' : 'completed';
    oracle = o;
  }
}

// --- output ----------------------------------------------------------------
if (asJson) {
  console.log(JSON.stringify({ evidenceType: 'authored-regression-corpus', total: benchmarkCases.length, baseCases: corpus.cases.length, extendedCases: extendedCases.length, agree, agreementPct: pct, rows: rows.map(({ text, ...r }) => r), oracle }, null, 2));
} else {
  console.log('\n  Authored regression corpus — not independent AWS validation\n');
  for (const r of rows) {
    const mark = r.ok ? '✓' : '✗';
    console.log(`  ${mark} ${r.id.padEnd(26)} expected ${r.expected.padEnd(16)} got ${r.got}`);
    if (!r.ok) console.log(`      ${r.note}`);
  }
  console.log(`\n  Engine ↔ corpus: ${agree}/${benchmarkCases.length} = ${pct.toFixed(1)}%\n`);

  if (useOracle) {
    if (!oracle.available) {
      console.log(`  AWS oracle: unavailable (${oracle.reason})`);
      console.log('  → corpus-only run. Configure the AWS CLI + credentials to diff against SimulateCustomPolicy.\n');
    } else if (oracle.blocked) {
      console.log(`  AWS oracle: reachable, but the call was blocked — ${oracle.blocked}`);
      console.log('  → An owner must resolve the reported credential or iam:SimulateCustomPolicy permission problem.\n');
    } else {
      const apct = oracle.agreementPct == null ? 'n/a' : `${oracle.agreementPct.toFixed(1)}%`;
      console.log(`  AWS oracle (SimulateCustomPolicy): engine ↔ AWS ${oracle.engineVsAws}/${oracle.checked} = ${apct}`);
      if (oracle.skipped.length) console.log(`  skipped (intentional divergence): ${oracle.skipped.map((s) => s.id).join(', ')}`);
      for (const m of oracle.mismatches) {
        console.log(m.error ? `   ! ${m.id}: ${m.error}` : `   ✗ ${m.id}: engine=${m.engine} aws=${m.aws} (expected ${m.expected})`);
      }
      console.log('');
    }
  }
}

const oracleFailed = useOracle && (oracle.status !== 'completed' || !oracle.checked || oracle.mismatches.length > 0);
process.exit(pct < threshold || oracleFailed ? 1 : 0);
