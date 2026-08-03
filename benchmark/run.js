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
const asJson = args.includes('--json');
const threshold = args.includes('--threshold') ? Number(args[args.indexOf('--threshold') + 1]) : 100;

const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'corpus.json'), 'utf8'));

function evalCase(c) {
  const text = JSON.stringify(c.policy, null, 2);
  const model = analyzeDocuments([{ name: `${c.id}.json`, text }]);
  const r = evaluateRequest(model, c.request);
  return { text, decision: r.decision, explanation: r.explanation };
}

// --- corpus comparison (always runs) ---------------------------------------
const rows = [];
let agree = 0;
for (const c of corpus.cases) {
  const got = evalCase(c);
  const ok = got.decision === c.expected;
  if (ok) agree++;
  rows.push({ id: c.id, note: c.note, expected: c.expected, got: got.decision, ok, text: got.text, request: c.request, oracleSkip: !!c.oracleSkip, oracleReason: c.oracleReason });
}
const pct = (agree / corpus.cases.length) * 100;

// --- optional AWS oracle diff ----------------------------------------------
let oracle = null;
if (useOracle) {
  const adapter = require('./oracle-aws');
  const avail = adapter.isAvailable();
  if (!avail.ok) {
    oracle = { available: false, reason: avail.reason };
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
    oracle = o;
  }
}

// --- output ----------------------------------------------------------------
if (asJson) {
  console.log(JSON.stringify({ total: corpus.cases.length, agree, agreementPct: pct, rows: rows.map(({ text, ...r }) => r), oracle }, null, 2));
} else {
  console.log('\n  G1 correctness benchmark — engine vs documented AWS semantics\n');
  for (const r of rows) {
    const mark = r.ok ? '✓' : '✗';
    console.log(`  ${mark} ${r.id.padEnd(26)} expected ${r.expected.padEnd(16)} got ${r.got}`);
    if (!r.ok) console.log(`      ${r.note}`);
  }
  console.log(`\n  Engine ↔ corpus: ${agree}/${corpus.cases.length} = ${pct.toFixed(1)}%\n`);

  if (oracle) {
    if (!oracle.available) {
      console.log(`  AWS oracle: unavailable (${oracle.reason})`);
      console.log('  → corpus-only run. Configure the AWS CLI + credentials to diff against SimulateCustomPolicy.\n');
    } else if (oracle.blocked) {
      console.log(`  AWS oracle: reachable, but the call was blocked — ${oracle.blocked}`);
      console.log('  → The credentials in use lack iam:SimulateCustomPolicy. Grant that action (and');
      console.log('    access-analyzer:CheckAccessNotGranted) to a read-only benchmark principal to run the G1 gate.\n');
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

process.exit(pct < threshold ? 1 : 0);
