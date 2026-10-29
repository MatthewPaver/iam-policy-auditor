#!/usr/bin/env node
'use strict';

// Policylens CLI: review before/after policies (or a Terraform plan) on the
// local machine. Exit codes: 0 pass, 1 stop, 2 review, 3 input error.

const fs = require('fs');
const path = require('path');
const { reviewChange } = require('../src/change_review');
const { fromTerraformPlan, normalizePolicyInput } = require('../src/adapters');

function usage() {
  return [
    'Usage:',
    '  policylens review --before <file> --after <file> [--request <json|file>] [--require <file>]... [--principal <p>] [--format text|json|sarif]',
    '  policylens review --terraform-plan <file> [--format text|json|sarif]',
  ].join('\n');
}

function failInput(message) {
  process.stderr.write(`${message}\n`);
  process.exit(3);
}

function readFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    failInput(`Could not read ${filePath}: ${err.message}`);
  }
}

function parseArgs(argv) {
  const args = {
    command: null,
    before: null,
    after: null,
    request: null,
    require: [],
    principal: null,
    format: 'text',
    terraformPlan: null,
  };
  if (!argv.length) return args;
  args.command = argv[0];
  for (let i = 1; i < argv.length; i++) {
    const flag = argv[i];
    const next = argv[i + 1];
    if (flag === '--before') { args.before = next; i++; }
    else if (flag === '--after') { args.after = next; i++; }
    else if (flag === '--request') { args.request = next; i++; }
    else if (flag === '--require') { args.require.push(next); i++; }
    else if (flag === '--principal') { args.principal = next; i++; }
    else if (flag === '--format') { args.format = next; i++; }
    else if (flag === '--terraform-plan') { args.terraformPlan = next; i++; }
    else if (flag === '--help' || flag === '-h') { args.help = true; }
    else failInput(`Unknown argument: ${flag}\n${usage()}`);
  }
  return args;
}

function loadRequest(spec, principal) {
  if (!spec && !principal) return undefined;
  let request = {};
  if (spec) {
    const raw = fs.existsSync(spec) ? readFile(spec) : spec;
    try {
      request = JSON.parse(raw);
    } catch (err) {
      failInput(`Request must be JSON or a JSON file: ${err.message}`);
    }
  }
  if (principal) request.principal = principal;
  return request;
}

function exitCodeForResults(results) {
  const statuses = results.map((r) => r.verdict && r.verdict.status);
  if (statuses.some((s) => s === 'stop')) return 1;
  if (statuses.some((s) => s === 'review')) return 2;
  return 0;
}

function toSarif(results, afterPath) {
  const sarifResults = [];
  for (const review of results) {
    if (!review.verdict || review.verdict.status !== 'stop') continue;
    const findings = [
      ...(review.findings && review.findings.introduced ? review.findings.introduced : []),
      ...(review.findings && review.findings.widened ? review.findings.widened : []),
    ].filter((f) => ['high', 'critical'].includes(f.severity));
    const newly = (review.newlyAllowed && review.newlyAllowed.items) || [];
    const riskyNew = newly.filter((i) => ['privesc', 'destructive', 'sensitive-read'].includes(i.sensitivity));

    if (!findings.length && !riskyNew.length) {
      sarifResults.push({
        ruleId: 'policylens/stop',
        level: 'error',
        message: { text: review.verdict.reason || 'Stop and review' },
        locations: afterPath ? [{
          physicalLocation: {
            artifactLocation: { uri: afterPath },
            region: { startLine: 1 },
          },
        }] : [],
      });
      continue;
    }
    for (const finding of findings) {
      const evidence = (finding.evidence && finding.evidence[0]) || {};
      sarifResults.push({
        ruleId: finding.ruleId || 'policylens/finding',
        level: 'error',
        message: { text: finding.title || finding.description || 'Stop finding' },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: afterPath || evidence.doc || 'after.json' },
            region: { startLine: evidence.line || 1 },
          },
        }],
      });
    }
    for (const item of riskyNew) {
      sarifResults.push({
        ruleId: `newly-allowed/${item.sensitivity}`,
        level: 'error',
        message: { text: `Newly allowed ${item.action} on ${item.resource}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: afterPath || item.doc || 'after.json' },
            region: { startLine: item.line || 1 },
          },
        }],
      });
    }
  }
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'policylens',
          informationUri: 'https://github.com/MatthewPaver/iam-policy-auditor',
          rules: [],
        },
      },
      results: sarifResults,
    }],
  };
}

function formatText(results) {
  const lines = [];
  for (const review of results) {
    const label = review.address ? `${review.address}: ` : '';
    lines.push(`${label}${review.verdict.status} — ${review.verdict.reason}`);
    if (review.newlyAllowed && review.newlyAllowed.items.length) {
      const top = review.newlyAllowed.items.slice(0, 10);
      for (const item of top) {
        lines.push(`  + ${item.action} on ${item.resource} (${item.sensitivity}, line ${item.line})`);
      }
      if (review.newlyAllowed.items.length > 10) {
        lines.push(`  … ${review.newlyAllowed.items.length - 10} more`);
      }
    }
  }
  return `${lines.join('\n')}\n`;
}

function reviewPair(beforeText, afterText, request, address) {
  try {
    // Touch the adapter early so malformed input gets the plain sentence, not a stack.
    normalizePolicyInput(beforeText, 'before');
    normalizePolicyInput(afterText, 'after');
    const review = reviewChange({ before: beforeText, after: afterText, request });
    return address ? { ...review, address } : review;
  } catch (err) {
    failInput(err.message || String(err));
  }
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.help || args.command !== 'review') {
    process.stdout.write(`${usage()}\n`);
    process.exit(args.help ? 0 : 3);
  }
  if (!['text', 'json', 'sarif'].includes(args.format)) {
    failInput(`Unknown format: ${args.format}`);
  }

  const request = loadRequest(args.request, args.principal);
  const results = [];
  let afterPath = args.after || args.terraformPlan || 'after.json';

  if (args.terraformPlan) {
    const planText = readFile(args.terraformPlan);
    let pairs;
    try {
      pairs = fromTerraformPlan(JSON.parse(planText));
    } catch (err) {
      failInput(err.message || String(err));
    }
    if (!pairs.length) failInput('No IAM / S3 bucket policy changes found in the Terraform plan.');
    for (const pair of pairs) {
      if (pair.unknown) {
        results.push({
          address: pair.address,
          verdict: {
            status: 'review',
            label: 'Needs context',
            reason: 'Policy value is unknown until apply; cannot be checked yet.',
          },
          findings: { introduced: [], resolved: [], widened: [] },
          newlyAllowed: { items: [], capped: false },
        });
        continue;
      }
      if (!pair.before || !pair.after) {
        failInput(`${pair.address}: Terraform change is missing before or after policy text.`);
      }
      results.push(reviewPair(pair.before, pair.after, request, pair.address));
    }
  } else {
    if (!args.before || !args.after) failInput(`--before and --after are required.\n${usage()}`);
    afterPath = path.resolve(args.after);
    results.push(reviewPair(readFile(args.before), readFile(args.after), request));
  }

  if (args.format === 'json') {
    // Drop heavy statement dumps / snippets so CI logs stay readable.
    const compact = (review) => ({
      address: review.address || undefined,
      verdict: review.verdict,
      access: review.access
        ? {
          before: review.access.before && review.access.before.decision,
          after: review.access.after && review.access.after.decision,
          broadened: review.access.broadened,
        }
        : null,
      findings: {
        introduced: (review.findings.introduced || []).map((f) => ({
          ruleId: f.ruleId, severity: f.severity, title: f.title,
        })),
        widened: (review.findings.widened || []).map((f) => ({
          ruleId: f.ruleId, severity: f.severity, title: f.title,
        })),
        resolved: (review.findings.resolved || []).map((f) => ({
          ruleId: f.ruleId, severity: f.severity, title: f.title,
        })),
      },
      newlyAllowed: review.newlyAllowed
        ? {
          capped: review.newlyAllowed.capped,
          items: (review.newlyAllowed.items || []).slice(0, 100),
          total: (review.newlyAllowed.items || []).length,
        }
        : undefined,
      limits: review.limits,
    });
    const body = results.length === 1 ? compact(results[0]) : { results: results.map(compact) };
    process.stdout.write(`${JSON.stringify(body, null, 2)}\n`);
  } else if (args.format === 'sarif') {
    process.stdout.write(`${JSON.stringify(toSarif(results, afterPath), null, 2)}\n`);
  } else {
    process.stdout.write(formatText(results));
  }
  process.exit(exitCodeForResults(results));
}

main(process.argv.slice(2));
