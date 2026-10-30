#!/usr/bin/env node
'use strict';

// Policylens CLI: review before/after policies (or a Terraform plan) on the
// local machine. Exit codes: 0 pass, 1 stop, 2 review, 3 input error.

const fs = require('fs');
const { reviewChange } = require('../src/change_review');
const { fromTerraformPlan, normalizePolicyInput } = require('../src/adapters');

function usage() {
  return [
    'Usage:',
    '  policylens review --before <file> --after <file> [--request <json|file>] [--require <file>]... [--principal <p>] [--format text|json]',
    '  policylens review --terraform-plan <file> [--format text|json]',
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
  if (!['text', 'json'].includes(args.format)) {
    failInput(`Unknown format: ${args.format}`);
  }

  const request = loadRequest(args.request, args.principal);
  const results = [];

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
  } else {
    process.stdout.write(formatText(results));
  }
  process.exit(exitCodeForResults(results));
}

main(process.argv.slice(2));
