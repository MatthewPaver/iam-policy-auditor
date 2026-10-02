#!/usr/bin/env node
'use strict';

// Optional release-candidate run. It calls the configured model repeatedly,
// captures the exact model/prompt/temperature/latency/token metadata, and feeds
// every completion through the same deterministic grounding evaluator used in CI.

const fs = require('fs');
const path = require('path');
const { reviewChange } = require('../src/change_review');
const { explainChangeAI, MODEL, TEMPERATURE, CHANGE_PROMPT_VERSION } = require('../src/ai');
const { evaluateExplanation } = require('../src/ai_eval');

const args = process.argv.slice(2);
const valueAfter = (flag, fallback) => args.includes(flag) ? args[args.indexOf(flag) + 1] : fallback;
const repeats = Math.max(1, Number(valueAfter('--repeats', '3')));
const output = valueAfter('--output', path.join('evals', 'results', `live-${new Date().toISOString().replace(/[:.]/g, '-')}.json`));

if (!process.env.ANTHROPIC_API_KEY) {
  console.error('ANTHROPIC_API_KEY is required for eval:live. Offline CI remains available with npm run eval.');
  process.exit(2);
}

function readSample(name) {
  return fs.readFileSync(path.join(__dirname, '..', 'samples', name), 'utf8');
}

function estimateCost(usage) {
  const inputRate = Number(process.env.AUDITOR_INPUT_USD_PER_MILLION || 0);
  const outputRate = Number(process.env.AUDITOR_OUTPUT_USD_PER_MILLION || 0);
  if (!usage || !inputRate || !outputRate) return null;
  return Number((((usage.input_tokens || 0) * inputRate + (usage.output_tokens || 0) * outputRate) / 1_000_000).toFixed(6));
}

async function main() {
  const review = reviewChange({
    before: readSample('aws-change-before.json'),
    after: readSample('aws-change-after.json'),
    request: {
      action: 'rds:DeleteDBInstance',
      resource: 'arn:aws:rds:eu-west-1:111122223333:db:production-main',
    },
  });
  const runs = [];
  for (let index = 0; index < repeats; index += 1) {
    const completion = await explainChangeAI({ review });
    if (!completion || completion.error) {
      runs.push({ repeat: index + 1, error: completion?.error || 'no response' });
      continue;
    }
    const evaluation = evaluateExplanation({
      text: completion.text,
      facts: completion.facts,
      expectedStatus: review.verdict.status,
    });
    runs.push({
      repeat: index + 1,
      model: completion.model,
      temperature: completion.temperature,
      promptVersion: completion.promptVersion,
      requestId: completion.requestId,
      latencyMs: completion.latencyMs,
      usage: completion.usage,
      estimatedCostUsd: estimateCost(completion.usage),
      text: completion.text,
      evaluation,
    });
  }

  const valid = runs.filter((run) => run.evaluation);
  const result = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    model: MODEL,
    temperature: TEMPERATURE,
    promptVersion: CHANGE_PROMPT_VERSION,
    repeats,
    passRate: valid.length ? valid.filter((run) => run.evaluation.passed).length / valid.length : null,
    costNote: 'estimatedCostUsd is null unless versioned per-million-token rates are supplied through AUDITOR_INPUT_USD_PER_MILLION and AUDITOR_OUTPUT_USD_PER_MILLION.',
    runs,
  };
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`Wrote ${output}; pass rate ${result.passRate == null ? 'n/a' : `${Math.round(result.passRate * 100)}%`}`);
  process.exit(result.passRate === 1 ? 0 : 1);
}

main().catch((error) => { console.error(error); process.exit(1); });
