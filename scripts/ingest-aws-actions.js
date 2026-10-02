#!/usr/bin/env node
'use strict';

// Ingest the AWS IAM action catalogue from iann0036/iam-dataset (MIT) into a
// compact index the engine loads at runtime. This replaces the hand-curated
// toy action list with the real ~18k actions and their AWS-assigned access
// levels (Read / Write / List / Tagging / Permissions management).
//
// Usage:
//   node scripts/ingest-aws-actions.js [sourcePath]
// If sourcePath is omitted the raw file is downloaded from GitHub. The compact
// output is written to data/aws-actions.json.
//
// Access level → single-char code to keep the file small:
//   R Read · W Write · L List · T Tagging · P Permissions management · U Unknown

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const SOURCE_COMMIT = '14982bbe1ce61089f8e66c07781ba63eed2d946a';
const SRC_URL = `https://raw.githubusercontent.com/iann0036/iam-dataset/${SOURCE_COMMIT}/aws/iam_definition.json`;
const OUT = path.join(__dirname, '..', 'data', 'aws-actions.json');
const PROVENANCE_OUT = path.join(__dirname, '..', 'data', 'aws-actions.provenance.json');

// Some entries carry compound levels (e.g. "Tagging, Write", "Permissions
// management, Write"). Collapse to the single most-significant code by priority
// so mutating/escalation actions are never misclassified as read-only.
const LEVEL_PRIORITY = [
  ['Permissions management', 'P'],
  ['Write', 'W'],
  ['Tagging', 'T'],
  ['List', 'L'],
  ['Read', 'R'],
];
function levelCode(access) {
  if (!access) return 'U';
  for (const [label, code] of LEVEL_PRIORITY) if (access.includes(label)) return code;
  return 'U';
}

function download(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) { reject(new Error(`HTTP ${res.statusCode} for ${url}`)); res.resume(); return; }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    }).on('error', reject);
  });
}

async function main() {
  const srcArg = process.argv[2];
  let raw;
  if (srcArg) {
    console.log(`Reading local source: ${srcArg}`);
    raw = fs.readFileSync(srcArg, 'utf8');
  } else {
    console.log(`Downloading ${SRC_URL} …`);
    raw = await download(SRC_URL);
  }

  const services = JSON.parse(raw);
  if (!Array.isArray(services)) throw new Error('Unexpected dataset shape: expected top-level array of services');

  const index = {};
  let actionCount = 0;
  const levelTally = {};

  for (const svc of services) {
    const prefix = svc.prefix;
    if (!prefix) continue;
    const actions = {};
    for (const priv of svc.privileges || []) {
      const name = priv.privilege;
      if (!name) continue;
      const code = levelCode(priv.access_level);
      actions[name] = code;
      levelTally[code] = (levelTally[code] || 0) + 1;
      actionCount++;
    }
    index[prefix.toLowerCase()] = { name: svc.service_name || prefix, actions };
  }

  const out = {
    _meta: {
      source: 'iann0036/iam-dataset (MIT) — aws/iam_definition.json',
      sourceUrl: SRC_URL,
      sourceCommit: SOURCE_COMMIT,
      sourceSha256: crypto.createHash('sha256').update(raw).digest('hex'),
      generatedAt: new Date().toISOString(),
      services: Object.keys(index).length,
      actions: actionCount,
      levelTally,
      levelCodes: { R: 'Read', W: 'Write', L: 'List', T: 'Tagging', P: 'Permissions management', U: 'Unknown' },
    },
    services: index,
  };

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(out));
  const outputSha256 = crypto.createHash('sha256').update(fs.readFileSync(OUT)).digest('hex');
  fs.writeFileSync(PROVENANCE_OUT, `${JSON.stringify({
    schemaVersion: 1,
    sourceRepository: 'https://github.com/iann0036/iam-dataset',
    sourceCommit: SOURCE_COMMIT,
    sourcePath: 'aws/iam_definition.json',
    sourceSha256: out._meta.sourceSha256,
    outputPath: 'data/aws-actions.json',
    outputSha256,
    generatedAt: out._meta.generatedAt,
    licence: 'MIT',
  }, null, 2)}\n`);
  const kb = Math.round(fs.statSync(OUT).size / 1024);
  console.log(`\nWrote ${OUT}`);
  console.log(`  services: ${out._meta.services}`);
  console.log(`  actions:  ${actionCount}`);
  console.log(`  levels:   ${Object.entries(levelTally).map(([k, v]) => `${k}=${v}`).join(', ')}`);
  console.log(`  size:     ${kb} KB`);
  console.log(`  commit:   ${SOURCE_COMMIT}`);
  console.log(`  sha256:   ${outputSha256}`);
}

main().catch((e) => { console.error('Ingestion failed:', e.message); process.exit(1); });
