'use strict';
// Real-case accuracy benchmark. Each set is real AWS managed-policy changes (MAMIP) or
// changes modelled from AWS docs and Rhino Security Labs; sources in SOURCES.md.
// Every case runs the way a new user would: before + after, no request.
// Exits 1 if any set scores below its floor in floors.json (the score when this was added).
// Usage: node bench/real-cases/run.js [--update-floors]
const fs = require('fs');
const path = require('path');
const { reviewChange } = require('../../src/change_review');
const dir = __dirname;
const floors = JSON.parse(fs.readFileSync(path.join(dir, 'floors.json'), 'utf8'));
const sets = fs.readdirSync(dir).filter((f) => /^policylens-heldout\d*\.json$/.test(f)).sort();
const scores = {};
let failed = false;
for (const file of sets) {
  const cases = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
  let right = 0;
  const misses = [];
  for (const c of cases) {
    const expect = typeof c.expect === 'string' ? c.expect : c.expect.status;
    let got;
    try {
      got = reviewChange({
        before: typeof c.before === 'string' ? c.before : JSON.stringify(c.before),
        after: typeof c.after === 'string' ? c.after : JSON.stringify(c.after),
      }).verdict.status;
    } catch (error) { got = `error: ${error.message.slice(0, 60)}`; }
    if (got === expect) right += 1; else misses.push(`  ${c.id} [${c.kind}] expected ${expect}, got ${got}: ${c.title.slice(0, 80)}`);
  }
  scores[file] = right;
  const floor = floors[file] ?? 0;
  const status = right < floor ? 'BELOW FLOOR' : 'ok';
  if (right < floor) failed = true;
  console.log(`${file}: ${right}/${cases.length} (floor ${floor}) ${status}`);
  if (misses.length) console.log(misses.join('\n'));
}
if (process.argv.includes('--update-floors')) {
  fs.writeFileSync(path.join(dir, 'floors.json'), `${JSON.stringify(scores, null, 2)}\n`);
  console.log('floors.json updated');
}
process.exit(failed ? 1 : 0);
