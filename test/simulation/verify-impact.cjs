const { chromium } = require('@playwright/test');
const { verifyCorrection } = require('../../src/change_review');
const { createHash } = require('node:crypto');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '../..'), out = process.env.POLICYLENS_PROOF_DIR || path.join(root, 'test-results/simulation'); fs.mkdirSync(out, { recursive: true });
const server = spawn('python3', ['-m', 'http.server', '4195', '--bind', '127.0.0.1', '--directory', path.join(root, 'site')], { stdio: ['ignore', 'ignore', 'pipe'] });
const log = fs.createWriteStream(path.join(out, 'server.log')); server.stderr.pipe(log);
let browser; const cases = [], errors = [];
const hash = input => createHash('sha256').update(JSON.stringify(input)).digest('hex');
const comparable = value => { const copy = structuredClone(value); delete copy.engine; return copy; };
async function ready(page, choice = 'keep') { await page.waitForFunction(c => { const d = document.querySelector('#rehearsal').dataset; return d.ready === 'true' && d.choice === c; }, choice); }
async function record(page) { return JSON.parse(await page.locator('#recordJSON').textContent()); }
async function step(page, count) { await page.locator('#attempt').click(); await page.waitForFunction(n => { const d = document.querySelector('#rehearsal').dataset; return d.actions === String(n) && d.acting === 'false'; }, count); }
async function advance(page, predicate, label, interval = 200, limit = 240) { for (let n = 0; n < limit; n++) { if (await page.evaluate(predicate)) return; await page.clock.runFor(interval); } assert.fail(`${label}: ${await page.locator('#walkthrough').getAttribute('data-state')} / ${await page.locator('#chapter').textContent()}`); }
async function capture(page, name) { await page.screenshot({ path: path.join(out, `${name}-viewport.png`) }); await page.screenshot({ path: path.join(out, `${name}-full.png`), fullPage: true }); }
async function checks(page) {
  const current = await record(page); assert.equal(current.inputIdentity, hash(current.inputs)); assert.equal(current.correction.inputIdentity, hash(current.correction.inputs));
  assert.deepEqual(comparable(current.correction.result), comparable(verifyCorrection(current.correction.inputs)));
  for (const [key, item] of Object.entries(current.comparisons)) {
    assert.equal(item.inputIdentity, hash(item.inputs)); assert.deepEqual(comparable(item.result), comparable(verifyCorrection(item.inputs)));
    const row = page.locator(`[data-comparison=${key}]`); assert((await row.textContent()).includes(item.result.verified ? 'Yes · both pass' : key === 'keep' ? 'No · deletion allowed' : 'No · report blocked'));
  }
  assert.deepEqual(Object.keys(current.comparisons).sort(), ['block', 'keep', 'reports']);
  assert.equal(current.simulation.cloudActionsPerformed, false); assert.equal(current.simulation.reportDependsOnDatabase, false);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  return current;
}
async function downloaded(page) { const expected = await record(page); const promise = page.waitForEvent('download'); await page.locator('#download').click(); const file = await promise; assert.deepEqual(JSON.parse(fs.readFileSync(await file.path(), 'utf8')), expected); }
function track(page, label) { page.on('pageerror', error => errors.push({ label, message: error.message })); page.on('request', r => { assert(r.url().startsWith('http://127.0.0.1:4195/') || r.url().startsWith('blob:')); assert.equal(r.method(), 'GET'); }); }
(async () => {
  for (let i = 0; i < 40; i++) { try { if ((await fetch('http://127.0.0.1:4195/impact/')).ok) break; } catch { /* Wait for the local proof server. */ } await new Promise(resolve => setTimeout(resolve, 100)); }
  browser = await chromium.launch({ headless: true, args: ['--use-angle=swiftshader'] });
  for (const [device, viewport] of [['desktop', { width: 1440, height: 1000 }], ['phone', { width: 390, height: 844 }]]) {
    const context = await browser.newContext({ viewport, acceptDownloads: true }), page = await context.newPage(), requests = []; track(page, device); page.on('request', r => requests.push(r.url()));
    await page.goto('http://127.0.0.1:4195/impact/?mode=manual'); await ready(page); await checks(page);
    assert(await page.locator('#diagram').isVisible()); assert.equal(await page.locator('canvas').count(), 0); assert(!requests.some(url => /world.js|vendor/.test(url)));
    const first = await page.locator('#attempt').boundingBox(); assert(first.y + first.height < viewport.height, 'First manual task is visible');
    await step(page, 1); assert(await page.locator('#reportPreview').isVisible()); await step(page, 2); assert(await page.locator('#databaseEmpty').isVisible()); assert(await page.locator('#reportPreview').isVisible());
    const baseline = (await record(page)).simulation.originalRun; assert.equal(baseline.sandbox.rows.length, 0); await checks(page); cases.push({ device, choice: 'keep', sourceParity: true, comparisonParity: true, exportIdentity: true, originalPreserved: true }); await downloaded(page); await capture(page, `${device}-proposed`);
    for (const choice of ['block', 'reports']) {
      await page.locator(`[name=candidate][value=${choice}]`).check(); await ready(page, choice); assert.deepEqual((await record(page)).simulation.originalRun, baseline);
      assert.equal((await record(page)).simulation.currentRun.actions.length, 0); await step(page, 1); assert.equal(await page.locator('#reportPreview').isVisible(), choice === 'reports');
      await step(page, 2); const current = await checks(page); assert.equal(current.simulation.currentRun.rows.length, 3); assert.equal(current.correction.result.verified, choice === 'reports'); await downloaded(page); await capture(page, `${device}-${choice}`);
      cases.push({ device, choice, sourceParity: true, comparisonParity: true, exportIdentity: true, originalPreserved: true });
    }
    await page.locator('#showRule').click(); assert((await page.locator('#sourceCitation').textContent()).includes('after.json:10')); assert((await page.locator('#statementChanges').textContent()).includes('ReadReports')); await page.locator('#rule>summary').click();
    await page.locator('#rewind').click(); await ready(page, 'reports'); assert.equal((await record(page)).simulation.currentRun.actions.length, 0); assert.deepEqual((await record(page)).simulation.originalRun, baseline);
    await page.locator('#reset').click(); await ready(page); assert.equal((await record(page)).simulation.originalRun, null); await context.close(); console.log(`Manual ${device}: all three choices passed`);
  }
  const guided = [];
  for (const [device, viewport] of [['desktop', { width: 1440, height: 1000 }], ['phone', { width: 390, height: 844 }]]) {
    const context = await browser.newContext({ viewport, acceptDownloads: true }), page = await context.newPage(); track(page, `guide-${device}`); await page.clock.install();
    await page.goto('http://127.0.0.1:4195/'); await page.getByRole('link', { name: 'Watch the walkthrough', exact: true }).click(); await page.waitForURL('**/impact/'); await ready(page); await page.locator('#walkthrough[data-state=playing]').waitFor();
    const start = await page.evaluate(() => performance.now());
    const result = await page.locator('#runResult').boundingBox(), caption = await page.locator('#caption').boundingBox(); assert(result.y + result.height < viewport.height, 'Result visible on arrival'); assert(caption.y + caption.height < viewport.height, 'Caption visible on arrival');
    await capture(page, `${device}-arrival`);
    await page.locator('#playPause').press('Enter'); const paused = await record(page); await page.clock.runFor(6000); assert.deepEqual(await record(page), paused); await page.locator('#playPause').click();
    await advance(page, () => document.querySelector('#rehearsal').dataset.acting === 'true', 'first request begins'); await page.locator('#playPause').click(); const mid = await record(page); await page.clock.runFor(6000); assert.deepEqual(await record(page), mid); await page.locator('#playPause').click();
    await advance(page, () => Boolean(JSON.parse(document.querySelector('#recordJSON').textContent).simulation.originalRun), 'risk result');
    const baseline = (await record(page)).simulation.originalRun; await capture(page, `${device}-risk`);
    await page.evaluate(() => scrollTo(0, scrollY + document.querySelector('#caption').getBoundingClientRect().bottom + 10)); await page.screenshot(); await page.clock.runFor(100); assert.equal(await page.locator('#walkthrough').getAttribute('data-state'), 'paused');
    assert(await page.locator('.visual').isVisible());
    const offscreen = await record(page); await page.clock.runFor(6000); assert.deepEqual(await record(page), offscreen);
    await page.evaluate(() => scrollTo(0, 0)); await page.screenshot(); await page.clock.runFor(100); await page.locator('#playPause').click();
    await advance(page, () => document.querySelector('#walkthrough').dataset.state === 'ended', 'short story completion');
    const activeMs = await page.evaluate(() => performance.now()) - start - 18000;
    assert(activeMs < 45000, `Short guide exceeded45seconds: ${activeMs}`);
    const final = await checks(page); assert.equal(final.correction.result.verified, true); assert.deepEqual(final.simulation.originalRun, baseline); assert.equal(await page.locator('#transcript li').count(), 7); await downloaded(page);
    await page.evaluate(() => scrollTo(0, 0)); await capture(page, `${device}-complete`);
    await page.clock.runFor(12000); assert.deepEqual(await record(page), final);
    await page.locator('#replayStory').click(); await ready(page); await advance(page, () => document.querySelector('#rehearsal').dataset.acting === 'true', 'replayed request begins');
    await page.locator('#takeControl').click(); await page.waitForFunction(() => document.querySelector('#rehearsal').dataset.acting === 'false'); const taken = await record(page); await page.clock.runFor(8000); assert.deepEqual(await record(page), taken); assert.equal(taken.simulation.currentRun.actions.length, 0); assert(await page.locator('#attempt').isEnabled());
    guided.push({ device, completed: true, chapters: 5, captions: 7, estimatedActiveMsUnderControlledClock: activeMs, pauseResume: true, midActionCancel: true, offscreenCaptionPause: true, replay: true, sourceParity: true }); await context.close(); console.log(`Short guide ${device}: passed`);
  }
  const quiet = await browser.newContext({ reducedMotion: 'reduce', viewport: { width: 390, height: 844 } }), qp = await quiet.newPage(); track(qp, 'reduced'); await qp.clock.install(); await qp.goto('http://127.0.0.1:4195/impact/'); await ready(qp); await qp.locator('#walkthrough[data-state=paused]').waitFor(); await qp.clock.runFor(30000); assert.equal((await record(qp)).simulation.currentRun.actions.length, 0); await qp.locator('#playPause').click(); await advance(qp, () => document.querySelector('#walkthrough').dataset.state === 'ended', 'reduced story'); assert((await record(qp)).correction.result.verified); await quiet.close();
  const retry = await browser.newContext(), rp = await retry.newPage(); await rp.route('**/samples/aws-change-after.json', r => r.fulfill({ status: 503, body: 'Unavailable' })); await rp.goto('http://127.0.0.1:4195/impact/?mode=manual'); await rp.locator('#error').waitFor({ state: 'visible' }); assert(await rp.locator('#download').isDisabled()); await rp.unroute('**/samples/aws-change-after.json'); await rp.locator('#retry').click(); await ready(rp); await checks(rp); await retry.close();
  assert.deepEqual(errors, []); fs.writeFileSync(path.join(out, 'checks.json'), JSON.stringify({ manualTaskAttempts: 12, cases, guided, reducedMotion: true, fixtureRetry: true, noExternalRequests: true, errors }, null, 2)); console.log('All focused journeys passed.');
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); server.kill('SIGTERM'); await new Promise(resolve => server.exitCode !== null ? resolve() : server.once('exit', resolve)); log.end(); });
