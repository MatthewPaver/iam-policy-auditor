'use strict';
const { test, expect } = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const samples = path.join(__dirname, '../../samples');
const hash = input => createHash('sha256').update(JSON.stringify(input)).digest('hex');

async function ready(page) {
  await page.goto('/');
  await expect(page.locator('#demoAfter')).toHaveText('Allow');
}
async function downloadRecord(page, selector) {
  const downloading = page.waitForEvent('download');
  await page.locator(selector).click();
  return JSON.parse(await fs.readFile(await (await downloading).path(), 'utf8'));
}

test('product landing completes a real-engine review, correction and exact evidence export', async ({ page }) => {
  const errors = [], requests = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => requests.push(request));
  await ready(page);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Understand the permission change before it ships.');
  await expect(page.locator('#tools')).toBeHidden();
  await expect(page.locator('#demoBefore')).toHaveText('ImplicitDeny');
  await expect(page.locator('#demoBeforeMeaning')).toHaveText('Not allowed');
  await expect(page.locator('#demoAfterMeaning')).toHaveText('Allowed');
  await expect(page.locator('#demoCitation')).toContainText('S2 · after.json:10');
  await expect(page.locator('#demoEvidence')).not.toHaveAttribute('open');
  await expect(page.getByRole('button', { name: 'Check correction', exact: true })).toBeVisible();
  await page.locator('#demoEvidence summary').click();
  await expect(page.locator('#demoSource')).toContainText('arn:aws:rds:eu-west-1:111122223333:db:prod-1');
  await expect(page.locator('#demoSource .source-risk')).toHaveCount(4);
  await page.locator('#viewDemoPolicy').click();
  await expect(page.locator('#demoSource')).toContainText('Version');
  await page.locator('#viewDemoPolicy').click();
  await expect(page.locator('#demoSource')).not.toContainText('Version');
  await page.locator('#tryPermission').click();
  await expect(page.locator('#demoTraceStatus')).toContainText('after.json line 10');
  await page.getByRole('button', { name: 'Check correction', exact: true }).click();
  await expect(page.locator('#demoChanges [data-change-kind=removed]')).toContainText('DeleteProductionDatabase');
  await expect(page.locator('#demoChanges [data-change-kind=retained]')).toContainText('ReadReports');
  await expect(page.locator('#demoChanges [data-change-kind=retained]')).toContainText('arn:aws:s3:::reports/*');
  await expect(page.locator('#demoChanges [data-change-kind=added]')).toHaveCount(0);
  await expect(page.locator('#demoVerification')).toContainText('Not checked yet');
  await expect(page.locator('.original-outcome')).toContainText('Stop and review');
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#demoVerification h3')).toHaveText('Deletion not allowed by this policy. Required access preserved.');
  await expect(page.locator('.verification-evidence')).not.toHaveAttribute('open');
  await page.locator('.verification-evidence summary').click();
  await expect(page.locator('#demoVerification')).toContainText('rds:DeleteDBInstance');
  await expect(page.locator('#demoVerification')).toContainText('Correction verified for declared requests');
  await expect(page.locator('.original-outcome')).toContainText('ImplicitDeny → Allow');
  await page.getByRole('button', { name: 'View review record' }).click();
  const record = await downloadRecord(page, '#exportDemoReview');
  expect(record.inputIdentity).toBe(hash(record.inputs));
  expect(record.correction.inputIdentity).toBe(hash(record.correction.inputs));
  expect(record.inputs.after).toBe(await fs.readFile(path.join(samples, 'aws-change-after.json'), 'utf8'));
  expect(record.review.verdict.status).toBe('stop');
  expect(record.correction.result.verified).toBe(true);
  expect(record.correction.result.requiredPreserved).toBe(true);
  expect(record.engine.sourceIdentity).toMatch(/^[a-f0-9]{64}$/);
  expect(record.review.evidence[0].line).toBe(10);
  if (await page.evaluate(() => !!window.PolicyLensLocalAPI)) {
    expect(record.engine.runtime).toBe('browser');
    const origin = new URL(page.url()).origin;
    expect(requests.every(request => request.method() === 'GET' && request.url().startsWith(origin + '/'))).toBe(true);
  }
  expect(errors).toEqual([]);
});

test('edited and rejected corrections never retain a verified export, and invalid inputs recover', async ({ page }) => {
  await ready(page);
  await page.locator('#chapterCorrection').click();
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#demoVerification')).toContainText('Correction verified');
  await page.locator('.demo-edit summary').click();
  await page.locator('#demoCandidate').fill('{"Version":"2012-10-17","Statement":[]}');
  await expect(page.locator('#demoVerification')).toContainText('stale');
  await page.locator('#chapterExport').click();
  const stale = await downloadRecord(page, '#exportDemoReview');
  expect(stale.correction).toBe(null);
  await page.locator('#chapterCorrection').click();
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#demoVerification')).toContainText('Correction not verified');
  await expect(page.locator('#demoVerification')).toContainText('Required access preservedNo');
  await page.locator('#demoRequiredAction').fill('');
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#demoVerification [role=alert]')).toContainText('both required action and resource');
  await page.locator('#demoRequiredAction').fill('s3:GetObject');
  await page.locator('#demoCandidate').fill('{bad');
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#demoVerification [role=alert]')).toContainText('Repair the inputs');
  await page.locator('#demoCandidate').fill(await fs.readFile(path.join(samples, 'aws-change-corrected.json'), 'utf8'));
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#demoVerification')).toContainText('Correction verified');
});

test('own JSON files complete review and correction while home navigation preserves separate work', async ({ page }) => {
  await ready(page);
  await page.getByRole('link', { name: 'Use your own policies', exact: true }).click();
  await expect(page).toHaveURL(/view=review/);
  await expect(page.locator('#productHome')).toBeHidden();
  await page.locator('#beforeFile').setInputFiles(path.join(samples, 'aws-change-before.json'));
  await page.locator('#afterFile').setInputFiles(path.join(samples, 'aws-change-after.json'));
  await expect(page.locator('#changeStatus')).toContainText('loaded');
  await page.locator('#compareBtn').click();
  await expect(page.locator('#compareResult')).toContainText('Stop and review');
  await page.locator('#candidateBox').fill(await fs.readFile(path.join(samples, 'aws-change-corrected.json'), 'utf8'));
  expect(await page.locator('#candidateBox').evaluate(element => getComputedStyle(element).fontFamily)).toContain('monospace');
  await page.locator('#verifyCorrectionBtn').click();
  await expect(page.locator('#correctionResult')).toContainText('Correction verified');
  await expect(page.locator('#correctionResult [data-change-kind=removed]')).toContainText('DeleteProductionDatabase');
  await expect(page.locator('#correctionResult [data-change-kind=retained]')).toContainText('ReadReports');
  const own = await downloadRecord(page, '#exportChange');
  expect(own.correction.result.verified).toBe(true);
  expect(own.inputIdentity).toBe(hash(own.inputs));
  await page.getByRole('link', { name: 'PolicyLens home', exact: true }).click();
  await expect(page.locator('#productHome')).toBeVisible();
  await page.locator('#chapterExport').click();
  await expect(page.locator('#demoRecordSummary')).toContainText('Not checked');
  await page.getByRole('link', { name: 'Use your own policies', exact: true }).click();
  await expect(page.locator('#correctionResult')).toContainText('Correction verified');
  await page.goBack();
  await expect(page.locator('#productHome')).toBeVisible();
  await page.goForward();
  await expect(page.locator('#tools')).toBeVisible();
  await expect(page.locator('#productHome')).toBeHidden();
  await page.locator('#changeInputs summary').click();
  await page.locator('#afterBox').fill(own.inputs.after + '\n');
  await expect(page.locator('#exportChange')).toBeDisabled();
  await expect(page.locator('#correctionResult')).toBeEmpty();
});

test('copy controls copy the actual request, citation and displayed source', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await ready(page);
  await page.locator('#demoEvidence summary').click();
  await page.locator('#copyDemoRequest').click();
  await expect(page.locator('#demoCopyStatus')).toHaveText('Copied checked request.');
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('rds:DeleteDBInstance');
  await page.locator('#copyDemoCitation').click();
  await expect(page.locator('#demoCopyStatus')).toHaveText('Copied evidence citation.');
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('S2 · after.json:10');
  await page.locator('#copyDemoSource').click();
  await expect(page.locator('#demoCopyStatus')).toHaveText('Copied cited statement.');
  expect(JSON.parse(await page.evaluate(() => navigator.clipboard.readText())).Action).toBe('rds:DeleteDBInstance');
  await page.locator('#viewDemoPolicy').click();
  await page.getByRole('button', { name: 'Copy proposed policy', exact: true }).click();
  await expect(page.locator('#demoCopyStatus')).toHaveText('Copied proposed policy.');
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(await fs.readFile(path.join(samples, 'aws-change-after.json'), 'utf8'));
});

test('example load failure makes no verdict claim and retry restores the actual engine result', async ({ page }) => {
  let fail = true;
  await page.route('**/samples/aws-change-after.json', route => fail ? route.fulfill({ status: 503, body: 'Unavailable' }) : route.continue());
  await page.goto('/');
  await expect(page.locator('#exampleStatus [role=alert]')).toContainText('could not load');
  await expect(page.locator('#demoAfter')).toBeHidden();
  await page.locator('#chapterCorrection').click();
  await expect(page.locator('.original-outcome')).toContainText('awaiting');
  await expect(page.locator('#verifyDemoCorrection')).toBeDisabled();
  fail = false;
  await page.locator('#retryExample').click();
  await page.locator('#chapterRisk').click();
  await expect(page.locator('#demoAfter')).toHaveText('Allow');
});

test('keyboard chapter navigation, reduced motion and phone correction/export remain usable', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await ready(page);
  const next = page.getByRole('button', { name: 'Check correction', exact: true });
  expect(await next.evaluate(element => element.clientHeight < 70 && element.scrollWidth <= element.clientWidth)).toBe(true);
  await expect(page.locator('.record-contents')).not.toHaveAttribute('open');
  await page.locator('.record-contents summary').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.record-contents')).toHaveAttribute('open');
  await page.locator('#chapterRisk').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#chapterCorrection')).toBeFocused();
  await expect(page.locator('#demoCorrection')).toBeVisible();
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#demoVerification')).toContainText('Correction verified');
  await page.locator('#chapterCorrection').focus();
  await page.keyboard.press('End');
  await expect(page.locator('#chapterExport')).toBeFocused();
  const record = await downloadRecord(page, '#exportDemoReview');
  expect(record.correction.result.verified).toBe(true);
  await page.locator('#chapterRisk').click();
  await page.locator('#replayTrace').click();
  expect(await page.locator('.proposed').evaluate(element => getComputedStyle(element).animationName)).toBe('none');
  for (const width of [320, 390, 760, 943, 1280, 1536]) {
    await page.setViewportSize({ width, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  }
});

test('a deny override retains its original grant in the edit view and invalid edits discard verification', async ({ page }) => {
  await ready(page);
  await page.locator('#chapterCorrection').click();
  await page.locator('.demo-edit summary').click();
  const policy = JSON.parse(await fs.readFile(path.join(samples, 'aws-change-after.json'), 'utf8'));
  policy.Statement.push({ Sid: '<img src=x onerror=alert(1)>', Effect: 'Deny', Action: 'rds:DeleteDBInstance', Resource: '*' });
  await page.locator('#demoCandidate').fill(JSON.stringify(policy));
  await expect(page.locator('#demoChanges [data-change-kind=removed]')).toContainText('No removed statements');
  await expect(page.locator('#demoChanges [data-change-kind=retained]')).toContainText('DeleteProductionDatabase');
  await expect(page.locator('#demoChanges [data-change-kind=added]')).toContainText('<img src=x onerror=alert(1)>');
  await expect(page.locator('#demoChanges img')).toHaveCount(0);
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#demoVerification')).toContainText('Correction verified');
  await expect(page.locator('#demoVerification')).toContainText('ExplicitDeny');
  await page.locator('#demoCandidate').fill('{bad');
  await expect(page.locator('#demoChanges')).toContainText('Fix the candidate JSON');
  await expect(page.locator('#demoVerification')).toContainText('stale');
  await page.locator('#chapterExport').click();
  expect((await downloadRecord(page, '#exportDemoReview')).correction).toBe(null);
});

test('date conditions and unresolved Denies cannot export a false correction proof', async ({ page }) => {
  const read = { Sid: 'ReadReports', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/daily.csv' };
  const destroy = { Sid: 'DeleteProduction', Effect: 'Allow', Action: 'rds:DeleteDBInstance', Resource: 'arn:aws:rds:eu-west-1:111122223333:db:prod-1' };
  const deny = { ...read, Sid: 'DenyWithoutMfa', Effect: 'Deny', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } } };
  const policy = (...Statement) => JSON.stringify({ Version: '2012-10-17', Statement }, null, 2);
  await ready(page);
  await page.getByRole('link', { name: 'Use your own policies', exact: true }).click();
  for (const scenario of ['date', 'epoch', 'unknown-deny']) {
    await page.locator('#changeInputs').evaluate(element => { element.open = true; });
    await page.locator('#beforeBox').fill(policy(read, ...(scenario === 'unknown-deny' ? [deny] : [])));
    await page.locator('#afterBox').fill(policy(read, ...(scenario === 'unknown-deny' ? [deny] : []), destroy));
    await page.locator('#compareAction').fill(destroy.Action);
    await page.locator('#compareResource').fill(destroy.Resource);
    await page.locator('#compareContext').fill(scenario === 'date' ? '{"aws:CurrentTime":"2026-10-23T00:00:00Z"}' : scenario === 'epoch' ? '{"aws:CurrentTime":"2000-01-01T00:00:00Z"}' : '{}');
    await page.locator('#compareBtn').click();
    await page.locator('#candidateBox').fill(scenario !== 'unknown-deny'
      ? policy(read, { ...destroy, Condition: { DateNotEquals: { 'aws:CurrentTime': scenario === 'epoch' ? '0' : '2026-10-24T00:00:00Z' } } })
      : policy(read, deny));
    await page.locator('#requiredAction').fill(read.Action);
    await page.locator('#requiredResource').fill(read.Resource);
    await page.locator('#verifyCorrectionBtn').click();
    await expect(page.locator('#correctionResult')).toContainText('Correction not verified');
    if (scenario === 'unknown-deny') {
      await expect(page.locator('#correctionResult')).toContainText('Not determined');
      await expect(page.locator('#correctionResult')).toContainText('DenyWithoutMfa');
    }
    const record = await downloadRecord(page, '#exportChange');
    expect(record.correction.result.verified).toBe(false);
    expect(scenario !== 'unknown-deny' ? record.correction.result.riskClosed : record.correction.result.requiredPreserved).toBe(false);
  }
});

test('late verification cannot restore a pass after the candidate changes', async ({ page }) => {
  await ready(page);
  test.skip(await page.evaluate(() => !!window.PolicyLensLocalAPI), 'Network response race applies to the Node server; the static engine runs in this tab.');
  await page.locator('#chapterCorrection').click();
  await page.locator('.demo-edit summary').click();
  let release;
  const barrier = new Promise(resolve => { release = resolve; });
  await page.route('**/api/change/verify', async route => {
    const response = await route.fetch();
    await barrier;
    await route.fulfill({ response });
  });
  await page.locator('#verifyDemoCorrection').click();
  await expect(page.locator('#verifyDemoCorrection')).toHaveText('Verifying…');
  await page.locator('#demoCandidate').fill('{"Statement":[]}');
  release();
  await expect(page.locator('#verifyDemoCorrection')).toBeEnabled();
  await expect(page.locator('#demoVerification')).toContainText('stale');
  await page.locator('#chapterExport').click();
  expect((await downloadRecord(page, '#exportDemoReview')).correction).toBe(null);
});
