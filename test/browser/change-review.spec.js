'use strict';
const { test, expect } = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');
const captures = process.env.PORTFOLIO_CAPTURES;

async function sample(page) {
  await page.goto('/');
  await page.getByRole('button', { name: 'Run example change' }).click();
  await expect(page.locator('#compareResult')).toContainText('Stop and review');
}

test('proposal, correction, export, stale edits and source identity', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await sample(page);
  await expect(page.locator('#inputPanel')).toBeHidden();
  await expect(page.locator('#changeInputs')).not.toHaveAttribute('open');
  await expect(page.locator('#compareResult')).toContainText('after.json:10');
  if (captures) { await fs.mkdir(captures, { recursive: true }); await page.screenshot({ path: path.join(captures, 'policylens-review.png') }); }
  await page.getByRole('button', { name: 'Verify correction', exact: true }).click();
  await expect(page.locator('#correctionResult')).toContainText('Correction verified for declared requests');
  await expect(page.locator('#correctionResult')).toContainText('risk closed', { ignoreCase: true });
  await expect(page.locator('#compareResult')).toContainText('Stop and review');
  if (captures) { await page.evaluate(() => window.scrollTo(0, 0)); await page.screenshot({ path: path.join(captures, 'policylens-correction.png') }); }
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export review JSON' }).click();
  const record = JSON.parse(await fs.readFile(await (await downloaded).path(), 'utf8'));
  expect(record.inputIdentity).toMatch(/^[a-f0-9]{64}$/);
  expect(record.review.verdict.status).toBe('stop');
  expect(record.engine).toEqual(record.review.engine);
  expect(record.engine.sourceIdentity).toMatch(/^[a-f0-9]{64}$/);
  expect(record.correction.result.verified).toBe(true);
  expect(record.correction.inputIdentity).toMatch(/^[a-f0-9]{64}$/);
  await page.locator('#changeInputs summary').click();
  await page.locator('#afterBox').fill(record.inputs.after + '\n');
  await expect(page.locator('#changeStatus')).toContainText('stale');
  await expect(page.getByRole('button', { name: 'Export review JSON' })).toBeDisabled();
  await expect(page.locator('#correctionResult')).toBeEmpty();
  expect(errors).toEqual([]);
});

test('repair invalid JSON and reject a correction which drops required access', async ({ page }) => {
  await sample(page);
  await page.locator('#candidateBox').fill('{"Version":"2012-10-17","Statement":[]}');
  await page.getByRole('button', { name: 'Verify correction', exact: true }).click();
  await expect(page.locator('#correctionResult')).toContainText('Correction not verified');
  await expect(page.locator('#correctionResult')).toContainText('required access preserved: no');
  await page.locator('#requiredAction').fill('');
  await page.getByRole('button', { name: 'Verify correction', exact: true }).click();
  await expect(page.locator('#correctionResult [role=alert]')).toContainText('required action and resource');
  await page.locator('#changeInputs summary').click();
  await page.locator('#beforeBox').fill('{bad JSON');
  await page.getByRole('button', { name: 'Review this change', exact: true }).click();
  await expect(page.locator('#compareResult [role=alert]')).toContainText('Repair the inputs');
  await expect(page.getByRole('button', { name: 'Export review JSON' })).toBeDisabled();
});

test('late review cannot replace edited inputs', async ({ page }) => {
  await sample(page);
  await page.locator('#changeInputs summary').click();
  let release;
  const barrier = new Promise(resolve => { release = resolve; });
  await page.route('**/api/change/review', async route => {
    const response = await route.fetch();
    await barrier;
    await route.fulfill({ response });
  });
  await page.getByRole('button', { name: 'Review this change', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Reviewing…', exact: true })).toBeDisabled();
  await page.locator('#compareAction').fill('s3:DeleteObject');
  release();
  await expect(page.getByRole('button', { name: 'Review this change', exact: true })).toBeEnabled();
  await expect(page.locator('#changeStatus')).toContainText('stale');
  await expect(page.getByRole('button', { name: 'Export review JSON' })).toBeDisabled();
});

test('phone editor panes and complete sample correction', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await sample(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  if (captures) await page.screenshot({ path: path.join(captures, 'policylens-mobile.png') });
  await page.locator('#changeInputs summary').click();
  await expect(page.locator('#beforeBox')).toBeVisible();
  await expect(page.locator('#afterBox')).toBeHidden();
  await page.getByRole('button', { name: 'Proposed', exact: true }).click();
  await expect(page.locator('#afterBox')).toBeVisible();
  await expect(page.locator('#beforeBox')).toBeHidden();
  await page.getByRole('button', { name: 'Verify correction', exact: true }).click();
  await expect(page.locator('#correctionResult')).toContainText('Correction verified for declared requests');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});
