'use strict';

// Drop the real AWSSupportServiceRolePolicy v19/v20 pair with no request typed.
// The page must still stop and list s3:GetObject with a line number.

const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');

const examples = path.join(__dirname, '..', '..', 'examples', 'policies');
const site = path.resolve(__dirname, '../../site');
test.beforeEach(async ({ page }) => {
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    const file = path.resolve(site, `.${decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname)}`);
    if (!file.startsWith(site + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      return route.fulfill({ status: 404, body: 'Not found' });
    }
    const type = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.woff2': 'font/woff2' };
    await route.fulfill({ path: file, contentType: type[path.extname(file)] || 'application/octet-stream' });
  });
});

test('v19 to v20 without a request shows Stop and s3:GetObject', async ({ page }) => {
  await page.goto('/?view=review');
  await page.locator('#beforeBox').fill(
    fs.readFileSync(path.join(examples, 'AWSSupportServiceRolePolicy.v19.json'), 'utf8'),
  );
  await page.locator('#afterBox').fill(
    fs.readFileSync(path.join(examples, 'AWSSupportServiceRolePolicy.v20.json'), 'utf8'),
  );
  await page.locator('#compareAction').fill('');
  await page.locator('#compareResource').fill('');
  await page.getByRole('button', { name: 'Check my policies', exact: true }).click();
  await expect(page.locator('#compareResult')).toContainText('Stop and review');
  await expect(page.locator('#compareResult')).toContainText(/s3:GetObject/i);
  await expect(page.locator('#compareResult')).toContainText(/line\s+\d+/i);
});

// Round 5 acceptance: use the actual example files and browser-local engine.
test('real AWS incident opens with Stop, explains S3 reading and highlights its source', async ({ page }) => {
  await page.goto('/?view=review');
  await page.getByRole('button', { name: 'Try a real AWS incident', exact: true }).click();
  const result = page.locator('#compareResult');
  await expect(result.locator('.verdict').first()).toContainText('Stop:');
  await expect(result).toContainText('This identity can now read any object in any S3 bucket.');
  await expect(result.getByRole('heading', { name: 'Stop', exact: true })).toBeVisible();
  const lower = result.locator('details.lower-risk');
  await expect(lower).not.toHaveAttribute('open');
  await result.locator('[data-policy-line="1640"]').first().click();
  await expect(page.locator('#afterSource .highlighted-line')).toContainText(/s3:getObject/i);
  await expect(page.locator('#incidentSource')).toHaveAttribute('href', /AWS-2021-007/);
});

test('copy review includes the Stop sentence and line 1640, then edits disable copying', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/?view=review');
  await page.getByRole('button', { name: 'Try a real AWS incident', exact: true }).click();
  const copy = page.getByRole('button', { name: 'Copy review for a pull request', exact: true });
  await expect(copy).toBeEnabled();
  await copy.click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toContain('Stop:');
  expect(copied).toContain('line 1640');
  expect(copied).toMatch(/s3:getObject/i);
  await page.locator('#changeInputs').evaluate(el => { el.open = true; });
  await page.locator('#beforeBox').fill('{}');
  await expect(copy).toBeDisabled();
});
