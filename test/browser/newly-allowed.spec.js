'use strict';

// Drop the real AWSSupportServiceRolePolicy v19/v20 pair with no request typed.
// The page must still stop and list s3:GetObject with a line number.

const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');

const examples = path.join(__dirname, '..', '..', 'examples', 'policies');

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
