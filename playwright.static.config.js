'use strict';
const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
  testDir: './test/browser',
  testMatch: 'static-demo.spec.js',
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:4180', viewport: { width: 1280, height: 720 } },
  webServer: { command: 'python3 -m http.server 4180 --bind 127.0.0.1 --directory site', url: 'http://127.0.0.1:4180' },
});
