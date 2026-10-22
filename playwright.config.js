'use strict';
const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
  testDir: './test/browser',
  testIgnore: 'static-demo.spec.js',
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:4179', viewport: { width: 1280, height: 720 }, reducedMotion: 'reduce' },
  webServer: { command: 'node server.js', url: 'http://127.0.0.1:4179/api/health', env: { HOST: '127.0.0.1', PORT: '4179', ANTHROPIC_API_KEY: '', HOSTED: '0' } },
});
