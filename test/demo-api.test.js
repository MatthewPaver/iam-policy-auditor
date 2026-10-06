'use strict';
const assert = require('assert');
const http = require('http');

// Spin a one-off server on a free port with HOSTED=1 so the hosted demo path is on.
process.env.HOSTED = '1';
process.env.HOST = '127.0.0.1';
process.env.PORT = '0'; // we'll bind manually — actually server reads PORT at load

// Undergrad note: require after env so HOSTED flags stick
delete require.cache[require.resolve('../server.js')];
// server.js listens immediately — test via spawning is cleaner
const { spawn } = require('child_process');
const path = require('path');

const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
  env: { ...process.env, HOSTED: '1', HOST: '127.0.0.1', PORT: '4199' },
  stdio: ['ignore', 'pipe', 'pipe'],
});

function get(urlPath) {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:4199${urlPath}`, (res) => {
      let d = '';
      res.on('data', (c) => { d += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(d) }); }
        catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

function waitReady() {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = () => {
      http.get('http://127.0.0.1:4199/api/health', (res) => {
        res.resume();
        if (res.statusCode === 200) resolve();
        else if (Date.now() - t0 > 5000) reject(new Error('timeout'));
        else setTimeout(tick, 100);
      }).on('error', () => {
        if (Date.now() - t0 > 5000) reject(new Error('timeout'));
        else setTimeout(tick, 100);
      });
    };
    tick();
  });
}

(async () => {
  try {
    await waitReady();
    const health = await get('/api/health');
    assert.equal(health.body.hosted, true, 'hosted flag');

    const demo = await get('/api/demo/run');
    assert.ok(demo.body.who.rows.length >= 1, 'who-can rows');
    assert.ok(demo.body.reach.results.length >= 1, 'reach-admin');
    assert.ok(demo.body.exposure.findings.length >= 1, 'exposures');
    console.log('demo-api — 3 passed');
  } finally {
    child.kill('SIGTERM');
  }
})().catch((e) => {
  console.error(e);
  child.kill('SIGTERM');
  process.exit(1);
});
