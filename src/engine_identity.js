'use strict';

const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');
const { version: engineVersion } = require('../package.json');
const sourceHash = createHash('sha256');
for (const name of fs.readdirSync(__dirname).filter(name => name.endsWith('.js')).sort()) {
  sourceHash.update(name); sourceHash.update(fs.readFileSync(path.join(__dirname, name)));
}
const cataloguePath = path.join(__dirname, '..', 'data', 'aws-actions.json');
if (fs.existsSync(cataloguePath)) sourceHash.update(fs.readFileSync(cataloguePath));
module.exports = { name: 'PolicyLens', version: engineVersion, sourceIdentity: sourceHash.digest('hex') };
