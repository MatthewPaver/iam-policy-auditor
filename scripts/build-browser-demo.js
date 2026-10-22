'use strict';
// Bundle the existing deterministic modules; no server, API keys or runtime dependencies.
const fs = require('fs');
const path = require('path');
const { createHash } = require('crypto');
const root = path.join(__dirname, '..');
const out = path.join(root, 'site');
const modules = new Map();
const catalogue = fs.readFileSync(path.join(root, 'data/aws-actions.json'), 'utf8');
const source = require('../src/engine_identity');
const browserIdentity = { ...source, runtime: 'browser', sourceIdentity: createHash('sha256').update(source.sourceIdentity).update(fs.readFileSync(path.join(__dirname, 'browser-entry.js'))).update(fs.readFileSync(__filename)).digest('hex') };
modules.set('src/engine_identity.js', `module.exports = ${JSON.stringify(browserIdentity)};`);
modules.set('fs', `module.exports = {readFileSync(file) {if (!file.endsWith('data/aws-actions.json')) throw new Error('Unavailable browser file'); return ${JSON.stringify(catalogue)};}};`);
modules.set('path', 'module.exports = {join(...parts) {return parts.join("/");}};');
function add(id) {
  if (modules.has(id)) return;
  const text = fs.readFileSync(path.join(root, id), 'utf8');
  modules.set(id, text);
  for (const match of text.matchAll(/require\(['"]([^'"]+)['"]\)/g)) {
    const request = match[1];
    if (!request.startsWith('.')) {
      if (!modules.has(request)) throw new Error(`Unsupported browser dependency: ${request}`);
      continue;
    }
    let resolved = path.posix.normalize(path.posix.join(path.posix.dirname(id), request));
    if (!path.posix.extname(resolved)) resolved += '.js';
    add(resolved);
  }
}
add('scripts/browser-entry.js');
const wrapped = [...modules].map(([id, text]) => `${JSON.stringify(id)}:function(require,module,exports,__dirname){\n${text}\n}`).join(',\n');
const runtime = `(function(){'use strict';const modules={${wrapped}},cache={};function resolve(request,from){if(!request.startsWith('.'))return request;const parts=(from.slice(0,from.lastIndexOf('/')+1)+request).split('/'),result=[];for(const part of parts){if(part==='..')result.pop();else if(part!=='.')result.push(part);}let id=result.join('/');if(!id.endsWith('.js'))id+='.js';return id;}function load(id){if(cache[id])return cache[id].exports;if(!modules[id])throw new Error('Unknown module: '+id);const module={exports:{}};cache[id]=module;modules[id](request=>load(resolve(request,id)),module,module.exports,id.slice(0,id.lastIndexOf('/')));return module.exports;}load('scripts/browser-entry.js');})();`;
fs.mkdirSync(out, { recursive: true });
for (const file of ['style.css', 'app.js']) fs.copyFileSync(path.join(root, 'public', file), path.join(out, file));
fs.cpSync(path.join(root, 'samples'), path.join(out, 'samples'), { recursive: true });
let html = fs.readFileSync(path.join(root, 'public/index.html'), 'utf8')
  .replace('href="/style.css"', 'href="./style.css"')
  .replace('<body>', '<body class="browser-demo">')
  .replace('<script src="/app.js"></script>', '<script src="./engine-browser.js"></script><script src="./app.js"></script>')
  .replace('Request an optional AI explanation (sends extracted facts to Anthropic when configured)', 'AI explanation is available in the local server version only');
fs.writeFileSync(path.join(out, 'index.html'), html);
fs.appendFileSync(path.join(out, 'style.css'), '\n.browser-demo #tabs .tab:not([data-tab=compare]),.browser-demo .ai-opt-in{display:none}.browser-demo #tabs:after{content:"Browser-local change review · synthetic example included";font-size:12px;color:var(--muted);padding:12px;}\n');
fs.writeFileSync(path.join(out, 'engine-browser.js'), runtime);
console.log(`Browser demo built: ${modules.size} existing modules, no external API or server.`);
