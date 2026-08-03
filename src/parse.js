'use strict';

// Position-aware JSON parser. Returns { value, pointers } where `pointers` maps
// JSON-pointer paths ("/Statement/0/Action", root = "") to { line, endLine }.
// This is what lets every finding and answer cite exact policy lines.
function parseWithPointers(text) {
  let i = 0;
  let line = 1;
  const pointers = Object.create(null);

  const fail = (msg) => {
    const e = new SyntaxError(`${msg} (line ${line})`);
    e.line = line;
    throw e;
  };

  const skipWs = () => {
    while (i < text.length) {
      const c = text[i];
      if (c === '\n') { line++; i++; }
      else if (c === ' ' || c === '\t' || c === '\r') i++;
      else if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; }
      else break;
    }
  };

  const literal = (word, val) => {
    if (text.slice(i, i + word.length) !== word) fail('Unexpected token');
    i += word.length;
    return val;
  };

  const parseString = () => {
    i++; // opening quote
    let out = '';
    while (i < text.length) {
      const c = text[i];
      if (c === '"') { i++; return out; }
      if (c === '\\') {
        const n = text[i + 1];
        if (n === 'u') { out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)); i += 6; }
        else {
          out += ({ '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' })[n] ?? n;
          i += 2;
        }
      } else {
        if (c === '\n') line++;
        out += c;
        i++;
      }
    }
    fail('Unterminated string');
  };

  const parseNumber = () => {
    const start = i;
    while (i < text.length && /[-+0-9.eE]/.test(text[i])) i++;
    const num = Number(text.slice(start, i));
    if (Number.isNaN(num)) fail('Invalid number');
    return num;
  };

  const escapePtr = (s) => String(s).replace(/~/g, '~0').replace(/\//g, '~1');

  const parseObject = (path) => {
    i++; // {
    const obj = {};
    skipWs();
    if (text[i] === '}') { i++; return obj; }
    for (;;) {
      skipWs();
      if (text[i] !== '"') fail('Expected property name in double quotes');
      const key = parseString();
      skipWs();
      if (text[i] !== ':') fail('Expected ":" after property name');
      i++;
      obj[key] = parseValue(`${path}/${escapePtr(key)}`);
      skipWs();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; return obj; }
      fail('Expected "," or "}" in object');
    }
  };

  const parseArray = (path) => {
    i++; // [
    const arr = [];
    skipWs();
    if (text[i] === ']') { i++; return arr; }
    for (;;) {
      arr.push(parseValue(`${path}/${arr.length}`));
      skipWs();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === ']') { i++; return arr; }
      fail('Expected "," or "]" in array');
    }
  };

  const parseValue = (path) => {
    skipWs();
    if (i >= text.length) fail('Unexpected end of input');
    const startLine = line;
    const c = text[i];
    let v;
    if (c === '{') v = parseObject(path);
    else if (c === '[') v = parseArray(path);
    else if (c === '"') v = parseString();
    else if (c === 't') v = literal('true', true);
    else if (c === 'f') v = literal('false', false);
    else if (c === 'n') v = literal('null', null);
    else if (c === '-' || (c >= '0' && c <= '9')) v = parseNumber();
    else fail(`Unexpected character "${c}"`);
    pointers[path] = { line: startLine, endLine: line };
    return v;
  };

  const value = parseValue('');
  skipWs();
  if (i < text.length) fail('Trailing content after JSON document');
  return { value, pointers };
}

module.exports = { parseWithPointers };
