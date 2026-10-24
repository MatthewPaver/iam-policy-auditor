'use strict';

function asArray(x) {
  return x == null ? [] : Array.isArray(x) ? x : [x];
}

function uniq(a) {
  return [...new Set(a)];
}

// IAM-style glob: '*' matches any run, '?' matches one char. Case-insensitive,
// matching how AWS evaluates action names.
function globMatch(pattern, str, caseSensitive = false) {
  if (pattern == null) return false;
  if (pattern === str) return true;
  let re = '';
  for (const ch of String(pattern)) {
    if (ch === '*') re += '.*';
    else if (ch === '?') re += '.';
    else re += ch.replace(/[.+^${}()|[\]\\/]/g, '\\$&');
  }
  return new RegExp(`^${re}$`, caseSensitive ? 'su' : 'isu').test(String(str));
}

module.exports = { asArray, uniq, globMatch };
