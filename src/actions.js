'use strict';

// Runtime API over the ingested AWS action catalogue (data/aws-actions.json,
// produced by scripts/ingest-aws-actions.js from iann0036/iam-dataset).
//
// Gives the engine real, authoritative answers to:
//   - what concrete actions does "s3:*" or "ec2:Describe*" expand to?
//   - is this action Read / Write / List / Tagging / Permissions management?
//   - how much does a statement actually grant (blast radius by access level)?
// replacing the previous regex-verb heuristic which guessed from the name.

const fs = require('fs');
const path = require('path');
const { globMatch } = require('./util');

const DB_PATH = path.join(__dirname, '..', 'data', 'aws-actions.json');

let _db = null;
let _loadError = null;

function db() {
  if (_db || _loadError) return _db;
  try {
    _db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (e) {
    _loadError = e;
    // Graceful degradation: engine still runs, just without catalogue-backed
    // expansion/classification. Callers check isLoaded().
    _db = null;
  }
  return _db;
}

function isLoaded() {
  return Boolean(db());
}

function meta() {
  const d = db();
  return d ? d._meta : null;
}

const LEVEL_NAME = { R: 'Read', W: 'Write', L: 'List', T: 'Tagging', P: 'Permissions management', U: 'Unknown' };
const MUTATING = new Set(['W', 'P', 'T']); // Write, Permissions management, Tagging change state

function splitAction(action) {
  const i = String(action).indexOf(':');
  if (i < 0) return { service: null, name: String(action) };
  return { service: String(action).slice(0, i).toLowerCase(), name: String(action).slice(i + 1) };
}

// Access level code ('R'|'W'|'L'|'T'|'P'|'U') for a concrete action, or null if
// the action/service is unknown to the catalogue.
function levelCode(action) {
  const d = db();
  if (!d) return null;
  const { service, name } = splitAction(action);
  const svc = d.services[service];
  if (!svc) return null;
  return svc.actions[name] || null;
}

function accessLevel(action) {
  const c = levelCode(action);
  return c ? LEVEL_NAME[c] : 'Unknown';
}

// A concrete action that changes state or permissions. Unknown actions return
// null (caller decides how to treat uncertainty) rather than a false negative.
function isMutating(action) {
  const c = levelCode(action);
  if (c == null) return null;
  return MUTATING.has(c);
}

// Expand an action pattern to concrete catalogue actions.
// "s3:DeleteObject" -> [that], "s3:Delete*" -> globbed, "s3:*" -> all s3,
// "*" -> capped (won't materialize 21k). Returns { actions, total, capped }.
function expand(pattern, { cap = 500 } = {}) {
  const d = db();
  if (!d) return { actions: [], total: 0, capped: false, unavailable: true };
  const p = String(pattern);
  const { service, name } = splitAction(p);

  const services = service && service !== '*' ? [service] : Object.keys(d.services);
  const out = [];
  let total = 0;
  for (const svcKey of services) {
    const svc = d.services[svcKey];
    if (!svc) continue;
    for (const act of Object.keys(svc.actions)) {
      const full = `${svcKey}:${act}`;
      // Match against the full "service:Action" for bare "*", else against the action name.
      const ok = (service && service !== '*')
        ? globMatch(name, act)
        : globMatch(p, full);
      if (ok) {
        total++;
        if (out.length < cap) out.push(full);
      }
    }
  }
  return { actions: out, total, capped: total > out.length };
}

// A flat list of every "service:Action" in the catalogue. Built once and cached
// because the NotAction complement below needs to walk the whole universe.
let _allActions = null;
function allActions() {
  if (_allActions) return _allActions;
  const d = db();
  if (!d) return [];
  const list = [];
  for (const [svcKey, svc] of Object.entries(d.services)) {
    for (const act of Object.keys(svc.actions)) list.push(`${svcKey}:${act}`);
  }
  _allActions = list;
  return list;
}

// The concrete actions a statement actually grants. Handles both the normal
// Action list and the Allow+NotAction complement (which grants EVERYTHING except
// the listed patterns — that is the whole point of NotAction and it is easy to
// under-estimate by eye).
function grantedActions({ actions: actionPatterns = [], notActions = [] }) {
  const d = db();
  if (!d) return [];
  if (actionPatterns.length) {
    const set = new Set();
    for (const pat of actionPatterns) {
      for (const a of expand(pat, { cap: Number.MAX_SAFE_INTEGER }).actions) set.add(a);
    }
    return [...set];
  }
  if (notActions.length) {
    return allActions().filter((a) => !notActions.some((p) => globMatch(p, a)));
  }
  return [];
}

// Count a concrete action list by access level, with the two rollups that
// actually matter for risk triage: how many can change state, and how many can
// change who has access.
function tally(actionList) {
  const byLevel = { Read: 0, Write: 0, List: 0, Tagging: 0, 'Permissions management': 0, Unknown: 0 };
  for (const a of actionList) byLevel[accessLevel(a)]++;
  return {
    total: actionList.length,
    byLevel,
    mutating: byLevel.Write + byLevel['Permissions management'] + byLevel.Tagging,
    permissionsManagement: byLevel['Permissions management'],
  };
}

// Blast radius of a set of Action patterns (deduped union). Kept for existing
// callers; now a thin wrapper over the shared grant/tally path.
function blastRadius(patterns) {
  if (!db()) return { unavailable: true };
  return tally(grantedActions({ actions: patterns }));
}

// Blast radius of a whole statement, correctly accounting for NotAction.
function grantedBlast(stmtLike) {
  if (!db()) return { unavailable: true };
  return tally(grantedActions(stmtLike));
}

// Validate that a curated action name actually exists (used to keep the NL
// concept KB honest against the catalogue).
function exists(action) {
  return levelCode(action) != null;
}

module.exports = {
  isLoaded, meta, accessLevel, levelCode, isMutating, expand, exists, LEVEL_NAME,
  blastRadius, grantedActions, grantedBlast, tally, allActions,
};
