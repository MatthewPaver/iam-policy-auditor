'use strict';
const { reviewChange, verifyCorrection } = require('../src/change_review');
window.PolicyLensLocalAPI = async (path, body = {}) => {
  if (path === '/api/health') return { ai: false, hosted: false, browser: true };
  if (path === '/api/samples') return [];
  if (path === '/api/change/review') return { ...reviewChange({ before: body.before, after: body.after, request: { action: body.action, resource: body.resource, context: body.context, contextComplete: body.contextComplete } }), ai: null, aiEvaluation: null, aiError: null };
  if (path === '/api/change/verify') return verifyCorrection(body);
  throw new Error('This browser demo supports permission-change review. Run the repository locally for account analysis.');
};
