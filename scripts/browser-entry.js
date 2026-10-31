'use strict';
const { reviewChange, verifyCorrection } = require('../src/change_review');
window.PolicyLensLocalAPI = async (path, body = {}) => {
  if (path === '/api/health') return { ai: false, hosted: false, browser: true };
  if (path === '/api/samples') return [];
  if (path === '/api/change/review') {
    // Request fields are optional: empty action/resource means request-free review.
    const hasRequest = Boolean(body.action && String(body.action).trim() && body.resource && String(body.resource).trim());
    const request = hasRequest
      ? {
        action: body.action,
        resource: body.resource,
        context: body.context,
        contextComplete: body.contextComplete,
        ...(body.principal ? { principal: body.principal } : {}),
      }
      : undefined;
    return {
      ...reviewChange({ before: body.before, after: body.after, request }),
      ai: null,
      aiEvaluation: null,
      aiError: null,
    };
  }
  if (path === '/api/change/verify') return verifyCorrection(body);
  throw new Error('This browser demo supports permission-change review. Run the repository locally for account analysis.');
};
