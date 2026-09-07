import type { Env } from './types.js';
import { handleStripeWebhook } from './stripe-webhook.js';
import { handleLicenseIssue } from './license-issue.js';
import { handleLicenseVerify } from './license-verify.js';

// `assets.run_worker_first` in wrangler.jsonc scopes this Worker to exactly
// `/webhooks/*` and `/license/*` — every other request is served as a static
// asset and never reaches this file, so there is no fallback branch here for
// the landing page itself.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/webhooks/stripe') {
      return handleStripeWebhook(request, env);
    }
    if (url.pathname === '/license/issue') {
      return handleLicenseIssue(request, env);
    }
    if (url.pathname === '/license/verify') {
      return handleLicenseVerify(request, env);
    }

    return new Response('Not Found', { status: 404 });
  },
};
