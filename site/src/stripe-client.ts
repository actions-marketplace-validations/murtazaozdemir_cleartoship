import Stripe from 'stripe';
import type { Env } from './types.js';

type SecretName = 'STRIPE_SECRET_KEY' | 'STRIPE_WEBHOOK_SECRET' | 'LICENSE_SIGNING_PRIVATE_KEY_JWK';

// Billing is dormant: until the secrets are set with `wrangler secret put`,
// these routes are reachable but unconfigured. `new Stripe(undefined)` throws,
// which surfaced as an unhandled 500 with a stack trace. Each handler checks
// the secrets it needs first and answers a plain 503 instead. The response
// names no secret, only that billing is not available.
export function billingUnavailable(env: Env, names: SecretName[]): Response | null {
  const missing = names.filter((n) => !env[n]);
  if (missing.length === 0) return null;
  console.error(`billing route called with unset secrets: ${missing.join(', ')}`);
  return Response.json({ error: 'billing is not configured' }, { status: 503 });
}

// Workers has no Node `https` module, so the SDK's default HTTP client
// doesn't work here — it must be built with the fetch-based client instead.
export function createStripeClient(env: Env): Stripe {
  return new Stripe(env.STRIPE_SECRET_KEY, {
    httpClient: Stripe.createFetchHttpClient(),
  });
}
