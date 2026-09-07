import Stripe from 'stripe';
import type { Env } from './types.js';

// Workers has no Node `https` module, so the SDK's default HTTP client
// doesn't work here — it must be built with the fetch-based client instead.
export function createStripeClient(env: Env): Stripe {
  return new Stripe(env.STRIPE_SECRET_KEY, {
    httpClient: Stripe.createFetchHttpClient(),
  });
}
