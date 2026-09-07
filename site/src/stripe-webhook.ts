import Stripe from 'stripe';
import type { Env, LicensePayload } from './types.js';
import { CURRENT_KEY_ID } from './types.js';
import { createStripeClient } from './stripe-client.js';
import { signLicenseToken } from './license-token.js';
import { upsertLicense, revokeBySubscription } from './db.js';

// Single bundled "Pro" tier today — the field exists so a future à la carte
// or "team" tier has somewhere to put a different list without a schema
// change.
const ENTITLED_SCANNERS = ['rls', 'server-actions', 'llm'];
const GRACE_PERIOD_SECONDS = 7 * 24 * 60 * 60;
const FALLBACK_PERIOD_SECONDS = 30 * 24 * 60 * 60;

const ACTIVE_STATUSES = new Set<Stripe.Subscription.Status>(['active', 'trialing']);
const REVOKED_STATUSES = new Set<Stripe.Subscription.Status>([
  'canceled',
  'unpaid',
  'incomplete_expired',
]);

export async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const signature = request.headers.get('stripe-signature');
  if (!signature) {
    return new Response('Missing stripe-signature header', { status: 400 });
  }

  const rawBody = await request.text();
  const stripe = createStripeClient(env);

  let event: Stripe.Event;
  try {
    // The async, WebCrypto-based verifier — the sync `constructEvent` reaches
    // for Node's sync HMAC, which the Workers runtime doesn't guarantee.
    event = await stripe.webhooks.constructEventAsync(
      rawBody,
      signature,
      env.STRIPE_WEBHOOK_SECRET,
      undefined,
      Stripe.createSubtleCryptoProvider(),
    );
  } catch (err) {
    return new Response(`Webhook signature verification failed: ${(err as Error).message}`, {
      status: 400,
    });
  }

  if (event.type.startsWith('customer.subscription.')) {
    await handleSubscriptionEvent(event.data.object as Stripe.Subscription, stripe, env);
  }

  return Response.json({ received: true });
}

// The field name/location for a subscription's current billing-period end
// has moved between Stripe API versions (top-level on the subscription in
// older versions, per-item in newer ones). Check both, and fall back to a
// conservative 30-day window if neither is present rather than failing the
// webhook outright — worth re-verifying against whichever API version the
// real Stripe account ends up pinned to before this goes live.
function currentPeriodEnd(subscription: Stripe.Subscription): number {
  const topLevel = (subscription as unknown as { current_period_end?: number }).current_period_end;
  if (typeof topLevel === 'number') return topLevel;
  const item = subscription.items.data[0] as unknown as { current_period_end?: number } | undefined;
  if (item && typeof item.current_period_end === 'number') return item.current_period_end;
  return Math.floor(Date.now() / 1000) + FALLBACK_PERIOD_SECONDS;
}

async function handleSubscriptionEvent(
  subscription: Stripe.Subscription,
  stripe: Stripe,
  env: Env,
): Promise<void> {
  const customerId =
    typeof subscription.customer === 'string' ? subscription.customer : subscription.customer.id;

  if (REVOKED_STATUSES.has(subscription.status)) {
    await revokeBySubscription(env.DB, subscription.id, `stripe status: ${subscription.status}`);
    return;
  }

  if (!ACTIVE_STATUSES.has(subscription.status)) {
    // past_due, incomplete, paused, etc. — not a grant, not yet a revoke.
    // Stripe will send a further event (either to an active status or to a
    // revoked one above) once the state resolves.
    return;
  }

  const customer = await stripe.customers.retrieve(customerId);
  const email = 'deleted' in customer && customer.deleted ? '' : (customer as Stripe.Customer).email ?? '';

  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = currentPeriodEnd(subscription) + GRACE_PERIOD_SECONDS;
  const jti = crypto.randomUUID();

  const payload: LicensePayload = {
    v: 1,
    sub: customerId,
    email,
    plan: 'pro',
    scanners: ENTITLED_SCANNERS,
    iat: issuedAt,
    exp: expiresAt,
    kid: CURRENT_KEY_ID,
    jti,
  };

  // Signing here isn't strictly necessary for the webhook's own job (D1 is
  // the source of truth for revocation, and /license/issue re-signs on
  // demand from the stored fields) — but doing it once up front fails loudly
  // and immediately if LICENSE_SIGNING_PRIVATE_KEY_JWK is ever missing,
  // rather than only surfacing that at the moment a customer tries to fetch
  // their key.
  await signLicenseToken(payload, env);

  await upsertLicense(env.DB, {
    jti,
    customerId,
    subscriptionId: subscription.id,
    email,
    plan: 'pro',
    scanners: ENTITLED_SCANNERS,
    issuedAt,
    expiresAt,
    keyId: CURRENT_KEY_ID,
  });
}
