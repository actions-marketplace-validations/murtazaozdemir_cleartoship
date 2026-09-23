import Stripe from 'stripe';
import type { Env, LicensePayload } from './types.js';
import { CURRENT_KEY_ID } from './types.js';
import { billingUnavailable, createStripeClient } from './stripe-client.js';
import { signLicenseToken } from './license-token.js';
import { upsertLicense, revokeBySubscription, lastEventCreated } from './db.js';

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
  const unavailable = billingUnavailable(env, [
    'STRIPE_SECRET_KEY',
    'STRIPE_WEBHOOK_SECRET',
    'LICENSE_SIGNING_PRIVATE_KEY_JWK',
  ]);
  if (unavailable) return unavailable;

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
    const subscription = event.data.object as Stripe.Subscription;
    await handleSubscriptionEvent(subscription.id, event.created, stripe, env);
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

function isMissingResource(err: unknown): boolean {
  const e = err as { code?: string; statusCode?: number };
  return e?.code === 'resource_missing' || e?.statusCode === 404;
}

// Stripe delivers events at least once and in no guaranteed order, so the
// event's payload is a snapshot that may already be stale when it arrives: a
// `customer.subscription.created` retried after `...deleted` still says
// "active". Acting on it used to re-grant a cancelled customer. So:
//   1. an event older than the newest one already applied to this
//      subscription is ignored outright;
//   2. otherwise the subscription is re-read from Stripe, and its CURRENT
//      status decides — the event only says "something changed";
//   3. the write itself repeats the age check (db.ts), which closes the race
//      between two deliveries handled concurrently.
async function handleSubscriptionEvent(
  subscriptionId: string,
  eventCreated: number,
  stripe: Stripe,
  env: Env,
): Promise<void> {
  const last = await lastEventCreated(env.DB, subscriptionId);
  if (last !== null && eventCreated < last) {
    console.log(`ignoring stale event for ${subscriptionId}: created ${eventCreated} < ${last}`);
    return;
  }

  let subscription: Stripe.Subscription;
  try {
    subscription = await stripe.subscriptions.retrieve(subscriptionId);
  } catch (err) {
    // Stripe keeps cancelled subscriptions retrievable, so "no such
    // subscription" means it was deleted outright: nothing left to entitle.
    if (isMissingResource(err)) {
      await revokeBySubscription(env.DB, subscriptionId, 'stripe: subscription not found', eventCreated);
      return;
    }
    // Anything else is transient. Throwing answers 500, and Stripe retries.
    throw err;
  }

  const customerId =
    typeof subscription.customer === 'string' ? subscription.customer : subscription.customer.id;

  if (REVOKED_STATUSES.has(subscription.status)) {
    await revokeBySubscription(env.DB, subscription.id, `stripe status: ${subscription.status}`, eventCreated);
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
  // Used only if this subscription has no row yet; an existing row keeps its
  // jti (db.ts), so tokens already issued stay revocable by the same id.
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
  // and immediately if LICENSE_SIGNING_PRIVATE_KEY_JWK is ever unusable,
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
    eventCreated,
  });
}
