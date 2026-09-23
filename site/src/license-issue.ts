import type { Env, LicensePayload } from './types.js';
import { CURRENT_KEY_ID } from './types.js';
import { billingUnavailable, createStripeClient } from './stripe-client.js';
import { findActiveBySubscription, setKeyId } from './db.js';
import { signLicenseToken } from './license-token.js';

// A checkout session id is a bearer credential for this endpoint: whoever holds
// it gets the key. It sits in the success-page URL, and URLs leak into browser
// history, screenshots and support tickets, so its usefulness is bounded in
// time. Three days covers a customer who closed the tab and came back; key
// recovery after that is a support request, not an old link.
const MAX_SESSION_AGE_SECONDS = 3 * 24 * 60 * 60;

// GET /license/issue?session_id=<checkout_session_id>
//
// The webhook (stripe-webhook.ts) grants the entitlement in D1 as soon as
// Stripe reports an active subscription, but it fires in the background —
// the paying customer still needs a way to actually *see* their key. This
// endpoint is the delivery path: a Checkout success-page redirect target
// that trades a recent session id (which only the person who just paid can
// have) for the license of the subscription that session created.
//
// Not rate limited here: that is a Cloudflare dashboard rule on /license/*
// (see SECURITY.md), which stops a flood before it costs a Stripe API call.
export async function handleLicenseIssue(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', { status: 405 });
  }
  const unavailable = billingUnavailable(env, ['STRIPE_SECRET_KEY', 'LICENSE_SIGNING_PRIVATE_KEY_JWK']);
  if (unavailable) return unavailable;

  const sessionId = new URL(request.url).searchParams.get('session_id');
  if (!sessionId) {
    return Response.json({ error: 'session_id is required' }, { status: 400 });
  }

  const stripe = createStripeClient(env);

  let session;
  try {
    session = await stripe.checkout.sessions.retrieve(sessionId);
  } catch {
    return Response.json({ error: 'session not found' }, { status: 404 });
  }

  if (session.payment_status !== 'paid' && session.status !== 'complete') {
    return Response.json({ error: 'checkout session is not complete' }, { status: 409 });
  }

  if (Math.floor(Date.now() / 1000) - session.created > MAX_SESSION_AGE_SECONDS) {
    return Response.json({ error: 'checkout session has expired for key delivery' }, { status: 410 });
  }

  // The license delivered is the one for the subscription THIS session
  // created — not "any active license this customer has", which let a session
  // for one purchase hand out the key of another.
  const subscriptionId =
    typeof session.subscription === 'string' ? session.subscription : session.subscription?.id;
  if (session.mode !== 'subscription' || !subscriptionId) {
    return Response.json({ error: 'checkout session has no subscription' }, { status: 409 });
  }

  // The webhook may not have landed yet (Stripe delivers it asynchronously,
  // separately from the browser redirect) — a client hitting this
  // immediately after paying can reasonably retry a few times.
  const row = await findActiveBySubscription(env.DB, subscriptionId);
  if (!row) {
    return Response.json(
      { error: 'license not issued yet, retry shortly' },
      { status: 202 },
    );
  }

  // `kid` names the key that signs THIS token, which is the current one — not
  // whatever key signed when the row was first written. After a rotation the
  // stored value would send a verifier to a key that cannot verify it.
  const payload: LicensePayload = {
    v: 1,
    sub: row.customer_id,
    email: row.email,
    plan: row.plan as 'pro',
    scanners: JSON.parse(row.scanners) as string[],
    iat: row.issued_at,
    exp: row.expires_at,
    kid: CURRENT_KEY_ID,
    jti: row.jti,
  };

  const token = await signLicenseToken(payload, env);
  await setKeyId(env.DB, row.jti, CURRENT_KEY_ID);
  return Response.json({ token });
}
