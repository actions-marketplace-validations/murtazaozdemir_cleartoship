import type { Env, LicensePayload } from './types.js';
import { createStripeClient } from './stripe-client.js';
import { findActiveByCustomer } from './db.js';
import { signLicenseToken } from './license-token.js';

// GET /license/issue?session_id=<checkout_session_id>
//
// The webhook (stripe-webhook.ts) grants the entitlement in D1 as soon as
// Stripe reports an active subscription, but it fires in the background —
// the paying customer still needs a way to actually *see* their key. This
// endpoint is the delivery path: a Checkout success-page redirect target
// that trades a session id (which only the person who just paid can have)
// for the license token.
export async function handleLicenseIssue(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', { status: 405 });
  }

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

  const customerId = typeof session.customer === 'string' ? session.customer : session.customer?.id;
  if (!customerId) {
    return Response.json({ error: 'checkout session has no customer' }, { status: 409 });
  }

  // The webhook may not have landed yet (Stripe delivers it asynchronously,
  // separately from the browser redirect) — a client hitting this
  // immediately after paying can reasonably retry a few times.
  const row = await findActiveByCustomer(env.DB, customerId);
  if (!row) {
    return Response.json(
      { error: 'license not issued yet, retry shortly' },
      { status: 202 },
    );
  }

  const payload: LicensePayload = {
    v: 1,
    sub: row.customer_id,
    email: row.email,
    plan: row.plan as 'pro',
    scanners: JSON.parse(row.scanners) as string[],
    iat: row.issued_at,
    exp: row.expires_at,
    kid: row.key_id,
    jti: row.jti,
  };

  const token = await signLicenseToken(payload, env);
  return Response.json({ token });
}
