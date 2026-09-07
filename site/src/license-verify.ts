import type { Env } from './types.js';
import { findByJti } from './db.js';

// POST /license/verify — body: { jti }. The client already trusts its own
// local Ed25519 signature+expiry check; this endpoint's only job is
// answering "has this been revoked since it was issued." Deliberately takes
// just the jti, not the full token — there is nothing here that needs to
// re-verify a signature the client already checked.
export async function handleLicenseVerify(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  let jti: unknown;
  try {
    const body = await request.json();
    jti = (body as Record<string, unknown>)?.jti;
  } catch {
    return Response.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  if (typeof jti !== 'string' || jti.length === 0) {
    return Response.json({ error: 'jti is required' }, { status: 400 });
  }

  const row = await findByJti(env.DB, jti);
  // A jti this server has never seen is not treated as revoked — the client
  // already trusts its own offline signature check, and an unknown jti most
  // likely means the row hasn't propagated yet or this is a non-production
  // token, not that the license was actively revoked.
  const revoked = row ? row.status === 'revoked' : false;

  return Response.json({ revoked });
}
