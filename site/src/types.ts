// Hand-written. The D1 database now exists (its real id is in wrangler.jsonc),
// so `npm run types` could generate this instead; until someone switches over,
// keep it in step with the bindings and secrets listed in wrangler.jsonc.
//
// The three secrets are typed `string`, but billing is dormant: until each has
// been set with `wrangler secret put`, it is undefined at run time. That is why
// every billing route checks the ones it needs first (`billingUnavailable` in
// stripe-client.ts) and answers 503 rather than crashing with a 500.
export interface Env {
  DB: D1Database;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  // A JSON-serialized Ed25519 private JWK, e.g. {"kty":"OKP","crv":"Ed25519","x":"...","d":"..."}
  LICENSE_SIGNING_PRIVATE_KEY_JWK: string;
}

// Identifies which signing key produced a token, carried in both the token
// payload's `kid` and the D1 row's `key_id` — bump this if the signing key
// is ever rotated, so old tokens can still be traced to the key that must
// verify them.
export const CURRENT_KEY_ID = '2026-v1';

export interface LicensePayload {
  v: 1;
  sub: string;
  email: string;
  plan: 'pro';
  scanners: string[];
  iat: number;
  exp: number;
  kid: string;
  jti: string;
}
