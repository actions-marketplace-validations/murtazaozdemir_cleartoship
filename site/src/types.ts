// Hand-written rather than `wrangler types` — generating that requires a
// live Cloudflare/D1 binding (`database_id` is still a placeholder in
// wrangler.jsonc until `wrangler d1 create` has been run for real), so there
// is nothing yet for the generator to introspect. Regenerate this with
// `wrangler types` once the D1 database exists and swap this file out.
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
