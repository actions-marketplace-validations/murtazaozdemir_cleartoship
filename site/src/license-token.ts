import type { Env, LicensePayload } from './types.js';

// `CTSL1.<base64url(payload-json)>.<base64url(signature)>`. The `CTSL1` tag
// names format+algorithm version so a future key-algorithm swap has
// somewhere to be checked against, rather than every consumer assuming
// Ed25519 forever. The signature covers the exact bytes of the base64url
// payload segment — never a re-serialized copy of the JSON — so a signer and
// verifier that disagree about key order or whitespace can never disagree
// about what was actually signed.
const TOKEN_TAG = 'CTSL1';

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importSigningKey(jwkJson: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkJson) as JsonWebKey;
  return crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
}

export async function signLicenseToken(payload: LicensePayload, env: Env): Promise<string> {
  if (!env.LICENSE_SIGNING_PRIVATE_KEY_JWK) {
    // Fail loudly — never mint an unsigned or unsignable token.
    throw new Error('LICENSE_SIGNING_PRIVATE_KEY_JWK is not configured');
  }
  const key = await importSigningKey(env.LICENSE_SIGNING_PRIVATE_KEY_JWK);
  const payloadB64 = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(payloadB64));
  const sigB64 = base64url(new Uint8Array(signature));
  return `${TOKEN_TAG}.${payloadB64}.${sigB64}`;
}
