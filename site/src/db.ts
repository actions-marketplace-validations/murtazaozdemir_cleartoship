// All access goes through D1's parameter binding — never string
// interpolation into SQL — matching the rule cleartoship's own scanner
// enforces on scanned repos (CTS002/CTS043 and friends).

export interface LicenseRow {
  jti: string;
  customer_id: string;
  subscription_id: string;
  email: string;
  plan: string;
  scanners: string; // JSON-encoded string[]
  status: 'active' | 'revoked';
  issued_at: number;
  expires_at: number;
  key_id: string;
  revoked_at: number | null;
  revoked_reason: string | null;
  created_at: number;
  updated_at: number;
}

export interface NewLicense {
  jti: string;
  customerId: string;
  subscriptionId: string;
  email: string;
  plan: string;
  scanners: string[];
  issuedAt: number;
  expiresAt: number;
  keyId: string;
}

export async function upsertLicense(db: D1Database, license: NewLicense): Promise<void> {
  await db
    .prepare(
      `INSERT INTO licenses
         (jti, customer_id, subscription_id, email, plan, scanners, status, issued_at, expires_at, key_id, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, unixepoch())
       ON CONFLICT(jti) DO UPDATE SET
         email = excluded.email,
         plan = excluded.plan,
         scanners = excluded.scanners,
         status = 'active',
         expires_at = excluded.expires_at,
         revoked_at = NULL,
         revoked_reason = NULL,
         updated_at = unixepoch()`,
    )
    .bind(
      license.jti,
      license.customerId,
      license.subscriptionId,
      license.email,
      license.plan,
      JSON.stringify(license.scanners),
      license.issuedAt,
      license.expiresAt,
      license.keyId,
    )
    .run();
}

export async function findByJti(db: D1Database, jti: string): Promise<LicenseRow | null> {
  const row = await db.prepare(`SELECT * FROM licenses WHERE jti = ?`).bind(jti).first<LicenseRow>();
  return row ?? null;
}

export async function findActiveByCustomer(db: D1Database, customerId: string): Promise<LicenseRow | null> {
  const row = await db
    .prepare(
      `SELECT * FROM licenses WHERE customer_id = ? AND status = 'active' ORDER BY issued_at DESC LIMIT 1`,
    )
    .bind(customerId)
    .first<LicenseRow>();
  return row ?? null;
}

export async function revokeBySubscription(
  db: D1Database,
  subscriptionId: string,
  reason: string,
): Promise<void> {
  await db
    .prepare(
      `UPDATE licenses
       SET status = 'revoked', revoked_at = unixepoch(), revoked_reason = ?, updated_at = unixepoch()
       WHERE subscription_id = ? AND status = 'active'`,
    )
    .bind(reason, subscriptionId)
    .run();
}
