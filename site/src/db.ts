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
  last_event_created: number;
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
  // `created` of the Stripe event being applied, in seconds.
  eventCreated: number;
}

// One row per subscription (migration 0002's UNIQUE index). The jti is minted
// once, when the subscription is first granted, and kept across renewals, so a
// token already handed out stays revocable by the same id.
//
// The WHERE on the update is the out-of-order guard: Stripe does not deliver
// events in order, and an event older than the one that last touched this row
// must not undo it. A late `customer.subscription.created` must never re-grant
// a subscription whose `...deleted` was already applied.
export async function upsertLicense(db: D1Database, license: NewLicense): Promise<void> {
  await db
    .prepare(
      `INSERT INTO licenses
         (jti, customer_id, subscription_id, email, plan, scanners, status, issued_at, expires_at, key_id,
          last_event_created, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, unixepoch())
       ON CONFLICT(subscription_id) DO UPDATE SET
         email = excluded.email,
         plan = excluded.plan,
         scanners = excluded.scanners,
         status = 'active',
         expires_at = excluded.expires_at,
         revoked_at = NULL,
         revoked_reason = NULL,
         last_event_created = excluded.last_event_created,
         updated_at = unixepoch()
       WHERE excluded.last_event_created >= licenses.last_event_created`,
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
      license.eventCreated,
    )
    .run();
}

// Resolves a jti to its license row, including a jti that migration 0002 folded
// into its subscription's surviving row: a token carrying an old jti must still
// see that subscription's revocation.
export async function findByJti(db: D1Database, jti: string): Promise<LicenseRow | null> {
  const row = await db.prepare(`SELECT * FROM licenses WHERE jti = ?`).bind(jti).first<LicenseRow>();
  if (row) return row;
  const aliased = await db
    .prepare(
      `SELECT l.* FROM license_jti_aliases a
         JOIN licenses l ON l.subscription_id = a.subscription_id
        WHERE a.jti = ?`,
    )
    .bind(jti)
    .first<LicenseRow>();
  return aliased ?? null;
}

export async function findActiveBySubscription(
  db: D1Database,
  subscriptionId: string,
): Promise<LicenseRow | null> {
  const row = await db
    .prepare(`SELECT * FROM licenses WHERE subscription_id = ? AND status = 'active'`)
    .bind(subscriptionId)
    .first<LicenseRow>();
  return row ?? null;
}

// Records the key that actually signed the token being handed out, so the row
// never names a key other than the one needed to verify what the customer holds.
export async function setKeyId(db: D1Database, jti: string, keyId: string): Promise<void> {
  await db
    .prepare(`UPDATE licenses SET key_id = ?, updated_at = unixepoch() WHERE jti = ? AND key_id <> ?`)
    .bind(keyId, jti, keyId)
    .run();
}

// Same out-of-order guard as the upsert: a stale revoke must not undo a newer
// grant. `revoked_at` keeps the first revocation time when one is repeated.
export async function revokeBySubscription(
  db: D1Database,
  subscriptionId: string,
  reason: string,
  eventCreated: number,
): Promise<void> {
  await db
    .prepare(
      `UPDATE licenses
       SET status = 'revoked',
           revoked_at = COALESCE(revoked_at, unixepoch()),
           revoked_reason = ?,
           last_event_created = ?,
           updated_at = unixepoch()
       WHERE subscription_id = ? AND last_event_created <= ?`,
    )
    .bind(reason, eventCreated, subscriptionId, eventCreated)
    .run();
}

// The `created` time of the newest event applied to this subscription, or null
// when there is no row for it yet.
export async function lastEventCreated(db: D1Database, subscriptionId: string): Promise<number | null> {
  const row = await db
    .prepare(`SELECT last_event_created FROM licenses WHERE subscription_id = ?`)
    .bind(subscriptionId)
    .first<{ last_event_created: number }>();
  return row ? row.last_event_created : null;
}
