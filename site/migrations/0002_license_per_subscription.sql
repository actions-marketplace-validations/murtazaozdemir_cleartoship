-- One license row per Stripe subscription, and a record of which webhook event
-- last changed it.
--
-- Why. 0001 keyed rows on `jti` alone, and the webhook minted a fresh random
-- jti on every `customer.subscription.*` event, so the ON CONFLICT(jti) upsert
-- never matched: each renewal or update inserted another row for the same
-- subscription. Worse, events are delivered out of order, so a late
-- `customer.subscription.created` arriving after `...deleted` inserted a fresh
-- ACTIVE row next to the revoked one — a cancelled customer was re-granted.
-- The Worker now upserts ON CONFLICT(subscription_id), re-reads the
-- subscription from Stripe before acting, and ignores events older than
-- `last_event_created`.
--
-- Dedupe-safe. A UNIQUE index cannot be created while duplicates exist, so the
-- older rows for each subscription are removed first — but their jtis may be
-- inside tokens already handed to customers, and /license/verify answers
-- "revoked?" by jti. Deleting them outright would turn those tokens into
-- "unknown jti", which verify treats as NOT revoked, so a cancellation would no
-- longer reach them. Each removed jti is therefore kept in `license_jti_aliases`
-- pointing at its subscription, and verify resolves an alias to the surviving
-- row's status. Nothing that could be revoked before this migration becomes
-- unrevocable after it.
--
-- The survivor per subscription is the most recently issued row (ties broken
-- by rowid). If any row for that subscription was revoked, the survivor is
-- revoked too: the old code cannot tell a real reactivation (unpaid -> paid)
-- from the out-of-order re-grant described above, and the two mistakes are not
-- symmetric. Wrongly revoking an active subscription is undone by its next
-- webhook event, which re-reads Stripe and re-grants; wrongly keeping a
-- cancelled one active would never be undone.

ALTER TABLE licenses ADD COLUMN last_event_created INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS license_jti_aliases (
  jti             TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

-- "Survivor" below = no other row for the same subscription is newer.

UPDATE licenses
   SET status = 'revoked',
       revoked_at = COALESCE(revoked_at, unixepoch()),
       revoked_reason = COALESCE(revoked_reason, 'migration 0002: an older row for this subscription was revoked'),
       updated_at = unixepoch()
 WHERE status = 'active'
   AND subscription_id IN (SELECT subscription_id FROM licenses WHERE status = 'revoked')
   AND NOT EXISTS (
         SELECT 1 FROM licenses newer
          WHERE newer.subscription_id = licenses.subscription_id
            AND (newer.issued_at > licenses.issued_at
                 OR (newer.issued_at = licenses.issued_at AND newer.rowid > licenses.rowid)));

INSERT OR IGNORE INTO license_jti_aliases (jti, subscription_id)
  SELECT jti, subscription_id FROM licenses
   WHERE EXISTS (
         SELECT 1 FROM licenses newer
          WHERE newer.subscription_id = licenses.subscription_id
            AND (newer.issued_at > licenses.issued_at
                 OR (newer.issued_at = licenses.issued_at AND newer.rowid > licenses.rowid)));

DELETE FROM licenses
 WHERE EXISTS (
         SELECT 1 FROM licenses newer
          WHERE newer.subscription_id = licenses.subscription_id
            AND (newer.issued_at > licenses.issued_at
                 OR (newer.issued_at = licenses.issued_at AND newer.rowid > licenses.rowid)));

DROP INDEX IF EXISTS idx_licenses_subscription;
CREATE UNIQUE INDEX idx_licenses_subscription ON licenses(subscription_id);
