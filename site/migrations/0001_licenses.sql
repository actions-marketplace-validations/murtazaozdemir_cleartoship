CREATE TABLE IF NOT EXISTS licenses (
  jti             TEXT PRIMARY KEY,
  customer_id     TEXT NOT NULL,
  subscription_id TEXT NOT NULL,
  email           TEXT NOT NULL,
  plan            TEXT NOT NULL,
  scanners        TEXT NOT NULL,             -- JSON array, e.g. '["rls","server-actions","llm"]'
  status          TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'revoked'
  issued_at       INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  key_id          TEXT NOT NULL,             -- 'kid' that signed this token
  revoked_at      INTEGER,
  revoked_reason  TEXT,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_licenses_customer ON licenses(customer_id);
CREATE INDEX idx_licenses_subscription ON licenses(subscription_id);
