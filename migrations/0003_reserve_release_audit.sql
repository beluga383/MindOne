ALTER TABLE reserve_ledger
    ADD COLUMN IF NOT EXISTS audit_reference TEXT;

ALTER TABLE reserve_ledger
    DROP CONSTRAINT IF EXISTS reserve_release_requires_reference;

ALTER TABLE reserve_ledger
    ADD CONSTRAINT reserve_release_requires_reference CHECK (
        delta_micro >= 0
        OR (audit_reference IS NOT NULL AND length(btrim(audit_reference)) > 0)
    );
