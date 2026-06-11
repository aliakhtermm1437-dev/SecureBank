CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS transactions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key varchar(64) NOT NULL,
    initiator_user_id uuid NOT NULL,
    src_account_id uuid NOT NULL,
    dst_account_id uuid NOT NULL,
    amount numeric(18,2) NOT NULL,
    currency varchar(3) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'pending',
    failure_reason varchar(64),
    memo varchar(140),
    risk_score double precision NOT NULL DEFAULT 0,
    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_tx_idemp UNIQUE (initiator_user_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS transactions_initiator_idx ON transactions(initiator_user_id);
CREATE INDEX IF NOT EXISTS transactions_status_idx ON transactions(status);
