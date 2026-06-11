CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL,
    iban_enc bytea NOT NULL,
    iban_hash varchar(64) NOT NULL UNIQUE,
    currency varchar(3) NOT NULL DEFAULT 'PKR',
    balance numeric(18,2) NOT NULL DEFAULT 0,
    status varchar(16) NOT NULL DEFAULT 'active',
    version int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS accounts_user_id_idx ON accounts(user_id);
