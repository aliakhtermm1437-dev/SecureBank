-- Auth service schema
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email varchar(254) NOT NULL UNIQUE,
    phone varchar(20) UNIQUE,
    password_hash varchar(255) NOT NULL,
    must_rotate_pw boolean NOT NULL DEFAULT true,
    is_active boolean NOT NULL DEFAULT true,
    is_admin boolean NOT NULL DEFAULT false,
    mfa_enabled boolean NOT NULL DEFAULT false,
    mfa_secret_enc bytea,
    failed_logins int NOT NULL DEFAULT 0,
    lock_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (lower(email));

CREATE TABLE IF NOT EXISTS audit_events (
    id bigserial PRIMARY KEY,
    ts timestamptz NOT NULL DEFAULT now(),
    user_id uuid,
    event varchar(64) NOT NULL,
    outcome varchar(16) NOT NULL,
    ip varchar(45),
    ua varchar(255),
    attrs jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS audit_events_event_ts_idx ON audit_events (event, ts DESC);
