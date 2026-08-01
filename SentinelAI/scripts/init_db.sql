-- ============================================================
-- SentinelAI — PostgreSQL Schema
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Users ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            VARCHAR(64)  PRIMARY KEY,
    username      VARCHAR(64)  UNIQUE NOT NULL,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT         NOT NULL,
    role          VARCHAR(32)  NOT NULL DEFAULT 'analyst',
    full_name     VARCHAR(128) NOT NULL,
    mfa_secret    VARCHAR(64),
    mfa_enabled   BOOLEAN      NOT NULL DEFAULT false,
    is_active     BOOLEAN      NOT NULL DEFAULT true,
    last_login    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─── API Keys ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id          VARCHAR(32)  PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    key_hash    TEXT         NOT NULL,
    permissions TEXT         NOT NULL,
    created_by  VARCHAR(64)  REFERENCES users(id),
    is_active   BOOLEAN      NOT NULL DEFAULT true,
    last_used   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─── Incidents ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    title            VARCHAR(256) NOT NULL,
    description      TEXT,
    severity         VARCHAR(16)  NOT NULL,
    status           VARCHAR(32)  NOT NULL DEFAULT 'open',
    assigned_to      VARCHAR(64)  REFERENCES users(id),
    alert_ids        TEXT[],
    source_ips       TEXT[],
    affected_hosts   TEXT[],
    mitre_techniques TEXT[],
    timeline         JSONB        DEFAULT '[]',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ,
    created_by       VARCHAR(64)  REFERENCES users(id)
);

-- ─── Audit Logs ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     VARCHAR(64) REFERENCES users(id),
    action      VARCHAR(128) NOT NULL,
    resource    VARCHAR(128),
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    details     JSONB,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─── Detection Rules (persistent) ────────────────────────────
CREATE TABLE IF NOT EXISTS detection_rules (
    id              VARCHAR(32)  PRIMARY KEY,
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    rule_type       VARCHAR(32)  NOT NULL,
    severity        VARCHAR(16)  NOT NULL,
    detection_type  VARCHAR(64)  NOT NULL,
    rule_content    TEXT         NOT NULL,
    is_active       BOOLEAN      NOT NULL DEFAULT true,
    hit_count       INTEGER      NOT NULL DEFAULT 0,
    false_positive  INTEGER      NOT NULL DEFAULT 0,
    created_by      VARCHAR(64)  REFERENCES users(id),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─── Threat Intel Cache ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ioc_value   VARCHAR(512) PRIMARY KEY,
    ioc_type    VARCHAR(32)  NOT NULL,
    threat_score INTEGER     NOT NULL DEFAULT 0,
    verdict     VARCHAR(16)  NOT NULL,
    vt_data     JSONB,
    abuse_data  JSONB,
    otx_data    JSONB,
    queried_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ  NOT NULL DEFAULT (NOW() + INTERVAL '24 hours')
);

-- ─── SOAR Execution Logs ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS soar_executions (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_name   VARCHAR(64) NOT NULL,
    alert_id        VARCHAR(64),
    triggered_by    VARCHAR(64),
    status          VARCHAR(32) NOT NULL,
    steps_executed  JSONB       NOT NULL DEFAULT '[]',
    total_time_ms   NUMERIC,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Reports ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_type   VARCHAR(32) NOT NULL,
    title         VARCHAR(256) NOT NULL,
    period_hours  INTEGER     NOT NULL,
    summary_data  JSONB,
    created_by    VARCHAR(64) REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Indexes ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_incidents_severity    ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status      ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created     ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user            ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created         ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_cache_type     ON threat_intel_cache(ioc_type);
CREATE INDEX IF NOT EXISTS idx_threat_cache_expires  ON threat_intel_cache(expires_at);

-- ─── Seed default admin ───────────────────────────────────────
-- Default admin: admin / SentinelAI@2024 (CHANGE IMMEDIATELY)
INSERT INTO users (id, username, email, password_hash, role, full_name, mfa_enabled)
VALUES (
    'admin-001',
    'admin',
    'admin@sentinelai.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKOi0V0QV6wHpzW',
    'admin',
    'SentinelAI Administrator',
    false
) ON CONFLICT DO NOTHING;

COMMENT ON TABLE users IS 'Platform user accounts with RBAC roles';
COMMENT ON TABLE incidents IS 'Correlated security incidents with full lifecycle tracking';
COMMENT ON TABLE audit_logs IS 'Immutable audit trail of all user actions';
