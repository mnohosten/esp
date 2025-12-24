-- ESP Initial Database Schema
-- Version: 001

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Domains table
CREATE TABLE domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    -- DKIM configuration
    dkim_selector VARCHAR(255),
    dkim_private_key TEXT,

    -- Limits
    max_mailbox_size BIGINT DEFAULT 1073741824, -- 1GB
    max_message_size BIGINT DEFAULT 26214400,   -- 25MB

    -- Settings (JSONB for flexibility)
    settings JSONB DEFAULT '{}'
);

CREATE INDEX domains_name_idx ON domains(name);
CREATE INDEX domains_enabled_idx ON domains(enabled);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    is_admin BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,

    -- Quota
    quota_bytes BIGINT DEFAULT 1073741824, -- 1GB
    used_bytes BIGINT DEFAULT 0,

    -- Settings
    settings JSONB DEFAULT '{}',

    UNIQUE(domain_id, username)
);

CREATE INDEX users_email_idx ON users(email);
CREATE INDEX users_domain_id_idx ON users(domain_id);
CREATE INDEX users_enabled_idx ON users(enabled);

-- Mailboxes (IMAP folders)
CREATE TABLE mailboxes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uidnext INTEGER DEFAULT 1,
    subscribed BOOLEAN DEFAULT true,
    special_use VARCHAR(50), -- \Inbox, \Sent, \Drafts, \Trash, \Junk, \Archive
    message_count INTEGER DEFAULT 0,
    unread_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(user_id, name)
);

CREATE INDEX mailboxes_user_id_idx ON mailboxes(user_id);
CREATE INDEX mailboxes_special_use_idx ON mailboxes(special_use);

-- Messages metadata
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mailbox_id UUID NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid INTEGER NOT NULL,

    -- Envelope data
    message_id VARCHAR(998),
    in_reply_to VARCHAR(998),
    subject TEXT,
    from_address VARCHAR(255),
    to_addresses TEXT[],
    cc_addresses TEXT[],
    date TIMESTAMP,

    -- Storage
    size INTEGER NOT NULL,
    storage_path VARCHAR(500) NOT NULL,

    -- IMAP flags
    flags TEXT[] DEFAULT '{}',
    internal_date TIMESTAMP DEFAULT NOW(),

    -- Metadata
    headers_json JSONB,

    -- Search support
    body_text TEXT,

    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(mailbox_id, uid)
);

-- Full-text search index
CREATE INDEX messages_fts_idx ON messages
    USING GIN (to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(body_text, '')));

CREATE INDEX messages_mailbox_idx ON messages(mailbox_id);
CREATE INDEX messages_date_idx ON messages(date);
CREATE INDEX messages_from_idx ON messages(from_address);
CREATE INDEX messages_message_id_idx ON messages(message_id);
CREATE INDEX messages_flags_idx ON messages USING GIN (flags);

-- Aliases
CREATE TABLE aliases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    source VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(domain_id, source)
);

CREATE INDEX aliases_domain_id_idx ON aliases(domain_id);
CREATE INDEX aliases_source_idx ON aliases(source);

-- Outbound Queue
CREATE TABLE queue (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id VARCHAR(998),
    sender VARCHAR(255) NOT NULL,
    recipient VARCHAR(255) NOT NULL,

    -- Message storage
    message_path VARCHAR(500),
    size INTEGER,

    -- State
    status VARCHAR(20) DEFAULT 'pending',
    priority INTEGER DEFAULT 0,
    attempts INTEGER DEFAULT 0,
    last_attempt TIMESTAMP,
    next_attempt TIMESTAMP DEFAULT NOW(),
    last_error TEXT,

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

CREATE INDEX queue_next_attempt_idx ON queue(status, next_attempt);
CREATE INDEX queue_sender_idx ON queue(sender);
CREATE INDEX queue_status_idx ON queue(status);

-- Webhooks
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID REFERENCES domains(id) ON DELETE CASCADE,
    name VARCHAR(255),
    url VARCHAR(500) NOT NULL,
    events TEXT[] NOT NULL,
    secret VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_triggered TIMESTAMP,
    failure_count INTEGER DEFAULT 0
);

CREATE INDEX webhooks_domain_id_idx ON webhooks(domain_id);
CREATE INDEX webhooks_enabled_idx ON webhooks(enabled);

-- Filter Rules
CREATE TABLE filter_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255),
    priority INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,

    -- Conditions (JSONB for flexibility)
    conditions JSONB NOT NULL,

    -- Actions
    actions JSONB NOT NULL,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX filter_rules_user_id_idx ON filter_rules(user_id);
CREATE INDEX filter_rules_enabled_idx ON filter_rules(enabled);

-- Audit Log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    actor_id UUID,
    actor_ip INET,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB
);

CREATE INDEX audit_log_timestamp_idx ON audit_log(timestamp);
CREATE INDEX audit_log_event_type_idx ON audit_log(event_type);
CREATE INDEX audit_log_actor_idx ON audit_log(actor_id);

-- API tokens (for service accounts)
CREATE TABLE api_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(token_hash)
);

CREATE INDEX api_tokens_user_id_idx ON api_tokens(user_id);

-- Sessions (for tracking active logins)
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_active TIMESTAMP DEFAULT NOW(),

    UNIQUE(token_hash)
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);

-- Update triggers for updated_at columns
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER domains_updated_at
    BEFORE UPDATE ON domains
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER mailboxes_updated_at
    BEFORE UPDATE ON mailboxes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER webhooks_updated_at
    BEFORE UPDATE ON webhooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER filter_rules_updated_at
    BEFORE UPDATE ON filter_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Quota tracking view
CREATE VIEW user_quota AS
SELECT
    u.id as user_id,
    u.quota_bytes as quota_limit,
    COALESCE(SUM(m.size), 0)::BIGINT as quota_used,
    COUNT(m.id)::INTEGER as message_count
FROM users u
LEFT JOIN mailboxes mb ON mb.user_id = u.id
LEFT JOIN messages m ON m.mailbox_id = mb.id
GROUP BY u.id;

-- Active sessions view
CREATE VIEW active_sessions AS
SELECT
    s.id,
    s.user_id,
    u.email,
    s.ip_address,
    s.created_at,
    s.last_active
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.expires_at > NOW();
