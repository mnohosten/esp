-- Migration: 002_reporting_schema.sql
-- Description: Add DMARC RUA and TLS-RPT reporting tables
-- Created: 2024-12-24

-- ============================================================================
-- DMARC AGGREGATE REPORTING (RFC 7489)
-- ============================================================================

-- DMARC Aggregate Reports - Received from external senders
CREATE TABLE IF NOT EXISTS dmarc_reports_received (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Report metadata (from <report_metadata>)
    org_name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    extra_contact_info TEXT,
    report_id VARCHAR(255) NOT NULL,
    date_begin TIMESTAMP NOT NULL,
    date_end TIMESTAMP NOT NULL,

    -- Policy published (from <policy_published>)
    domain VARCHAR(255) NOT NULL,
    adkim VARCHAR(10),  -- 'r' (relaxed) or 's' (strict)
    aspf VARCHAR(10),   -- 'r' (relaxed) or 's' (strict)
    policy VARCHAR(20), -- none, quarantine, reject
    subdomain_policy VARCHAR(20),
    pct INTEGER,

    -- Raw data storage
    raw_xml TEXT,

    -- Processing metadata
    received_at TIMESTAMP DEFAULT NOW(),
    source_ip INET,
    source_email VARCHAR(255),

    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(org_name, report_id)
);

CREATE INDEX IF NOT EXISTS dmarc_reports_received_domain_idx ON dmarc_reports_received(domain);
CREATE INDEX IF NOT EXISTS dmarc_reports_received_date_idx ON dmarc_reports_received(date_begin, date_end);
CREATE INDEX IF NOT EXISTS dmarc_reports_received_org_idx ON dmarc_reports_received(org_name);
CREATE INDEX IF NOT EXISTS dmarc_reports_received_created_idx ON dmarc_reports_received(created_at);

-- DMARC Report Records (individual authentication records from received reports)
CREATE TABLE IF NOT EXISTS dmarc_report_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_id UUID NOT NULL REFERENCES dmarc_reports_received(id) ON DELETE CASCADE,

    -- Row data (from <row>)
    source_ip INET NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,

    -- Policy evaluated
    disposition VARCHAR(20), -- none, quarantine, reject
    dkim_result VARCHAR(20), -- pass, fail
    spf_result VARCHAR(20),  -- pass, fail

    -- Identifiers (from <identifiers>)
    envelope_to VARCHAR(255),
    envelope_from VARCHAR(255),
    header_from VARCHAR(255) NOT NULL,

    -- Auth results stored as JSONB for flexibility
    -- Format: {dkim: [{domain, selector, result}], spf: [{domain, scope, result}]}
    auth_results JSONB,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS dmarc_report_records_report_idx ON dmarc_report_records(report_id);
CREATE INDEX IF NOT EXISTS dmarc_report_records_source_ip_idx ON dmarc_report_records(source_ip);
CREATE INDEX IF NOT EXISTS dmarc_report_records_header_from_idx ON dmarc_report_records(header_from);

-- DMARC Authentication Results (for generating outbound reports)
-- Stores per-message authentication results that we've performed
CREATE TABLE IF NOT EXISTS dmarc_auth_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Message identification
    message_id VARCHAR(998),

    -- Domains involved
    header_from_domain VARCHAR(255) NOT NULL,
    envelope_from_domain VARCHAR(255),
    envelope_to_domain VARCHAR(255),

    -- Source information
    source_ip INET NOT NULL,

    -- SPF results
    spf_result VARCHAR(20) NOT NULL, -- none, neutral, pass, fail, softfail, temperror, permerror
    spf_domain VARCHAR(255),
    spf_aligned BOOLEAN DEFAULT FALSE,

    -- DKIM results (can have multiple signatures, stored as JSONB)
    -- Format: [{domain, selector, result, aligned}]
    dkim_results JSONB,
    dkim_aligned BOOLEAN DEFAULT FALSE,

    -- DMARC result
    dmarc_result VARCHAR(20) NOT NULL, -- none, pass, fail
    dmarc_policy VARCHAR(20), -- none, quarantine, reject
    disposition VARCHAR(20), -- none, quarantine, reject (actual action taken)

    -- Timestamps
    received_at TIMESTAMP DEFAULT NOW(),

    -- For aggregation (partition key)
    report_date DATE DEFAULT CURRENT_DATE
);

CREATE INDEX IF NOT EXISTS dmarc_auth_results_domain_idx ON dmarc_auth_results(header_from_domain);
CREATE INDEX IF NOT EXISTS dmarc_auth_results_date_idx ON dmarc_auth_results(report_date);
CREATE INDEX IF NOT EXISTS dmarc_auth_results_source_ip_idx ON dmarc_auth_results(source_ip);

-- DMARC Outbound Report Queue
-- Tracks reports we've generated and their send status
CREATE TABLE IF NOT EXISTS dmarc_reports_sent (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Target domain and rua addresses
    domain VARCHAR(255) NOT NULL,
    rua_addresses TEXT[] NOT NULL,

    -- Report period
    date_begin TIMESTAMP NOT NULL,
    date_end TIMESTAMP NOT NULL,

    -- Report content
    report_id VARCHAR(255) NOT NULL,
    record_count INTEGER NOT NULL,
    report_xml TEXT,
    compressed_report BYTEA, -- gzip compressed

    -- Status tracking
    status VARCHAR(20) DEFAULT 'pending', -- pending, sent, failed
    last_error TEXT,
    attempts INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    sent_at TIMESTAMP,

    UNIQUE(domain, report_id)
);

CREATE INDEX IF NOT EXISTS dmarc_reports_sent_domain_idx ON dmarc_reports_sent(domain);
CREATE INDEX IF NOT EXISTS dmarc_reports_sent_status_idx ON dmarc_reports_sent(status);
CREATE INDEX IF NOT EXISTS dmarc_reports_sent_date_idx ON dmarc_reports_sent(date_begin);

-- ============================================================================
-- TLS-RPT (RFC 8460) AND MTA-STS
-- ============================================================================

-- MTA-STS Policy Cache
-- Stores cached MTA-STS policies fetched from remote domains
CREATE TABLE IF NOT EXISTS mta_sts_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain VARCHAR(255) NOT NULL UNIQUE,

    -- Policy details
    policy_mode VARCHAR(20) NOT NULL, -- 'enforce', 'testing', 'none'
    mx_patterns TEXT[] NOT NULL,
    max_age INTEGER NOT NULL, -- seconds
    policy_id VARCHAR(255),

    -- Timestamps
    fetched_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_validated TIMESTAMP DEFAULT NOW(),

    -- Error tracking
    validation_errors TEXT,
    fetch_failures INTEGER DEFAULT 0,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS mta_sts_policies_domain_idx ON mta_sts_policies(domain);
CREATE INDEX IF NOT EXISTS mta_sts_policies_expires_idx ON mta_sts_policies(expires_at);

-- TLS Connection Results (per-delivery tracking)
-- Records TLS negotiation outcome for each outbound delivery attempt
CREATE TABLE IF NOT EXISTS tls_connection_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    queue_id UUID, -- References queue(id), but allows NULL for cleanup
    recipient_domain VARCHAR(255) NOT NULL,
    mx_host VARCHAR(255) NOT NULL,
    mx_ip INET,

    -- Connection outcome (RFC 8460 result types)
    result_type VARCHAR(50) NOT NULL,
    -- Valid values: 'success', 'starttls-not-supported', 'certificate-host-mismatch',
    -- 'certificate-expired', 'certificate-not-trusted', 'validation-failure',
    -- 'tlsa-invalid', 'dnssec-invalid', 'sts-policy-fetch-error',
    -- 'sts-policy-invalid', 'sts-webpki-invalid'
    success BOOLEAN NOT NULL,

    -- Policy information
    policy_type VARCHAR(20) NOT NULL, -- 'sts', 'tlsa', 'no-policy-found'
    policy_domain VARCHAR(255),
    policy_string TEXT[], -- MX patterns for STS

    -- Failure details
    failure_reason_code VARCHAR(100),
    failure_reason_text TEXT,
    sending_mta_ip INET,
    receiving_ip INET,
    receiving_mx_hostname VARCHAR(255),
    receiving_mx_helo VARCHAR(255),

    -- TLS details (when successful)
    tls_version VARCHAR(20),
    cipher_suite VARCHAR(100),
    cert_issuer VARCHAR(500),
    cert_subject VARCHAR(500),
    cert_expiry TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS tls_results_domain_idx ON tls_connection_results(recipient_domain);
CREATE INDEX IF NOT EXISTS tls_results_created_idx ON tls_connection_results(created_at);
CREATE INDEX IF NOT EXISTS tls_results_result_type_idx ON tls_connection_results(result_type);
CREATE INDEX IF NOT EXISTS tls_results_success_idx ON tls_connection_results(success);

-- TLS Daily Aggregates (for efficient report generation)
CREATE TABLE IF NOT EXISTS tls_daily_aggregates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_date DATE NOT NULL,
    recipient_domain VARCHAR(255) NOT NULL,
    policy_type VARCHAR(20) NOT NULL,
    policy_domain VARCHAR(255),

    -- Counts
    total_successful INTEGER DEFAULT 0,
    total_failed INTEGER DEFAULT 0,

    -- Failure breakdown (JSONB for flexibility)
    -- Format: {"starttls-not-supported": 5, "certificate-expired": 2, ...}
    failure_details JSONB DEFAULT '{}',

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(report_date, recipient_domain, policy_type)
);

CREATE INDEX IF NOT EXISTS tls_aggregates_date_idx ON tls_daily_aggregates(report_date);
CREATE INDEX IF NOT EXISTS tls_aggregates_domain_idx ON tls_daily_aggregates(recipient_domain);

-- TLS-RPT Reports Received (inbound from other senders about our domain)
CREATE TABLE IF NOT EXISTS tlsrpt_reports_received (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_name VARCHAR(255),
    report_id VARCHAR(255) NOT NULL,
    contact_info VARCHAR(500),

    -- Date range covered by report
    date_range_start TIMESTAMP NOT NULL,
    date_range_end TIMESTAMP NOT NULL,

    -- Our domain being reported on
    policy_domain VARCHAR(255) NOT NULL,

    -- Raw report JSON (full RFC 8460 structure)
    raw_report JSONB NOT NULL,

    -- Parsed summary for quick queries
    total_successful INTEGER DEFAULT 0,
    total_failed INTEGER DEFAULT 0,

    -- Timestamps
    received_at TIMESTAMP DEFAULT NOW(),
    processed_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),

    UNIQUE(organization_name, report_id)
);

CREATE INDEX IF NOT EXISTS tlsrpt_received_domain_idx ON tlsrpt_reports_received(policy_domain);
CREATE INDEX IF NOT EXISTS tlsrpt_received_date_idx ON tlsrpt_reports_received(date_range_start, date_range_end);
CREATE INDEX IF NOT EXISTS tlsrpt_received_org_idx ON tlsrpt_reports_received(organization_name);

-- TLS-RPT Reports Sent (outbound to other domains)
CREATE TABLE IF NOT EXISTS tlsrpt_reports_sent (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_id VARCHAR(255) NOT NULL UNIQUE,

    -- Date range covered
    date_range_start TIMESTAMP NOT NULL,
    date_range_end TIMESTAMP NOT NULL,

    -- Target domain
    policy_domain VARCHAR(255) NOT NULL,
    rua_uri VARCHAR(500) NOT NULL, -- mailto: or https: URI

    -- Report content (RFC 8460 JSON structure)
    policies JSONB NOT NULL, -- Array of policy results
    report_json JSONB NOT NULL, -- Full report

    -- Delivery status
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'sent', 'failed'
    sent_at TIMESTAMP,
    error TEXT,
    retry_count INTEGER DEFAULT 0,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS tlsrpt_sent_domain_idx ON tlsrpt_reports_sent(policy_domain);
CREATE INDEX IF NOT EXISTS tlsrpt_sent_status_idx ON tlsrpt_reports_sent(status);
CREATE INDEX IF NOT EXISTS tlsrpt_sent_date_idx ON tlsrpt_reports_sent(date_range_start);

-- ============================================================================
-- DOMAIN CONFIGURATION EXTENSIONS
-- ============================================================================

-- Add reporting columns to domains table
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dmarc_rua_enabled BOOLEAN DEFAULT TRUE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dmarc_rua_addresses TEXT[];
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dmarc_policy VARCHAR(20) DEFAULT 'none';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dmarc_subdomain_policy VARCHAR(20);
ALTER TABLE domains ADD COLUMN IF NOT EXISTS dmarc_pct INTEGER DEFAULT 100;

ALTER TABLE domains ADD COLUMN IF NOT EXISTS tlsrpt_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS tlsrpt_rua_addresses TEXT[];

ALTER TABLE domains ADD COLUMN IF NOT EXISTS sts_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS sts_mode VARCHAR(20) DEFAULT 'testing';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS sts_max_age INTEGER DEFAULT 86400;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS sts_mx_patterns TEXT[];
ALTER TABLE domains ADD COLUMN IF NOT EXISTS sts_policy_id VARCHAR(255);

-- ============================================================================
-- UPDATE TRIGGERS
-- ============================================================================

CREATE TRIGGER mta_sts_policies_updated_at
    BEFORE UPDATE ON mta_sts_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER tls_daily_aggregates_updated_at
    BEFORE UPDATE ON tls_daily_aggregates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
