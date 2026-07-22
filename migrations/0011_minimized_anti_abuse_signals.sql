CREATE TABLE IF NOT EXISTS abuse_network_observations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    device_hash TEXT NOT NULL CHECK (device_hash ~ '^[0-9a-f]{64}$'),
    ip_prefix_hash TEXT NOT NULL CHECK (ip_prefix_hash ~ '^[0-9a-f]{64}$'),
    asn_hash TEXT CHECK (asn_hash ~ '^[0-9a-f]{64}$'),
    network_source TEXT NOT NULL CHECK (network_source IN ('direct_peer', 'trusted_cloudflare')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS abuse_observations_device_time_idx
    ON abuse_network_observations (device_hash, observed_at DESC);
CREATE INDEX IF NOT EXISTS abuse_observations_ip_time_idx
    ON abuse_network_observations (ip_prefix_hash, observed_at DESC);
CREATE INDEX IF NOT EXISTS abuse_observations_asn_time_idx
    ON abuse_network_observations (asn_hash, observed_at DESC)
    WHERE asn_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS abuse_call_edges (
    consumer_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    node_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    normal_requests BIGINT NOT NULL DEFAULT 0 CHECK (normal_requests >= 0),
    verification_requests BIGINT NOT NULL DEFAULT 0 CHECK (verification_requests >= 0),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer_user_id, node_user_id)
);

CREATE INDEX IF NOT EXISTS abuse_call_edges_node_consumer_idx
    ON abuse_call_edges (node_user_id, consumer_user_id);

CREATE TABLE IF NOT EXISTS abuse_decisions (
    id UUID PRIMARY KEY,
    assessment_key TEXT NOT NULL UNIQUE CHECK (length(assessment_key) BETWEEN 1 AND 128),
    request_hash TEXT NOT NULL UNIQUE CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    observation_id UUID REFERENCES abuse_network_observations(id) ON DELETE RESTRICT,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'block')),
    risk_score_ppm INTEGER NOT NULL CHECK (risk_score_ppm BETWEEN 0 AND 1000000),
    contribution_weight_ppm INTEGER NOT NULL
        CHECK (contribution_weight_ppm BETWEEN 0 AND 1000000),
    reason_codes TEXT[] NOT NULL DEFAULT '{}',
    device_user_count INTEGER CHECK (device_user_count >= 0),
    ip_user_count INTEGER CHECK (ip_user_count >= 0),
    asn_user_count INTEGER CHECK (asn_user_count >= 0),
    reciprocal_edge_requests BIGINT NOT NULL DEFAULT 0 CHECK (reciprocal_edge_requests >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS abuse_decisions_user_time_idx
    ON abuse_decisions (user_id, created_at DESC, id DESC);

DROP TRIGGER IF EXISTS abuse_network_observations_append_only
    ON abuse_network_observations;
CREATE TRIGGER abuse_network_observations_append_only
    BEFORE UPDATE OR DELETE ON abuse_network_observations
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();

DROP TRIGGER IF EXISTS abuse_decisions_append_only ON abuse_decisions;
CREATE TRIGGER abuse_decisions_append_only
    BEFORE UPDATE OR DELETE ON abuse_decisions
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();
