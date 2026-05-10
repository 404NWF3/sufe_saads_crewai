-- WP1-1 情报采集智能体 PostgreSQL 数据库创建脚本
-- 模型来源：wp11_data_model_design.tex
-- 说明：
-- 1) 本脚本默认在“已存在的数据库”中执行；如需单独建库，请先用超级用户执行：
--    CREATE DATABASE saads_wp11 ENCODING 'UTF8';
-- 2) 推荐 PostgreSQL 16+。

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE SCHEMA IF NOT EXISTS wp11;
SET search_path TO wp11, public;

-- =====================================
-- 通用函数
-- =====================================
CREATE OR REPLACE FUNCTION wp11.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

-- =====================================
-- 1. 来源采集层
-- =====================================

CREATE TABLE IF NOT EXISTS wp11.source_type (
    type_code       VARCHAR(30) PRIMARY KEY,
    type_name       VARCHAR(80) NOT NULL UNIQUE,
    description     TEXT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO wp11.source_type (type_code, type_name, description)
VALUES
    ('cve_repo', 'CVE Repository', 'Official CVE/NVD and vulnerability repositories'),
    ('github', 'GitHub', 'GitHub repositories, issues, and advisory feeds'),
    ('paper', 'Research Paper', 'Academic papers, preprints, and technical reports'),
    ('forum', 'Forum', 'Community forums and technical discussion boards'),
    ('api', 'External API', 'Third-party intelligence and monitoring APIs'),
    ('darkweb', 'Dark Web', 'Dark web monitoring and underground intelligence sources')
ON CONFLICT (type_code) DO NOTHING;

CREATE TABLE IF NOT EXISTS wp11.intel_source (
    source_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_name     VARCHAR(120) NOT NULL UNIQUE,
    source_type     VARCHAR(30) NOT NULL,
    base_uri        TEXT NOT NULL,
    trust_level     SMALLINT NOT NULL,
    default_qps     NUMERIC(6,2) NOT NULL DEFAULT 1.00,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_intel_source_type
        FOREIGN KEY (source_type)
        REFERENCES wp11.source_type (type_code)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,
    CONSTRAINT ck_intel_source_trust_level
        CHECK (trust_level BETWEEN 1 AND 5),
    CONSTRAINT ck_intel_source_default_qps
        CHECK (default_qps > 0)
);

CREATE INDEX IF NOT EXISTS idx_intel_source_type_enabled
    ON wp11.intel_source (source_type, enabled);

CREATE TABLE IF NOT EXISTS wp11.collection_task (
    task_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id        UUID NOT NULL,
    task_mode        VARCHAR(20) NOT NULL,
    trigger_type     VARCHAR(20) NOT NULL,
    task_status      VARCHAR(20) NOT NULL,
    scheduled_at     TIMESTAMPTZ NULL,
    started_at       TIMESTAMPTZ NULL,
    finished_at      TIMESTAMPTZ NULL,
    created_by       VARCHAR(80) NOT NULL DEFAULT 'system',
    retry_count      SMALLINT NOT NULL DEFAULT 0,
    trace_id         VARCHAR(64) NULL,
    CONSTRAINT fk_collection_task_source
        FOREIGN KEY (source_id)
        REFERENCES wp11.intel_source (source_id)
        ON DELETE RESTRICT,
    CONSTRAINT ck_collection_task_mode
        CHECK (task_mode IN ('fast','deep')),
    CONSTRAINT ck_collection_task_trigger_type
        CHECK (trigger_type IN ('cron','event','manual')),
    CONSTRAINT ck_collection_task_status
        CHECK (task_status IN ('queued','running','succeeded','failed','dead_letter')),
    CONSTRAINT ck_collection_task_retry_count
        CHECK (retry_count >= 0),
    CONSTRAINT ck_collection_task_started_after_scheduled
        CHECK (scheduled_at IS NULL OR started_at IS NULL OR started_at >= scheduled_at),
    CONSTRAINT ck_collection_task_finished_after_started
        CHECK (started_at IS NULL OR finished_at IS NULL OR finished_at >= started_at)
);

CREATE INDEX IF NOT EXISTS idx_collection_task_source_status_scheduled
    ON wp11.collection_task (source_id, task_status, scheduled_at);

CREATE INDEX IF NOT EXISTS idx_collection_task_trace_id
    ON wp11.collection_task (trace_id);

CREATE TABLE IF NOT EXISTS wp11.raw_intel_record (
    raw_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id         UUID NOT NULL,
    task_id           UUID NOT NULL,
    source_uri        TEXT NOT NULL,
    title             TEXT NULL,
    content_hash      CHAR(64) NOT NULL,
    raw_format        VARCHAR(20) NOT NULL,
    payload_uri       TEXT NOT NULL,
    language_code     VARCHAR(12) NULL,
    relevance_score   NUMERIC(5,4) NULL,
    parser_status     VARCHAR(20) NOT NULL DEFAULT 'pending',
    fetched_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_deleted        BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_raw_intel_source
        FOREIGN KEY (source_id)
        REFERENCES wp11.intel_source (source_id)
        ON DELETE RESTRICT,
    CONSTRAINT fk_raw_intel_task
        FOREIGN KEY (task_id)
        REFERENCES wp11.collection_task (task_id)
        ON DELETE RESTRICT,
    CONSTRAINT uq_raw_intel_source_content_hash
        UNIQUE (source_id, content_hash),
    CONSTRAINT ck_raw_intel_format
        CHECK (raw_format IN ('html','json','pdf','rss','text')),
    CONSTRAINT ck_raw_intel_relevance_score
        CHECK (relevance_score IS NULL OR (relevance_score >= 0 AND relevance_score <= 1)),
    CONSTRAINT ck_raw_intel_parser_status
        CHECK (parser_status IN ('pending','parsed','failed','skipped'))
);

CREATE INDEX IF NOT EXISTS idx_raw_intel_task_fetched_at
    ON wp11.raw_intel_record (task_id, fetched_at DESC);

CREATE INDEX IF NOT EXISTS idx_raw_intel_parser_status_fetched_at
    ON wp11.raw_intel_record (parser_status, fetched_at DESC);

-- =====================================
-- 2. 攻击知识层
-- =====================================
CREATE TABLE IF NOT EXISTS wp11.attack_entry (
    attack_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_code             VARCHAR(40) NOT NULL UNIQUE,
    canonical_name          TEXT NOT NULL,
    attack_family           VARCHAR(80) NOT NULL,
    severity_level          VARCHAR(20) NOT NULL,
    entry_status            VARCHAR(20) NOT NULL,
    summary                 TEXT NOT NULL,
    description             TEXT NOT NULL,
    exploit_preconditions   TEXT NULL,
    impact_scope            TEXT NULL,
    confidence_score        NUMERIC(5,4) NOT NULL,
    first_seen_at           TIMESTAMPTZ NULL,
    last_seen_at            TIMESTAMPTZ NULL,
    stix_type               VARCHAR(40) NULL,
    stix_payload            JSONB NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_attack_entry_severity_level
        CHECK (severity_level IN ('info','low','medium','high','critical')),
    CONSTRAINT ck_attack_entry_status
        CHECK (entry_status IN ('draft','active','deprecated','archived')),
    CONSTRAINT ck_attack_entry_confidence
        CHECK (confidence_score >= 0 AND confidence_score <= 1),
    CONSTRAINT ck_attack_entry_seen_range
        CHECK (first_seen_at IS NULL OR last_seen_at IS NULL OR first_seen_at <= last_seen_at)
);

CREATE INDEX IF NOT EXISTS idx_attack_entry_status_severity_last_seen
    ON wp11.attack_entry (entry_status, severity_level, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_attack_entry_stix_payload_gin
    ON wp11.attack_entry USING GIN (stix_payload);

CREATE INDEX IF NOT EXISTS idx_attack_entry_fts
    ON wp11.attack_entry
    USING GIN (to_tsvector('simple',
        coalesce(canonical_name, '') || ' ' ||
        coalesce(summary, '') || ' ' ||
        coalesce(description, '')
    ));

CREATE TRIGGER trg_attack_entry_set_updated_at
BEFORE UPDATE ON wp11.attack_entry
FOR EACH ROW
EXECUTE FUNCTION wp11.set_updated_at();

ALTER TABLE wp11.attack_entry
    ADD COLUMN IF NOT EXISTS primary_stix_bundle_id UUID NULL,
    ADD COLUMN IF NOT EXISTS primary_stix_object_id UUID NULL,
    ADD COLUMN IF NOT EXISTS stix_graph_status VARCHAR(20) NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_attack_entry_stix_graph_status'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.attack_entry
            ADD CONSTRAINT ck_attack_entry_stix_graph_status
            CHECK (
                stix_graph_status IS NULL
                OR stix_graph_status IN ('published','review_queue','draft','failed')
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_attack_entry_primary_stix_bundle
    ON wp11.attack_entry (primary_stix_bundle_id);

CREATE TABLE IF NOT EXISTS wp11.attack_cvss_assessment (
    score_id                 BIGSERIAL PRIMARY KEY,
    attack_id                UUID NOT NULL,
    source_raw_id            UUID NULL,
    cvss_version             VARCHAR(10) NOT NULL,
    vector_string            VARCHAR(255) NULL,
    base_score               NUMERIC(3,1) NULL,
    temporal_score           NUMERIC(3,1) NULL,
    environmental_score      NUMERIC(3,1) NULL,
    severity_label           VARCHAR(20) NOT NULL,
    exploitability_subscore  NUMERIC(4,2) NULL,
    impact_subscore          NUMERIC(4,2) NULL,
    score_origin             VARCHAR(20) NOT NULL,
    score_provider           VARCHAR(80) NULL,
    confidence_score         NUMERIC(5,4) NOT NULL,
    is_primary               BOOLEAN NOT NULL DEFAULT FALSE,
    published_at             TIMESTAMPTZ NULL,
    calculated_at            TIMESTAMPTZ NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_cvss_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_cvss_source_raw
        FOREIGN KEY (source_raw_id)
        REFERENCES wp11.raw_intel_record (raw_id)
        ON DELETE SET NULL,
    CONSTRAINT ck_cvss_version
        CHECK (cvss_version IN ('3.0','3.1','4.0')),
    CONSTRAINT ck_cvss_base_score
        CHECK (base_score IS NULL OR (base_score >= 0 AND base_score <= 10)),
    CONSTRAINT ck_cvss_temporal_score
        CHECK (temporal_score IS NULL OR (temporal_score >= 0 AND temporal_score <= 10)),
    CONSTRAINT ck_cvss_environmental_score
        CHECK (environmental_score IS NULL OR (environmental_score >= 0 AND environmental_score <= 10)),
    CONSTRAINT ck_cvss_exploitability_subscore
        CHECK (exploitability_subscore IS NULL OR (exploitability_subscore >= 0 AND exploitability_subscore <= 10)),
    CONSTRAINT ck_cvss_impact_subscore
        CHECK (impact_subscore IS NULL OR (impact_subscore >= 0 AND impact_subscore <= 10)),
    CONSTRAINT ck_cvss_severity_label
        CHECK (severity_label IN ('None','Low','Medium','High','Critical')),
    CONSTRAINT ck_cvss_score_origin
        CHECK (score_origin IN ('supplied','calculated','estimated','manual')),
    CONSTRAINT ck_cvss_confidence_score
        CHECK (confidence_score >= 0 AND confidence_score <= 1),
    CONSTRAINT ck_cvss_primary_requires_base_score
        CHECK (NOT is_primary OR base_score IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_cvss_attack_primary_base
    ON wp11.attack_cvss_assessment (attack_id, is_primary, base_score DESC);

CREATE INDEX IF NOT EXISTS idx_cvss_provider_version
    ON wp11.attack_cvss_assessment (score_provider, cvss_version);

CREATE INDEX IF NOT EXISTS idx_cvss_source_raw_id
    ON wp11.attack_cvss_assessment (source_raw_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cvss_primary_per_attack_version
    ON wp11.attack_cvss_assessment (attack_id, cvss_version)
    WHERE is_primary = TRUE;

CREATE TABLE IF NOT EXISTS wp11.attack_evidence (
    attack_id          UUID NOT NULL,
    raw_id             UUID NOT NULL,
    evidence_role      VARCHAR(20) NOT NULL,
    extractor_name     VARCHAR(80) NOT NULL,
    extracted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    evidence_snippet   TEXT NULL,
    PRIMARY KEY (attack_id, raw_id),
    CONSTRAINT fk_attack_evidence_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_attack_evidence_raw
        FOREIGN KEY (raw_id)
        REFERENCES wp11.raw_intel_record (raw_id)
        ON DELETE CASCADE,
    CONSTRAINT ck_attack_evidence_role
        CHECK (evidence_role IN ('primary','supporting','contradictory'))
);

CREATE INDEX IF NOT EXISTS idx_attack_evidence_raw_id
    ON wp11.attack_evidence (raw_id);

CREATE INDEX IF NOT EXISTS idx_attack_evidence_attack_role
    ON wp11.attack_evidence (attack_id, evidence_role);

CREATE TABLE IF NOT EXISTS wp11.attack_taxonomy_map (
    map_id             BIGSERIAL PRIMARY KEY,
    attack_id          UUID NOT NULL,
    taxonomy_type      VARCHAR(30) NOT NULL,
    taxonomy_code      VARCHAR(80) NOT NULL,
    taxonomy_name      VARCHAR(200) NOT NULL,
    is_primary         BOOLEAN NOT NULL DEFAULT FALSE,
    confidence_score   NUMERIC(5,4) NOT NULL,
    CONSTRAINT fk_taxonomy_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE CASCADE,
    CONSTRAINT uq_attack_taxonomy
        UNIQUE (attack_id, taxonomy_type, taxonomy_code),
    CONSTRAINT ck_taxonomy_type
        CHECK (taxonomy_type IN ('OWASP_LLM','CWE','CAPEC','ATTACK')),
    CONSTRAINT ck_taxonomy_confidence_score
        CHECK (confidence_score >= 0 AND confidence_score <= 1)
);

CREATE INDEX IF NOT EXISTS idx_attack_taxonomy_type_code
    ON wp11.attack_taxonomy_map (taxonomy_type, taxonomy_code);

CREATE UNIQUE INDEX IF NOT EXISTS uq_attack_primary_taxonomy_per_type
    ON wp11.attack_taxonomy_map (attack_id, taxonomy_type)
    WHERE is_primary = TRUE;

CREATE TABLE IF NOT EXISTS wp11.attack_seed_asset (
    asset_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id        UUID NOT NULL,
    asset_type       VARCHAR(30) NOT NULL,
    asset_name       VARCHAR(160) NOT NULL,
    artifact_uri     TEXT NOT NULL,
    checksum         CHAR(64) NOT NULL,
    language         VARCHAR(30) NULL,
    modality         VARCHAR(30) NULL,
    qa_status        VARCHAR(20) NOT NULL DEFAULT 'draft',
    is_template      BOOLEAN NOT NULL DEFAULT TRUE,
    metadata_json    JSONB NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_seed_asset_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE CASCADE,
    CONSTRAINT uq_seed_asset_checksum
        UNIQUE (checksum),
    CONSTRAINT ck_seed_asset_type
        CHECK (asset_type IN ('poc','payload_template','prompt_corpus','rule')),
    CONSTRAINT ck_seed_asset_qa_status
        CHECK (qa_status IN ('draft','reviewed','published')),
    CONSTRAINT ck_seed_asset_modality
        CHECK (modality IS NULL OR modality IN ('text','image','audio','multimodal')),
    CONSTRAINT ck_seed_asset_publish_ready
        CHECK (qa_status <> 'published' OR (checksum IS NOT NULL AND artifact_uri IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_seed_asset_attack_qa
    ON wp11.attack_seed_asset (attack_id, qa_status);
CREATE INDEX IF NOT EXISTS idx_seed_asset_metadata_gin
    ON wp11.attack_seed_asset USING GIN (metadata_json);

CREATE TABLE IF NOT EXISTS wp11.remediation_advice (
    advice_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id         UUID NOT NULL,
    advice_type       VARCHAR(30) NOT NULL,
    title             VARCHAR(200) NOT NULL,
    content           TEXT NOT NULL,
    priority_level    SMALLINT NOT NULL,
    source_uri        TEXT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_remediation_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE CASCADE,
    CONSTRAINT ck_remediation_type
        CHECK (advice_type IN ('hardening','detection','patch','process')),
    CONSTRAINT ck_remediation_priority
        CHECK (priority_level BETWEEN 1 AND 5)
);

CREATE INDEX IF NOT EXISTS idx_remediation_attack_priority
    ON wp11.remediation_advice (attack_id, priority_level DESC);

-- =====================================
-- 3. AI BOM 层
-- =====================================
CREATE TABLE IF NOT EXISTS wp11.ai_component (
    component_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_code      VARCHAR(40) NOT NULL UNIQUE,
    component_name      VARCHAR(160) NOT NULL,
    component_layer     VARCHAR(40) NULL,
    vendor_name         VARCHAR(120) NULL,
    component_type      VARCHAR(40) NOT NULL,
    modality            VARCHAR(30) NULL,
    purl                TEXT NULL,
    homepage_uri        TEXT NULL,
    lifecycle_status    VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_ai_component_type
        CHECK (component_type IN ('model','framework','plugin','vector_db','agent_tool')),
    CONSTRAINT ck_ai_component_modality
        CHECK (modality IS NULL OR modality IN ('text','image','audio','multimodal')),
    CONSTRAINT ck_ai_component_lifecycle
        CHECK (lifecycle_status IN ('active','deprecated','retired'))
);

ALTER TABLE wp11.ai_component
    ADD COLUMN IF NOT EXISTS component_layer VARCHAR(40) NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_ai_component_layer'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.ai_component
            ADD CONSTRAINT ck_ai_component_layer
            CHECK (component_layer IS NULL OR component_layer IN (
                'vendor_platform', 'model_family', 'framework', 'plugin', 'runtime', 'vector_stack'
            ));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ai_component_type_vendor
    ON wp11.ai_component (component_type, vendor_name);

CREATE INDEX IF NOT EXISTS idx_ai_component_name
    ON wp11.ai_component (component_name);

CREATE TABLE IF NOT EXISTS wp11.ai_component_alias (
    alias_id            BIGSERIAL PRIMARY KEY,
    component_id        UUID NOT NULL,
    alias_name          VARCHAR(160) NOT NULL,
    alias_type          VARCHAR(30) NOT NULL,
    normalized_alias    VARCHAR(160) NOT NULL,
    is_preferred        BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_component_alias_component
        FOREIGN KEY (component_id)
        REFERENCES wp11.ai_component (component_id)
        ON DELETE CASCADE,
    CONSTRAINT ck_component_alias_type
        CHECK (alias_type IN ('vendor','common','package','research_name'))
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'uq_component_alias_normalized'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.ai_component_alias
            DROP CONSTRAINT uq_component_alias_normalized;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_component_alias_component_normalized
    ON wp11.ai_component_alias (component_id, normalized_alias);

CREATE INDEX IF NOT EXISTS idx_component_alias_component_id
    ON wp11.ai_component_alias (component_id);

CREATE INDEX IF NOT EXISTS idx_component_alias_normalized_trgm
    ON wp11.ai_component_alias USING GIN (normalized_alias gin_trgm_ops);

CREATE TABLE IF NOT EXISTS wp11.attack_component_mention (
    mention_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id               UUID NULL,
    raw_id                  UUID NULL,
    mentioned_name          VARCHAR(160) NOT NULL,
    mentioned_vendor        VARCHAR(120) NULL,
    mentioned_version       VARCHAR(80) NULL,
    normalized_alias        VARCHAR(160) NOT NULL,
    normalized_vendor       VARCHAR(120) NULL,
    component_layer         VARCHAR(40) NULL,
    impact_scope            VARCHAR(40) NULL,
    dependency_role         VARCHAR(40) NULL,
    evidence_snippet        TEXT NULL,
    extractor_name          VARCHAR(80) NOT NULL,
    extraction_confidence   NUMERIC(5,4) NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_component_mention_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE SET NULL,
    CONSTRAINT fk_component_mention_raw
        FOREIGN KEY (raw_id)
        REFERENCES wp11.raw_intel_record (raw_id)
        ON DELETE SET NULL,
    CONSTRAINT ck_component_mention_confidence
        CHECK (extraction_confidence >= 0 AND extraction_confidence <= 1),
    CONSTRAINT ck_component_mention_layer
        CHECK (
            component_layer IS NULL
            OR component_layer IN (
                'vendor_platform', 'model_family', 'framework', 'plugin', 'runtime', 'vector_stack', 'unknown'
            )
        ),
    CONSTRAINT ck_component_mention_impact_scope
        CHECK (
            impact_scope IS NULL
            OR impact_scope IN ('direct','indirect','runtime','supply_chain')
        )
);

CREATE INDEX IF NOT EXISTS idx_component_mention_attack_created_at
    ON wp11.attack_component_mention (attack_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_component_mention_normalized_alias
    ON wp11.attack_component_mention (normalized_alias);

CREATE TABLE IF NOT EXISTS wp11.attack_component_impact (
    impact_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id                  UUID NOT NULL,
    component_id               UUID NOT NULL,
    version_constraint_raw     VARCHAR(120) NULL,
    normalized_constraint      VARCHAR(120) NULL,
    match_mode                 VARCHAR(20) NOT NULL,
    impact_scope               VARCHAR(40) NOT NULL,
    confidence_score           NUMERIC(5,4) NOT NULL,
    evidence_uri               TEXT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_component_impact_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_component_impact_component
        FOREIGN KEY (component_id)
        REFERENCES wp11.ai_component (component_id)
        ON DELETE RESTRICT,
    CONSTRAINT ck_component_impact_scope
        CHECK (impact_scope IN ('direct','indirect','runtime','supply_chain')),
    CONSTRAINT ck_component_impact_confidence
        CHECK (confidence_score >= 0 AND confidence_score <= 1)
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_component_impact_match_mode'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.attack_component_impact
            DROP CONSTRAINT ck_component_impact_match_mode;
    END IF;
END $$;

ALTER TABLE wp11.attack_component_impact
    ADD CONSTRAINT ck_component_impact_match_mode
    CHECK (match_mode IN ('exact','alias','trigram','embedding','range','vendor_fallback','major_only'));

CREATE UNIQUE INDEX IF NOT EXISTS uq_attack_component_impact_dedup
    ON wp11.attack_component_impact (
        attack_id,
        component_id,
        COALESCE(normalized_constraint, ''),
        impact_scope
    );

CREATE INDEX IF NOT EXISTS idx_attack_component_impact_component_mode
    ON wp11.attack_component_impact (component_id, match_mode);

CREATE INDEX IF NOT EXISTS idx_attack_component_impact_attack_confidence
    ON wp11.attack_component_impact (attack_id, confidence_score DESC);

ALTER TABLE wp11.attack_component_impact
    ADD COLUMN IF NOT EXISTS mention_id UUID NULL,
    ADD COLUMN IF NOT EXISTS source_raw_id UUID NULL,
    ADD COLUMN IF NOT EXISTS review_status VARCHAR(20) NOT NULL DEFAULT 'accepted',
    ADD COLUMN IF NOT EXISTS resolver_strategy VARCHAR(40) NULL,
    ADD COLUMN IF NOT EXISTS evidence_snippet TEXT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_component_impact_mention'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.attack_component_impact
            ADD CONSTRAINT fk_component_impact_mention
            FOREIGN KEY (mention_id)
            REFERENCES wp11.attack_component_mention (mention_id)
            ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_component_impact_source_raw'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.attack_component_impact
            ADD CONSTRAINT fk_component_impact_source_raw
            FOREIGN KEY (source_raw_id)
            REFERENCES wp11.raw_intel_record (raw_id)
            ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_component_impact_review_status'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.attack_component_impact
            ADD CONSTRAINT ck_component_impact_review_status
            CHECK (review_status IN ('accepted','review_queue','rejected'));
    END IF;
END $$;

-- =====================================
-- 4. 治理审计层
-- =====================================
CREATE TABLE IF NOT EXISTS wp11.dedup_audit (
    audit_id             BIGSERIAL PRIMARY KEY,
    candidate_raw_id     UUID NOT NULL,
    matched_attack_id    UUID NULL,
    similarity_score     NUMERIC(5,4) NOT NULL,
    rule_name            VARCHAR(80) NOT NULL,
    decision             VARCHAR(20) NOT NULL,
    reviewer_name        VARCHAR(80) NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_dedup_candidate_raw
        FOREIGN KEY (candidate_raw_id)
        REFERENCES wp11.raw_intel_record (raw_id)
        ON DELETE RESTRICT,
    CONSTRAINT fk_dedup_matched_attack
        FOREIGN KEY (matched_attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE SET NULL,
    CONSTRAINT ck_dedup_similarity
        CHECK (similarity_score >= 0 AND similarity_score <= 1),
    CONSTRAINT ck_dedup_decision
        CHECK (decision IN ('merge','new','review'))
);

CREATE INDEX IF NOT EXISTS idx_dedup_candidate_raw
    ON wp11.dedup_audit (candidate_raw_id);

CREATE INDEX IF NOT EXISTS idx_dedup_matched_attack_decision
    ON wp11.dedup_audit (matched_attack_id, decision);

CREATE TABLE IF NOT EXISTS wp11.bom_resolution_queue (
    queue_id                 BIGSERIAL PRIMARY KEY,
    attack_id                UUID NULL,
    raw_id                   UUID NULL,
    mentioned_name           VARCHAR(160) NOT NULL,
    mentioned_vendor         VARCHAR(120) NULL,
    mentioned_version        VARCHAR(80) NULL,
    reason_code              VARCHAR(40) NOT NULL,
    queue_status             VARCHAR(20) NOT NULL DEFAULT 'open',
    resolved_component_id    UUID NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at              TIMESTAMPTZ NULL,
    CONSTRAINT fk_bom_queue_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE SET NULL,
    CONSTRAINT fk_bom_queue_raw
        FOREIGN KEY (raw_id)
        REFERENCES wp11.raw_intel_record (raw_id)
        ON DELETE SET NULL,
    CONSTRAINT fk_bom_queue_resolved_component
        FOREIGN KEY (resolved_component_id)
        REFERENCES wp11.ai_component (component_id)
        ON DELETE RESTRICT,
    CONSTRAINT ck_bom_queue_reason
        CHECK (reason_code IN ('alias_not_found','version_ambiguous','conflict')),
    CONSTRAINT ck_bom_queue_status
        CHECK (queue_status IN ('open','resolved','rejected')),
    CONSTRAINT ck_bom_queue_resolved_consistency
        CHECK (
            (queue_status = 'resolved' AND resolved_component_id IS NOT NULL)
            OR (queue_status <> 'resolved')
        ),
    CONSTRAINT ck_bom_queue_resolved_time_consistency
        CHECK (
            (queue_status = 'resolved' AND resolved_at IS NOT NULL)
            OR (queue_status <> 'resolved')
            OR resolved_at IS NULL
        )
);

CREATE INDEX IF NOT EXISTS idx_bom_queue_status_created_at
    ON wp11.bom_resolution_queue (queue_status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_bom_queue_mentioned_name
    ON wp11.bom_resolution_queue (mentioned_name);

ALTER TABLE wp11.bom_resolution_queue
    ADD COLUMN IF NOT EXISTS mention_id UUID NULL,
    ADD COLUMN IF NOT EXISTS candidate_snapshot JSONB NULL,
    ADD COLUMN IF NOT EXISTS reasoning_summary TEXT NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_bom_queue_reason'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.bom_resolution_queue
            DROP CONSTRAINT ck_bom_queue_reason;
    END IF;
END $$;

ALTER TABLE wp11.bom_resolution_queue
    ADD CONSTRAINT ck_bom_queue_reason
    CHECK (
        reason_code IN (
            'alias_not_found',
            'version_ambiguous',
            'conflict',
            'catalog_gap',
            'vendor_conflict',
            'layer_conflict',
            'version_parse_failed',
            'cross_source_conflict',
            'llm_no_match',
            'llm_low_confidence',
            'missing_evidence',
            'reviewer_rejected'
        )
    );

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_bom_queue_mention'
          AND connamespace = 'wp11'::regnamespace
    ) THEN
        ALTER TABLE wp11.bom_resolution_queue
            ADD CONSTRAINT fk_bom_queue_mention
            FOREIGN KEY (mention_id)
            REFERENCES wp11.attack_component_mention (mention_id)
            ON DELETE SET NULL;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS wp11.bom_resolution_audit (
    audit_id                  BIGSERIAL PRIMARY KEY,
    mention_id                UUID NULL,
    attack_id                 UUID NULL,
    raw_id                    UUID NULL,
    strategy_requested        VARCHAR(40) NOT NULL,
    strategy_executed         VARCHAR(40) NOT NULL,
    llm_model                 VARCHAR(120) NOT NULL,
    prompt_version            VARCHAR(40) NOT NULL,
    llm_decision              VARCHAR(20) NOT NULL,
    llm_confidence            NUMERIC(5,4) NOT NULL,
    selected_component_code   VARCHAR(40) NULL,
    reasoning_summary         TEXT NOT NULL,
    reasoning_trace           JSONB NULL,
    candidate_count           INTEGER NOT NULL DEFAULT 0,
    evidence_quotes           JSONB NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_bom_audit_mention
        FOREIGN KEY (mention_id)
        REFERENCES wp11.attack_component_mention (mention_id)
        ON DELETE SET NULL,
    CONSTRAINT fk_bom_audit_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE SET NULL,
    CONSTRAINT fk_bom_audit_raw
        FOREIGN KEY (raw_id)
        REFERENCES wp11.raw_intel_record (raw_id)
        ON DELETE SET NULL,
    CONSTRAINT ck_bom_audit_confidence
        CHECK (llm_confidence >= 0 AND llm_confidence <= 1)
);

CREATE INDEX IF NOT EXISTS idx_bom_audit_attack_created_at
    ON wp11.bom_resolution_audit (attack_id, created_at DESC);

CREATE TABLE IF NOT EXISTS wp11.query_feedback_log (
    feedback_id          BIGSERIAL PRIMARY KEY,
    run_id               VARCHAR(64) NOT NULL,
    query_run_id         VARCHAR(64) NOT NULL,
    source_name          VARCHAR(120) NOT NULL,
    query_text           TEXT NOT NULL,
    query_intent         VARCHAR(40) NOT NULL,
    rewrite_round        SMALLINT NOT NULL DEFAULT 0,
    result_count         INTEGER NOT NULL DEFAULT 0,
    parsed_count         INTEGER NOT NULL DEFAULT 0,
    duplicate_count      INTEGER NOT NULL DEFAULT 0,
    novelty_yield        NUMERIC(5,4) NOT NULL DEFAULT 0,
    noise_ratio          NUMERIC(5,4) NOT NULL DEFAULT 0,
    source_mismatch      BOOLEAN NOT NULL DEFAULT FALSE,
    reflection_diagnosis VARCHAR(60) NULL,
    reflection_action    VARCHAR(60) NULL,
    should_retry         BOOLEAN NOT NULL DEFAULT FALSE,
    expected_gain_dim    VARCHAR(40) NULL,
    llm_confidence       NUMERIC(5,4) NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_query_feedback_novelty_yield
        CHECK (novelty_yield >= 0 AND novelty_yield <= 1),
    CONSTRAINT ck_query_feedback_noise_ratio
        CHECK (noise_ratio >= 0 AND noise_ratio <= 1),
    CONSTRAINT ck_query_feedback_llm_confidence
        CHECK (llm_confidence IS NULL OR (llm_confidence >= 0 AND llm_confidence <= 1)),
    CONSTRAINT ck_query_feedback_rewrite_round
        CHECK (rewrite_round >= 0)
);

CREATE INDEX IF NOT EXISTS idx_query_feedback_run_id
    ON wp11.query_feedback_log (run_id, created_at DESC);

-- =====================================
-- 5. STIX 2.1 规范化图模型
-- =====================================
CREATE TABLE IF NOT EXISTS wp11.stix_bundle (
    bundle_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id                 UUID NULL,
    bundle_stix_id            VARCHAR(80) NOT NULL UNIQUE,
    spec_version              VARCHAR(10) NOT NULL DEFAULT '2.1',
    bundle_role               VARCHAR(30) NOT NULL DEFAULT 'attack_graph',
    graph_confidence          NUMERIC(5,4) NULL,
    review_status             VARCHAR(20) NOT NULL DEFAULT 'draft',
    primary_object_stix_id    VARCHAR(80) NULL,
    bundle_payload            JSONB NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_stix_bundle_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE SET NULL,
    CONSTRAINT ck_stix_bundle_confidence
        CHECK (graph_confidence IS NULL OR (graph_confidence >= 0 AND graph_confidence <= 1)),
    CONSTRAINT ck_stix_bundle_review_status
        CHECK (review_status IN ('published','review_queue','draft','failed'))
);

CREATE TRIGGER trg_stix_bundle_set_updated_at
BEFORE UPDATE ON wp11.stix_bundle
FOR EACH ROW
EXECUTE FUNCTION wp11.set_updated_at();

CREATE TABLE IF NOT EXISTS wp11.stix_object (
    object_pk                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_id                 UUID NOT NULL,
    attack_id                 UUID NULL,
    stix_id                   VARCHAR(80) NOT NULL,
    object_type               VARCHAR(40) NOT NULL,
    spec_version              VARCHAR(10) NOT NULL DEFAULT '2.1',
    name                      TEXT NULL,
    description               TEXT NULL,
    created_ts                TIMESTAMPTZ NULL,
    modified_ts               TIMESTAMPTZ NULL,
    revoked                   BOOLEAN NOT NULL DEFAULT FALSE,
    confidence                NUMERIC(5,4) NULL,
    lang                      VARCHAR(20) NULL,
    is_primary                BOOLEAN NOT NULL DEFAULT FALSE,
    raw_payload               JSONB NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_stix_object_bundle
        FOREIGN KEY (bundle_id)
        REFERENCES wp11.stix_bundle (bundle_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_stix_object_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE SET NULL,
    CONSTRAINT uq_stix_object_bundle_stix_id
        UNIQUE (bundle_id, stix_id),
    CONSTRAINT ck_stix_object_confidence
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1))
);

CREATE TRIGGER trg_stix_object_set_updated_at
BEFORE UPDATE ON wp11.stix_object
FOR EACH ROW
EXECUTE FUNCTION wp11.set_updated_at();

CREATE INDEX IF NOT EXISTS idx_stix_object_type_name
    ON wp11.stix_object (object_type, name);

CREATE TABLE IF NOT EXISTS wp11.stix_relationship_projection (
    relationship_pk           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    object_pk                 UUID NOT NULL,
    bundle_id                 UUID NOT NULL,
    relationship_type         VARCHAR(40) NOT NULL,
    source_ref                VARCHAR(80) NOT NULL,
    target_ref                VARCHAR(80) NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_stix_relationship_object
        FOREIGN KEY (object_pk)
        REFERENCES wp11.stix_object (object_pk)
        ON DELETE CASCADE,
    CONSTRAINT fk_stix_relationship_bundle
        FOREIGN KEY (bundle_id)
        REFERENCES wp11.stix_bundle (bundle_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wp11.stix_external_reference (
    ext_ref_id                BIGSERIAL PRIMARY KEY,
    object_pk                 UUID NOT NULL,
    source_name               VARCHAR(120) NOT NULL,
    external_id               VARCHAR(120) NULL,
    url                       TEXT NULL,
    description               TEXT NULL,
    CONSTRAINT fk_stix_external_ref_object
        FOREIGN KEY (object_pk)
        REFERENCES wp11.stix_object (object_pk)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wp11.stix_kill_chain_phase (
    phase_id                  BIGSERIAL PRIMARY KEY,
    object_pk                 UUID NOT NULL,
    kill_chain_name           VARCHAR(80) NOT NULL,
    phase_name                VARCHAR(80) NOT NULL,
    CONSTRAINT fk_stix_phase_object
        FOREIGN KEY (object_pk)
        REFERENCES wp11.stix_object (object_pk)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wp11.stix_object_label (
    object_pk                 UUID NOT NULL,
    label                     VARCHAR(80) NOT NULL,
    PRIMARY KEY (object_pk, label),
    CONSTRAINT fk_stix_label_object
        FOREIGN KEY (object_pk)
        REFERENCES wp11.stix_object (object_pk)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wp11.stix_object_alias (
    object_pk                 UUID NOT NULL,
    alias                     VARCHAR(160) NOT NULL,
    PRIMARY KEY (object_pk, alias),
    CONSTRAINT fk_stix_alias_object
        FOREIGN KEY (object_pk)
        REFERENCES wp11.stix_object (object_pk)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wp11.attack_stix_binding (
    binding_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_id                 UUID NOT NULL UNIQUE,
    active_bundle_id          UUID NOT NULL,
    primary_object_pk         UUID NOT NULL,
    publication_status        VARCHAR(20) NOT NULL DEFAULT 'review_queue',
    published_at              TIMESTAMPTZ NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_attack_stix_binding_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_attack_stix_binding_bundle
        FOREIGN KEY (active_bundle_id)
        REFERENCES wp11.stix_bundle (bundle_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_attack_stix_binding_object
        FOREIGN KEY (primary_object_pk)
        REFERENCES wp11.stix_object (object_pk)
        ON DELETE CASCADE,
    CONSTRAINT ck_attack_stix_binding_status
        CHECK (publication_status IN ('published','review_queue','draft'))
);

CREATE TRIGGER trg_attack_stix_binding_set_updated_at
BEFORE UPDATE ON wp11.attack_stix_binding
FOR EACH ROW
EXECUTE FUNCTION wp11.set_updated_at();

CREATE TABLE IF NOT EXISTS wp11.stix_review_queue (
    review_id                 BIGSERIAL PRIMARY KEY,
    attack_id                 UUID NULL,
    bundle_id                 UUID NULL,
    reason_code               VARCHAR(40) NOT NULL,
    queue_status              VARCHAR(20) NOT NULL DEFAULT 'open',
    review_payload            JSONB NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at               TIMESTAMPTZ NULL,
    CONSTRAINT fk_stix_review_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE SET NULL,
    CONSTRAINT fk_stix_review_bundle
        FOREIGN KEY (bundle_id)
        REFERENCES wp11.stix_bundle (bundle_id)
        ON DELETE SET NULL,
    CONSTRAINT ck_stix_review_status
        CHECK (queue_status IN ('open','resolved','rejected'))
);

CREATE TABLE IF NOT EXISTS wp11.stix_extraction_audit (
    audit_id                  BIGSERIAL PRIMARY KEY,
    attack_id                 UUID NULL,
    bundle_id                 UUID NULL,
    extractor_model           VARCHAR(120) NOT NULL,
    reviewer_model            VARCHAR(120) NULL,
    prompt_version            VARCHAR(40) NOT NULL,
    review_decision           VARCHAR(20) NOT NULL,
    graph_confidence          NUMERIC(5,4) NULL,
    reasoning_summary         TEXT NOT NULL,
    reasoning_trace           JSONB NULL,
    finding_count             INTEGER NOT NULL DEFAULT 0,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_stix_audit_attack
        FOREIGN KEY (attack_id)
        REFERENCES wp11.attack_entry (attack_id)
        ON DELETE SET NULL,
    CONSTRAINT fk_stix_audit_bundle
        FOREIGN KEY (bundle_id)
        REFERENCES wp11.stix_bundle (bundle_id)
        ON DELETE SET NULL,
    CONSTRAINT ck_stix_audit_confidence
        CHECK (graph_confidence IS NULL OR (graph_confidence >= 0 AND graph_confidence <= 1)),
    CONSTRAINT ck_stix_audit_review_decision
        CHECK (review_decision IN ('accept','review_queue'))
);

CREATE INDEX IF NOT EXISTS idx_query_feedback_source_intent
    ON wp11.query_feedback_log (source_name, query_intent, created_at DESC);

ALTER TABLE wp11.bom_resolution_audit
    ADD COLUMN IF NOT EXISTS reasoning_trace JSONB NULL;

ALTER TABLE wp11.stix_extraction_audit
    ADD COLUMN IF NOT EXISTS reasoning_trace JSONB NULL;

COMMENT ON TABLE wp11.query_feedback_log IS '查询反馈历史持久化，跨 run 积累，支持自适应查询调整';


-- =====================================
-- 5. 视图 / 物化视图
-- =====================================
CREATE OR REPLACE VIEW wp11.v_primary_cvss_score AS
WITH ranked AS (
    SELECT
        a.*,
        ROW_NUMBER() OVER (
            PARTITION BY a.attack_id
            ORDER BY
                CASE a.cvss_version
                    WHEN '4.0' THEN 3
                    WHEN '3.1' THEN 2
                    WHEN '3.0' THEN 1
                    ELSE 0
                END DESC,
                COALESCE(a.published_at, a.calculated_at, a.created_at) DESC,
                a.base_score DESC NULLS LAST,
                a.score_id DESC
        ) AS rn
    FROM wp11.attack_cvss_assessment a
    WHERE a.is_primary = TRUE
)
SELECT
    score_id,
    attack_id,
    cvss_version,
    vector_string,
    base_score,
    temporal_score,
    environmental_score,
    severity_label,
    exploitability_subscore,
    impact_subscore,
    score_origin,
    score_provider,
    confidence_score,
    published_at,
    calculated_at,
    created_at
FROM ranked
WHERE rn = 1;

CREATE OR REPLACE VIEW wp11.v_wp12_attack_feed AS
SELECT
    ae.attack_id,
    ae.attack_code,
    ae.canonical_name,
    ae.attack_family,
    ae.severity_level,
    ae.entry_status,
    ae.summary,
    ae.last_seen_at,
    pcs.cvss_version AS primary_cvss_version,
    pcs.base_score AS primary_cvss_base_score,
    pcs.vector_string AS primary_cvss_vector,
    pcs.severity_label AS primary_cvss_severity_label,
    atm.taxonomy_type,
    atm.taxonomy_code,
    atm.taxonomy_name,
    ac.component_id,
    ac.component_name,
    aci.version_constraint_raw,
    aci.normalized_constraint,
    aci.impact_scope AS component_impact_scope,
    asa.asset_id,
    asa.asset_type,
    asa.asset_name,
    asa.artifact_uri,
    asa.qa_status
FROM wp11.attack_entry ae
LEFT JOIN wp11.v_primary_cvss_score pcs
    ON pcs.attack_id = ae.attack_id
LEFT JOIN wp11.attack_taxonomy_map atm
    ON atm.attack_id = ae.attack_id
   AND atm.is_primary = TRUE
LEFT JOIN wp11.attack_component_impact aci
    ON aci.attack_id = ae.attack_id
LEFT JOIN wp11.ai_component ac
    ON ac.component_id = aci.component_id
LEFT JOIN wp11.attack_seed_asset asa
    ON asa.attack_id = ae.attack_id
   AND asa.qa_status IN ('reviewed','published')
WHERE ae.entry_status = 'active';

CREATE OR REPLACE VIEW wp11.v_wp12_attack_execution_feed AS
SELECT
    ae.attack_id,
    ae.attack_code,
    ae.canonical_name,
    ae.attack_family,
    ae.severity_level,
    ae.summary,
    ac.component_id,
    ac.component_name,
    aci.normalized_constraint,
    aci.impact_scope AS component_impact_scope,
    ae.primary_stix_bundle_id,
    ae.primary_stix_object_id,
    ae.stix_graph_status,
    sb.primary_object_stix_id AS primary_attack_pattern_stix_id,
    sb.bundle_payload AS stix_bundle_payload
FROM wp11.attack_entry ae
LEFT JOIN wp11.attack_component_impact aci
    ON aci.attack_id = ae.attack_id
   AND aci.review_status = 'accepted'
LEFT JOIN wp11.ai_component ac
    ON ac.component_id = aci.component_id
LEFT JOIN wp11.stix_bundle sb
    ON sb.bundle_id = ae.primary_stix_bundle_id
WHERE ae.entry_status = 'active'
  AND (
      ae.stix_graph_status = 'published'
      OR ae.stix_graph_status IS NULL
  );

CREATE OR REPLACE VIEW wp11.v_component_risk_overview AS
SELECT
    ac.component_id,
    ac.component_code,
    ac.component_name,
    ac.vendor_name,
    ac.component_type,
    COUNT(DISTINCT aci.attack_id) AS attack_count,
    COUNT(DISTINCT aci.attack_id) FILTER (WHERE pcs.base_score >= 7.0) AS high_cvss_attack_count,
    COUNT(DISTINCT aci.attack_id) FILTER (WHERE pcs.base_score >= 9.0) AS critical_cvss_attack_count,
    MAX(ae.last_seen_at) AS latest_seen_at,
    MAX(pcs.base_score) AS max_primary_cvss_score,
    AVG(pcs.base_score) FILTER (WHERE pcs.base_score IS NOT NULL) AS avg_primary_cvss_score
FROM wp11.ai_component ac
LEFT JOIN wp11.attack_component_impact aci
    ON aci.component_id = ac.component_id
LEFT JOIN wp11.attack_entry ae
    ON ae.attack_id = aci.attack_id
LEFT JOIN wp11.v_primary_cvss_score pcs
    ON pcs.attack_id = ae.attack_id
GROUP BY
    ac.component_id,
    ac.component_code,
    ac.component_name,
    ac.vendor_name,
    ac.component_type;

CREATE OR REPLACE VIEW wp11.v_unresolved_bom_queue AS
SELECT
    q.queue_id,
    q.attack_id,
    ae.attack_code,
    ae.canonical_name,
    q.raw_id,
    rir.source_uri,
    q.mentioned_name,
    q.mentioned_vendor,
    q.mentioned_version,
    q.reason_code,
    q.queue_status,
    q.created_at,
    q.resolved_at
FROM wp11.bom_resolution_queue q
LEFT JOIN wp11.attack_entry ae
    ON ae.attack_id = q.attack_id
LEFT JOIN wp11.raw_intel_record rir
    ON rir.raw_id = q.raw_id
WHERE q.queue_status = 'open';

CREATE OR REPLACE VIEW wp11.v_source_quality_dashboard AS
SELECT
    s.source_id,
    s.source_name,
    s.source_type,
    COUNT(DISTINCT r.raw_id) AS raw_record_count,
    COUNT(DISTINCT r.raw_id) FILTER (WHERE r.parser_status = 'parsed') AS parsed_record_count,
    COUNT(DISTINCT e.attack_id) AS effective_attack_count,
    COUNT(DISTINCT d.audit_id) FILTER (WHERE d.decision = 'merge') AS dedup_merge_count,
    AVG(r.relevance_score) FILTER (WHERE r.relevance_score IS NOT NULL) AS avg_relevance_score,
    MAX(r.fetched_at) AS latest_fetched_at,
    COUNT(DISTINCT t.task_id) FILTER (WHERE t.task_status = 'failed') AS failed_task_count
FROM wp11.intel_source s
LEFT JOIN wp11.collection_task t
    ON t.source_id = s.source_id
LEFT JOIN wp11.raw_intel_record r
    ON r.source_id = s.source_id
LEFT JOIN wp11.attack_evidence e
    ON e.raw_id = r.raw_id
LEFT JOIN wp11.dedup_audit d
    ON d.candidate_raw_id = r.raw_id
GROUP BY s.source_id, s.source_name, s.source_type;

CREATE MATERIALIZED VIEW IF NOT EXISTS wp11.mv_owasp_coverage AS
SELECT
    atm.taxonomy_code,
    atm.taxonomy_name,
    COUNT(DISTINCT ae.attack_id) AS attack_count,
    COUNT(DISTINCT aci.component_id) AS impacted_component_count,
    COUNT(DISTINCT ae.attack_id) FILTER (WHERE pcs.base_score >= 7.0) AS high_cvss_attack_count,
    COUNT(DISTINCT ae.attack_id) FILTER (WHERE pcs.base_score >= 9.0) AS critical_cvss_attack_count,
    MAX(pcs.base_score) AS max_primary_cvss_score,
    AVG(pcs.base_score) FILTER (WHERE pcs.base_score IS NOT NULL) AS avg_primary_cvss_score,
    MAX(ae.last_seen_at) AS latest_seen_at
FROM wp11.attack_taxonomy_map atm
JOIN wp11.attack_entry ae
    ON ae.attack_id = atm.attack_id
LEFT JOIN wp11.v_primary_cvss_score pcs
    ON pcs.attack_id = ae.attack_id
LEFT JOIN wp11.attack_component_impact aci
    ON aci.attack_id = ae.attack_id
WHERE atm.taxonomy_type = 'OWASP_LLM'
GROUP BY atm.taxonomy_code, atm.taxonomy_name
WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_owasp_coverage_taxonomy_code
    ON wp11.mv_owasp_coverage (taxonomy_code);

-- =====================================
-- 6. 注释（可选，但建议保留）
-- =====================================
COMMENT ON SCHEMA wp11 IS 'WP1-1 情报采集智能体数据库模式：以攻击情报为核心，面向 AI BOM 适配与 WP1-2/WP1-3 消费';
COMMENT ON TABLE wp11.attack_entry IS '标准化攻击情报主表，是 WP1-1 的核心知识对象';
COMMENT ON TABLE wp11.attack_cvss_assessment IS '攻击条目的 CVSS 评分表，兼容 supplied/calculated/estimated/manual 多来源';
COMMENT ON TABLE wp11.attack_component_impact IS '攻击与 AI BOM 组件之间的影响映射表';
COMMENT ON VIEW wp11.v_primary_cvss_score IS '每个攻击条目当前对外发布的主 CVSS 评分';
COMMENT ON VIEW wp11.v_wp12_attack_feed IS '面向 WP1-2 的攻击投喂视图';
COMMENT ON VIEW wp11.v_component_risk_overview IS '按 AI BOM 组件聚合的风险总览';
COMMENT ON VIEW wp11.v_unresolved_bom_queue IS '未解析 AI BOM 组件复核队列';
COMMENT ON VIEW wp11.v_source_quality_dashboard IS '采集来源质量看板';
COMMENT ON MATERIALIZED VIEW wp11.mv_owasp_coverage IS '按 OWASP LLM 分类预聚合的攻击覆盖率与暴露面统计';
COMMENT ON TABLE wp11.attack_component_mention IS 'AI BOM mention extraction table';
COMMENT ON TABLE wp11.stix_bundle IS 'STIX 2.1 bundle source-of-truth table';
COMMENT ON TABLE wp11.stix_object IS 'STIX 2.1 object table with normalized projections and raw payload';
COMMENT ON VIEW wp11.v_wp12_attack_execution_feed IS 'Execution-oriented WP1-2 feed with published STIX graph and accepted AI BOM impacts';
