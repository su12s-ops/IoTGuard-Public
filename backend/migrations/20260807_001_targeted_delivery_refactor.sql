-- LinuxGuard targeted delivery refactor (SQLite baseline migration)
-- Applied idempotently by app.database._migrate_sqlite_schema for deployed DBs.

ALTER TABLE vulnerability_match ADD COLUMN match_status VARCHAR(32) DEFAULT 'unknown';
ALTER TABLE vulnerability_match ADD COLUMN reason_code VARCHAR(64) DEFAULT 'unknown';
ALTER TABLE vulnerability_match ADD COLUMN evidence_fingerprint VARCHAR(64) DEFAULT '';
ALTER TABLE vulnerability_match ADD COLUMN active BOOLEAN DEFAULT 1;
ALTER TABLE vulnerability_match ADD COLUMN updated_at DATETIME;

ALTER TABLE risk_assessment ADD COLUMN match_id INTEGER REFERENCES vulnerability_match(id);
ALTER TABLE risk_assessment ADD COLUMN package_name VARCHAR(128) DEFAULT '';
ALTER TABLE risk_assessment ADD COLUMN candidate_fingerprint VARCHAR(64) DEFAULT '';
ALTER TABLE risk_assessment ADD COLUMN active BOOLEAN DEFAULT 1;
ALTER TABLE risk_assessment ADD COLUMN evidence_packet_json TEXT DEFAULT '{}';
ALTER TABLE risk_assessment ADD COLUMN agent_results_json TEXT DEFAULT '{}';
ALTER TABLE risk_assessment ADD COLUMN conflict_result_json TEXT DEFAULT '{}';
ALTER TABLE risk_assessment ADD COLUMN audit_policy_reasons TEXT DEFAULT '[]';
ALTER TABLE risk_assessment ADD COLUMN recommended_priority VARCHAR(32) DEFAULT '';
ALTER TABLE risk_assessment ADD COLUMN recommended_action VARCHAR(64) DEFAULT '';
ALTER TABLE risk_assessment ADD COLUMN risk_direction VARCHAR(32) DEFAULT 'maintain';
ALTER TABLE risk_assessment ADD COLUMN reanalysis_count INTEGER DEFAULT 0;
ALTER TABLE risk_assessment ADD COLUMN updated_at DATETIME;

ALTER TABLE remediation_task ADD COLUMN risk_id INTEGER REFERENCES risk_assessment(id);

CREATE TABLE agent_audit_record (
    id INTEGER PRIMARY KEY,
    run_id VARCHAR(32) DEFAULT '',
    risk_id INTEGER NOT NULL REFERENCES risk_assessment(id),
    object_id VARCHAR(64) NOT NULL,
    agent_name VARCHAR(64) NOT NULL,
    model VARCHAR(128) DEFAULT '',
    evidence_ids_json TEXT DEFAULT '[]',
    structured_output_json TEXT DEFAULT '{}',
    raw_response TEXT DEFAULT '',
    parse_status VARCHAR(32) DEFAULT 'pending',
    retry_count INTEGER DEFAULT 0,
    latency_ms INTEGER DEFAULT 0,
    error TEXT DEFAULT '',
    created_at DATETIME
);

-- Backfill only unambiguous historical links. Ambiguous asset+CVE rows are
-- deliberately left for reanalysis instead of choosing an arbitrary match.
UPDATE risk_assessment
SET match_id = (
        SELECT MIN(vm.id) FROM vulnerability_match vm
        WHERE vm.asset_id = risk_assessment.asset_id
          AND vm.cve_id = risk_assessment.cve_id
    ),
    package_name = COALESCE((
        SELECT MIN(vm.package_name) FROM vulnerability_match vm
        WHERE vm.asset_id = risk_assessment.asset_id
          AND vm.cve_id = risk_assessment.cve_id
    ), '')
WHERE match_id IS NULL
  AND 1 = (
      SELECT COUNT(*) FROM vulnerability_match vm
      WHERE vm.asset_id = risk_assessment.asset_id
        AND vm.cve_id = risk_assessment.cve_id
  );

UPDATE risk_assessment
SET review_status = 'reanalysis_required',
    human_review_required = 1,
    review_reason = 'legacy_match_link_ambiguous'
WHERE match_id IS NULL
  AND 1 < (
      SELECT COUNT(*) FROM vulnerability_match vm
      WHERE vm.asset_id = risk_assessment.asset_id
        AND vm.cve_id = risk_assessment.cve_id
  );

-- Legacy automatic conclusions do not retain authority for High/Critical or
-- critical/core assets under the new deterministic backend audit policy.
UPDATE risk_assessment
SET review_status = 'pending_human_review',
    human_review_required = 1,
    final_score = NULL,
    risk_level = NULL,
    decision = NULL,
    audit_policy_reasons = '["migrated_high_risk_requires_human_review"]',
    review_reason = CASE
        WHEN COALESCE(review_reason, '') = '' THEN 'migrated_auto_confirmation_requires_human_review'
        ELSE review_reason || ' [migrated_auto_confirmation_requires_human_review]'
    END
WHERE review_status IN ('completed', 'auto_confirmed')
  AND (
      UPPER(COALESCE(risk_level, '')) IN ('HIGH', 'CRITICAL')
      OR UPPER(COALESCE(preliminary_level, '')) IN ('HIGH', 'CRITICAL')
      OR asset_id IN (
          SELECT id FROM linux_asset
          WHERE LOWER(COALESCE(business_level, '')) IN ('core', 'critical')
      )
  );

UPDATE remediation_task
SET status = 'blocked'
WHERE risk_id IN (
    SELECT id FROM risk_assessment
    WHERE review_status = 'pending_human_review'
      AND audit_policy_reasons = '["migrated_high_risk_requires_human_review"]'
)
  AND status NOT IN ('verified', 'resolved');

CREATE UNIQUE INDEX uq_vulnerability_match_active_event
ON vulnerability_match(asset_id, cve_id, package_name) WHERE active = 1;

CREATE UNIQUE INDEX uq_risk_assessment_active_match
ON risk_assessment(match_id) WHERE active = 1 AND match_id IS NOT NULL;
