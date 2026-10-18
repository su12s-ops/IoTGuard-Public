-- Official advisory snapshots are evidence, separate from operational matches.
CREATE TABLE IF NOT EXISTS iot_official_advisory (
    id INTEGER PRIMARY KEY,
    ecosystem VARCHAR(32) NOT NULL,
    advisory_id VARCHAR(64) NOT NULL,
    source_url TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    content_sha256 VARCHAR(64) NOT NULL,
    updated_at DATETIME,
    CONSTRAINT uq_iot_official_advisory_ecosystem_id UNIQUE (ecosystem, advisory_id)
);
CREATE INDEX IF NOT EXISTS ix_iot_official_advisory_ecosystem
    ON iot_official_advisory (ecosystem);
