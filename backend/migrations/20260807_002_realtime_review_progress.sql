-- LinuxGuard delivery migration 002
-- Apply once to databases created before real-time review progress was added.
ALTER TABLE analysis_report ADD COLUMN progress_percent INTEGER DEFAULT 0;
ALTER TABLE analysis_report ADD COLUMN current_object_id VARCHAR(64) DEFAULT '';
ALTER TABLE analysis_report ADD COLUMN progress_message TEXT DEFAULT '';
ALTER TABLE analysis_report ADD COLUMN progress_sequence INTEGER DEFAULT 0;
ALTER TABLE analysis_report ADD COLUMN progress_updated_at DATETIME;
