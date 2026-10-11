ALTER TABLE scan_jobs ADD COLUMN trust_json JSON NULL;
CREATE TABLE rescan_schedules (
 id CHAR(32) PRIMARY KEY,
 tenant VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL,
 source_scan_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_json JSON NOT NULL,
 trust_json JSON NOT NULL,
 interval_seconds INT NOT NULL,
 next_run_at DATETIME(3) NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 key_id BIGINT UNSIGNED NOT NULL,
 subject VARCHAR(128) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 KEY idx_rescan_due(enabled,next_run_at,id),
 FOREIGN KEY(source_scan_id) REFERENCES scan_jobs(id),
 FOREIGN KEY(key_id) REFERENCES scan_api_keys(id)
) ENGINE=InnoDB;
