CREATE TABLE policy_bundles (
 tenant VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
 digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 version VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
 bundle_json JSON NOT NULL,
 published_by VARCHAR(128) NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 PRIMARY KEY(tenant,digest), UNIQUE KEY uk_policy_version(tenant,version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TRIGGER policy_no_update BEFORE UPDATE ON policy_bundles FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='policy bundle is immutable';
CREATE TRIGGER policy_no_delete BEFORE DELETE ON policy_bundles FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='policy bundle is immutable';
ALTER TABLE scan_jobs ADD COLUMN policy_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'legacy-unknown';
