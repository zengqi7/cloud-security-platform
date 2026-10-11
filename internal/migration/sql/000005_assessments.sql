CREATE TABLE governance_locks (
 tenant VARCHAR(64) COLLATE utf8mb4_0900_bin PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE finding_waivers (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 tenant VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
 scan_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 fingerprint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 requested_by VARCHAR(128) NOT NULL,
 reason VARCHAR(1024) NOT NULL,
 expires_at DATETIME(3) NOT NULL,
 state VARCHAR(16) NOT NULL DEFAULT 'pending',
 decided_by VARCHAR(128) NULL,
 decision_reason VARCHAR(1024) NULL,
 decided_at DATETIME(3) NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 KEY idx_waiver_lookup(tenant,scan_id,state,expires_at),
 FOREIGN KEY(scan_id,fingerprint) REFERENCES scan_findings(scan_id,fingerprint)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE gate_assessments (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 tenant VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
 scan_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 idempotency_key VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL,
 assessment_json JSON NOT NULL,
 assessed_at DATETIME(3) NOT NULL,
 UNIQUE KEY uk_assessment_request(tenant,idempotency_key),
 KEY idx_assessment_scan(tenant,scan_id,assessed_at),
 FOREIGN KEY(scan_id) REFERENCES scan_jobs(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TRIGGER assessment_no_update BEFORE UPDATE ON gate_assessments FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='assessment is immutable';
CREATE TRIGGER assessment_no_delete BEFORE DELETE ON gate_assessments FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='assessment is immutable';
