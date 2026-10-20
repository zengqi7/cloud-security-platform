CREATE TABLE evidence_objects (
  tenant VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL,
  scan_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  lease_token CHAR(32) NOT NULL,
  kind VARCHAR(32) NOT NULL,
  object_key VARCHAR(512) NOT NULL,
  digest CHAR(71) NOT NULL,
  size_bytes BIGINT NOT NULL,
  linked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (tenant,scan_id,lease_token,kind),
  KEY idx_evidence_gc (linked,created_at),
  CONSTRAINT fk_evidence_scan FOREIGN KEY (scan_id) REFERENCES scan_jobs(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
