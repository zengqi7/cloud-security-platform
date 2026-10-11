CREATE TABLE IF NOT EXISTS scan_jobs (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 tenant VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
 idempotency_key VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL,
 request_hash CHAR(64) NOT NULL,
 request_json JSON NOT NULL,
 status VARCHAR(16) NOT NULL DEFAULT 'queued',
 attempts INT NOT NULL DEFAULT 0,
 error_text TEXT NULL,
 findings_json JSON NOT NULL,
 lease_token CHAR(32) NULL,
 lease_until DATETIME(3) NULL,
 next_attempt_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 finished_at DATETIME(3) NULL,
 UNIQUE KEY uk_tenant_idempotency(tenant,idempotency_key),
 KEY idx_scan_queue(status,next_attempt_at),
 KEY idx_scan_lease(status,lease_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
