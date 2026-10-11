CREATE TABLE assets (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 tenant VARCHAR(64) COLLATE utf8mb4_0900_bin NOT NULL,
 kind VARCHAR(32) NOT NULL,
 identity VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uk_asset_identity(tenant,kind,identity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE scan_series (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 asset_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 name VARCHAR(128) COLLATE utf8mb4_0900_bin NOT NULL,
 UNIQUE KEY uk_asset_series(asset_id,name),
 FOREIGN KEY(asset_id) REFERENCES assets(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
ALTER TABLE scan_jobs
 ADD COLUMN asset_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
 ADD COLUMN series_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
 ADD COLUMN scope_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'legacy-unknown',
 ADD COLUMN evidence_json JSON NULL,
 ADD COLUMN sbom_json JSON NULL,
 ADD KEY idx_scan_series(series_id,created_at,id),
 ADD FOREIGN KEY(asset_id) REFERENCES assets(id),
 ADD FOREIGN KEY(series_id) REFERENCES scan_series(id);
