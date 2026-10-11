ALTER TABLE scan_jobs ADD COLUMN summary_json JSON NULL, ADD KEY idx_scan_tenant_time(tenant,created_at,id);
CREATE TABLE scan_findings (
 scan_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 fingerprint VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 severity VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 finding_json JSON NOT NULL,
 PRIMARY KEY(scan_id,fingerprint),
 KEY idx_finding_severity(scan_id,severity,fingerprint),
 CONSTRAINT fk_finding_scan FOREIGN KEY(scan_id) REFERENCES scan_jobs(id)
) ENGINE=InnoDB;
INSERT INTO scan_findings(scan_id,fingerprint,severity,finding_json)
SELECT j.id,f.fingerprint,f.severity,f.finding FROM scan_jobs j JOIN JSON_TABLE(j.findings_json,'$[*]' COLUMNS(fingerprint VARCHAR(128) PATH '$.fingerprint' ERROR ON EMPTY,severity VARCHAR(16) PATH '$.severity' ERROR ON EMPTY,finding JSON PATH '$')) f;
UPDATE scan_jobs j LEFT JOIN (SELECT scan_id,SUM(severity='CRITICAL') c,SUM(severity='HIGH') h,SUM(severity='MEDIUM') m,SUM(severity='LOW') l,SUM(severity='UNKNOWN') u FROM scan_findings GROUP BY scan_id) f ON f.scan_id=j.id
SET summary_json=JSON_OBJECT('counts',JSON_OBJECT('CRITICAL',COALESCE(c,0),'HIGH',COALESCE(h,0),'MEDIUM',COALESCE(m,0),'LOW',COALESCE(l,0),'UNKNOWN',COALESCE(u,0)),'gate',CASE WHEN status='failed' THEN 'error' WHEN status<>'succeeded' THEN 'pending' WHEN COALESCE(u,0)>0 THEN 'error' WHEN COALESCE(c,0)+COALESCE(h,0)>0 THEN 'block' ELSE 'pass' END,'reason','migrated original scan assessment');
