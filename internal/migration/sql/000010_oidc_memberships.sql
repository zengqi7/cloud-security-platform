CREATE TABLE oidc_memberships (
 issuer_hash CHAR(64) NOT NULL,
 subject_hash CHAR(64) NOT NULL,
 issuer VARCHAR(512) NOT NULL,
 oidc_subject VARCHAR(512) NOT NULL,
 tenant VARCHAR(64) NOT NULL,
 scopes_json JSON NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT TRUE,
 expires_at DATETIME(3) NOT NULL,
 updated_by VARCHAR(128) NOT NULL,
 updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 PRIMARY KEY (issuer_hash,subject_hash)
);
