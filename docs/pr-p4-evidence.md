Archive Trivy/Cosign verification artifacts with digest/size references and an
authenticated evidence retrieval endpoint. New trust snapshots bind verifier,
artifact digest, verification age and operator epoch; support public key-ring
rotation and explicit key/policy hash revocation without modifying history.

Production can require object archival; existing SQL-only deployments remain
compatible. Assessments use the earlier vulnerability-DB/signature expiry.
Tests cover digest substitution, expiry, trust epoch and signer revocation;
live Sigstore/keyless/rotation fixtures remain an explicit staging gate.
