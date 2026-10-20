package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const evidenceMaxAge = 48 * time.Hour
const slsaPredicate = "https://slsa.dev/provenance/v1"

// Only operator configuration supplies trust requirements, never request JSON.
type TrustPolicy struct {
	Version       int    `json:"version,omitempty"`
	Epoch         string `json:"epoch,omitempty"`
	MaxAgeSeconds int    `json:"max_age_seconds,omitempty"`
	Mode          string `json:"mode"`
	KeyDigest     string `json:"key_digest,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	Builder       string `json:"builder,omitempty"`
}
type SupplyChainEvidence struct {
	ArtifactDigest        string `json:"artifact_digest,omitempty"`
	Verifier              string `json:"verifier,omitempty"`
	signature, provenance json.RawMessage
	PolicyDigest          string    `json:"policy_digest"`
	SignatureVerified     bool      `json:"signature_verified"`
	ProvenanceVerified    bool      `json:"provenance_verified"`
	VerifiedAt            time.Time `json:"verified_at"`
	SignatureDigest       string    `json:"signature_digest"`
	ProvenanceDigest      string    `json:"provenance_digest,omitempty"`
}

func (p TrustPolicy) Digest() string { raw, _ := json.Marshal(p); return hashBytes(raw) }
func loadTrustPolicy() (TrustPolicy, error) {
	p := TrustPolicy{Mode: os.Getenv("SUPPLY_CHAIN_MODE"), Identity: os.Getenv("COSIGN_IDENTITY"), Issuer: os.Getenv("COSIGN_ISSUER"), Builder: os.Getenv("SLSA_BUILDER_ID")}
	if p.Mode == "" {
		p.Mode = "disabled"
	}
	p.Version = 2
	p.Epoch = os.Getenv("TRUST_POLICY_EPOCH")
	p.MaxAgeSeconds = 86400
	if len(p.Epoch) > 128 {
		return p, errors.New("trust epoch exceeds 128 bytes")
	}
	if v := os.Getenv("SUPPLY_CHAIN_MAX_AGE_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 300 || n > 172800 {
			return p, errors.New("supply chain max age must be 300..172800 seconds")
		}
		p.MaxAgeSeconds = n
	}
	switch p.Mode {
	case "disabled":
		if p.Builder != "" {
			return p, errors.New("provenance requires enabled signature verification")
		}
	case "key":
		raw, err := readPublicKey(os.Getenv("COSIGN_PUBLIC_KEY"))
		if err != nil {
			return p, err
		}
		p.KeyDigest = hashBytes(raw)
		if revokedTrust(p.KeyDigest) {
			return p, errors.New("Cosign public key revoked")
		}
	case "keyless":
		if p.Identity == "" || p.Issuer == "" {
			return p, errors.New("exact Cosign identity and issuer required")
		}
	default:
		return p, errors.New("unknown supply chain mode")
	}
	return p, nil
}
func readPublicKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("operator Cosign public key unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		return nil, errors.New("invalid public key size")
	}
	return raw, nil
}
func verifySupplyChain(ctx context.Context, target string, p TrustPolicy) (*SupplyChainEvidence, error) {
	if p.Mode == "disabled" {
		return nil, nil
	}
	binary := os.Getenv("COSIGN_BIN")
	if binary == "" {
		binary = localTool("cosign")
	}
	args := []string{"--output", "json"}
	switch p.Mode {
	case "key":
		if revokedTrust(p.KeyDigest) {
			return nil, errors.New("Cosign public key revoked")
		}
		keyPath := os.Getenv("COSIGN_PUBLIC_KEY")
		if root := os.Getenv("COSIGN_KEYRING_DIR"); root != "" && len(p.KeyDigest) == 64 && hashHex.MatchString(p.KeyDigest) {
			keyPath = filepath.Join(root, p.KeyDigest+".pub")
		}
		raw, err := readPublicKey(keyPath)
		if err != nil {
			return nil, err
		}
		if hashBytes(raw) != p.KeyDigest {
			return nil, errors.New("Cosign public key differs from pinned trust policy")
		}
		// Materialize the exact hashed bytes, preventing path replacement between read and verify.
		root := os.Getenv("SCAN_DATA_DIR")
		if root == "" {
			root = "data"
		}
		dir := filepath.Join(root, "work")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		f, err := os.CreateTemp(dir, "cloudguard-key-*.pub")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(raw); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		args = append(args, "--key", f.Name())
	case "keyless":
		if p.Identity == "" || p.Issuer == "" {
			return nil, errors.New("invalid pinned keyless policy")
		}
		args = append(args, "--certificate-identity", p.Identity, "--certificate-oidc-issuer", p.Issuer)
	default:
		return nil, errors.New("unknown trust policy")
	}
	raw, err := runTool(ctx, nil, binary, append([]string{"verify"}, append(args, "--", target)...)...)
	if err != nil {
		return nil, errors.New("Cosign signature verification failed or unavailable")
	}
	var signatures []json.RawMessage
	if json.Unmarshal(raw, &signatures) != nil || len(signatures) == 0 {
		return nil, errors.New("empty signature verification evidence")
	}
	match := imageDigest.FindStringSubmatch(target)
	if match == nil {
		return nil, errors.New("signature target must be digest pinned")
	}
	version, err := runTool(ctx, nil, binary, "version", "--json")
	if err != nil {
		return nil, errors.New("Cosign verifier version unavailable")
	}
	var verifier struct {
		GitVersion string `json:"gitVersion"`
	}
	if json.Unmarshal(version, &verifier) != nil || verifier.GitVersion == "" {
		return nil, errors.New("invalid Cosign verifier version")
	}
	e := &SupplyChainEvidence{ArtifactDigest: "sha256:" + match[1], Verifier: "cosign/" + verifier.GitVersion, signature: append([]byte(nil), raw...), PolicyDigest: p.Digest(), SignatureVerified: true, SignatureDigest: hashBytes(raw), VerifiedAt: time.Now().UTC()}
	if p.Builder != "" {
		raw, err = runTool(ctx, nil, binary, append([]string{"verify-attestation"}, append(args, "--type", "slsaprovenance1", "--", target)...)...)
		if err != nil {
			return nil, errors.New("Cosign provenance verification failed or unavailable")
		}
		if err := checkProvenance(raw, target, p.Builder); err != nil {
			return nil, err
		}
		// Archive a valid JSON array even when Cosign emits a JSON value stream.
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		envelopes := []json.RawMessage{}
		for {
			var envelope json.RawMessage
			err := dec.Decode(&envelope)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, errors.New("invalid provenance evidence stream")
			}
			envelopes = append(envelopes, envelope)
		}
		raw, err = json.Marshal(envelopes)
		if err != nil {
			return nil, err
		}
		e.ProvenanceVerified = true
		e.ProvenanceDigest = hashBytes(raw)
		e.provenance = append([]byte(nil), raw...)
	}
	return e, nil
}

// Cosign emits one verified DSSE envelope per JSON value, not a trusted user report.
func checkProvenance(raw []byte, target, builder string) error {
	match := imageDigest.FindStringSubmatch(target)
	if match == nil {
		return errors.New("provenance target must be digest pinned")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	valid := false
	for {
		var envelope struct {
			Payload string `json:"payload"`
		}
		err := dec.Decode(&envelope)
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("invalid verified attestation envelope")
		}
		payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return errors.New("invalid attestation payload")
		}
		var statement struct {
			Type          string `json:"_type"`
			PredicateType string `json:"predicateType"`
			Subject       []struct {
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
			Predicate struct {
				RunDetails struct {
					Builder struct {
						ID string `json:"id"`
					} `json:"builder"`
				} `json:"runDetails"`
			} `json:"predicate"`
		}
		if json.Unmarshal(payload, &statement) != nil {
			return errors.New("invalid provenance statement")
		}
		if statement.Type != "https://in-toto.io/Statement/v1" || statement.PredicateType != slsaPredicate || statement.Predicate.RunDetails.Builder.ID != builder {
			continue
		}
		for _, s := range statement.Subject {
			if s.Digest["sha256"] == match[1] {
				valid = true
			}
		}
	}
	if !valid {
		return errors.New("no verified SLSA v1 statement matched digest and trusted builder")
	}
	return nil
}
func evidenceDeadline(j Job, now time.Time) (time.Time, bool) {
	if j.Request.Kind != "image" {
		return time.Time{}, true
	}
	e := j.Evidence
	if e == nil || e.DBUpdatedAt == nil || e.DBUpdatedAt.IsZero() || e.DBUpdatedAt.After(now.Add(5*time.Minute)) {
		return time.Time{}, false
	}
	deadline := e.DBUpdatedAt.Add(evidenceMaxAge)
	if j.Trust != nil && j.Trust.Version >= 2 && j.Trust.Mode != "disabled" {
		if e.SupplyChain == nil || e.SupplyChain.VerifiedAt.IsZero() || e.SupplyChain.VerifiedAt.After(now.Add(5*time.Minute)) || j.Trust.MaxAgeSeconds < 300 {
			return time.Time{}, false
		}
		trustDeadline := e.SupplyChain.VerifiedAt.Add(time.Duration(j.Trust.MaxAgeSeconds) * time.Second)
		if trustDeadline.Before(deadline) {
			deadline = trustDeadline
		}
	}
	return deadline, deadline.After(now)
}
func supplyChainValid(j Job) bool {
	if j.Request.Kind != "image" || j.Trust == nil || j.Trust.Mode == "disabled" {
		return true
	}
	if j.Evidence == nil || j.Evidence.SupplyChain == nil {
		return false
	}
	e := j.Evidence.SupplyChain
	if j.Trust.Version >= 2 {
		match := imageDigest.FindStringSubmatch(j.Request.Target)
		if match == nil || e.ArtifactDigest != "sha256:"+match[1] || j.Evidence.ArtifactDigest != e.ArtifactDigest || e.Verifier == "" || !hashHex.MatchString(e.SignatureDigest) {
			return false
		}
		if revokedTrust(j.Trust.KeyDigest) || revokedTrust(j.Trust.Digest()) {
			return false
		}
		if epoch := os.Getenv("TRUST_POLICY_EPOCH"); epoch != "" && j.Trust.Epoch != epoch {
			return false
		}
		if j.Trust.Builder != "" && !hashHex.MatchString(e.ProvenanceDigest) {
			return false
		}
	}
	return e.PolicyDigest == j.Trust.Digest() && e.SignatureVerified && (j.Trust.Builder == "" || e.ProvenanceVerified)
}

func revokedTrust(digest string) bool {
	if digest == "" {
		return false
	}
	for _, v := range strings.Split(os.Getenv("TRUST_REVOKED_DIGESTS"), ",") {
		if strings.TrimSpace(v) == digest {
			return true
		}
	}
	return false
}
