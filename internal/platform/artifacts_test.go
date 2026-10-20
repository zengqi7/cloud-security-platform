package platform

import (
	"strings"
	"testing"
	"time"
)

func TestVersionedTrustBindingFreshnessAndRevocation(t *testing.T) {
	now := time.Now().UTC()
	dbTime := now.Add(-time.Hour)
	target := "registry.example/app@sha256:" + strings.Repeat("a", 64)
	p := &TrustPolicy{Version: 2, Epoch: "one", Mode: "key", KeyDigest: strings.Repeat("b", 64), MaxAgeSeconds: 600}
	e := &ScanEvidence{Complete: true, ArtifactDigest: "sha256:" + strings.Repeat("a", 64), DBUpdatedAt: &dbTime, SupplyChain: &SupplyChainEvidence{ArtifactDigest: "sha256:" + strings.Repeat("a", 64), Verifier: "cosign/test", PolicyDigest: p.Digest(), SignatureVerified: true, SignatureDigest: strings.Repeat("c", 64), VerifiedAt: now}}
	j := Job{Request: Request{Kind: "image", Target: target}, Trust: p, Evidence: e}
	if !supplyChainValid(j) {
		t.Fatal("valid versioned binding rejected")
	}
	deadline, fresh := evidenceDeadline(j, now)
	if !fresh || !deadline.Equal(now.Add(600*time.Second)) {
		t.Fatal("trust freshness not bounded")
	}
	if _, fresh := evidenceDeadline(j, now.Add(601*time.Second)); fresh {
		t.Fatal("expired signature accepted")
	}
	e.SupplyChain.ArtifactDigest = "sha256:" + strings.Repeat("d", 64)
	if supplyChainValid(j) {
		t.Fatal("cross digest signature")
	}
	e.SupplyChain.ArtifactDigest = e.ArtifactDigest
	t.Setenv("TRUST_POLICY_EPOCH", "two")
	if supplyChainValid(j) {
		t.Fatal("old trust epoch accepted")
	}
	t.Setenv("TRUST_POLICY_EPOCH", "one")
	t.Setenv("TRUST_REVOKED_DIGESTS", p.KeyDigest)
	if supplyChainValid(j) {
		t.Fatal("revoked key accepted")
	}
}
