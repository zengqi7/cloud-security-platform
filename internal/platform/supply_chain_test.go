package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFreshnessAtEvaluationAndRequiredTrust(t *testing.T) {
	now := time.Now().UTC()
	updated := now.Add(-48*time.Hour + 2*time.Minute)
	j := Job{Status: "succeeded", PolicyDigest: DefaultPolicy().Digest(), Request: Request{Kind: "image"}, Policy: ptrPolicy(), Evidence: &ScanEvidence{Complete: true, DBUpdatedAt: &updated}}
	if summarizeAt(j, now).Gate != "pass" {
		t.Fatal("fresh evidence rejected")
	}
	if summarizeAt(j, now.Add(3*time.Minute)).Gate != "error" {
		t.Fatal("stale evidence passed")
	}
	j.Trust = &TrustPolicy{Mode: "key", KeyDigest: "trusted"}
	if summarizeAt(j, now).Gate != "error" {
		t.Fatal("missing signature passed")
	}
	j.Evidence.SupplyChain = &SupplyChainEvidence{PolicyDigest: j.Trust.Digest(), SignatureVerified: true}
	if summarizeAt(j, now).Gate != "pass" {
		t.Fatal("valid trust rejected")
	}
	j.Trust.Builder = "trusted-builder"
	if summarizeAt(j, now).Gate != "error" {
		t.Fatal("missing provenance passed")
	}
	future := now.Add(time.Hour)
	j.Evidence.DBUpdatedAt = &future
	if _, fresh := evidenceDeadline(j, now); fresh {
		t.Fatal("future metadata accepted")
	}
}
func ptrPolicy() *PolicyBundle { b := DefaultPolicy(); return &b }
func TestProvenanceRequiresVerifiedEnvelopeDigestAndBuilder(t *testing.T) {
	digest := strings.Repeat("a", 64)
	target := "registry/app@sha256:" + digest
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"digest":{"sha256":"` + digest + `"}}],"predicate":{"runDetails":{"builder":{"id":"trusted"}}}}`)
	envelope, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(payload)})
	if err := checkProvenance(envelope, target, "trusted"); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		raw             []byte
		target, builder string
	}{{envelope, target, "other"}, {envelope, "app@sha256:" + strings.Repeat("b", 64), "trusted"}, {payload, target, "trusted"}, {[]byte(`{}`), target, "trusted"}, {append(envelope, []byte("garbage")...), target, "trusted"}} {
		if checkProvenance(input.raw, input.target, input.builder) == nil {
			t.Fatal("invalid provenance accepted")
		}
	}
}
func TestRealCosignVerification(t *testing.T) {
	target := os.Getenv("COSIGN_INTEGRATION_TARGET")
	if target == "" {
		t.Skip("explicit signed digest and operator trust policy required")
	}
	p, err := loadTrustPolicy()
	if err != nil || p.Mode == "disabled" {
		t.Fatal("enabled policy required", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	evidence, err := verifySupplyChain(ctx, target, p)
	if os.Getenv("COSIGN_EXPECT_REJECT") == "true" {
		if err == nil {
			t.Fatal("untrusted artifact passed")
		}
		return
	}
	if err != nil || evidence == nil || !evidence.SignatureVerified {
		t.Fatal("real verification failed", err)
	}
}
