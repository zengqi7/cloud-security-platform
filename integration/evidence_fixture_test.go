//go:build integration

package integration

import (
	"cloud-security-platform/internal/platform"
	"context"
	"time"
)

// Synthetic worker evidence only for deterministic storage/state-machine tests.
// Real tool and artifact confirmation is tested separately with ToolScanner.
func finishFixture(ctx context.Context, s platform.Store, j platform.Job, findings []platform.Finding) error {
	profile := "image:vuln-os-library:v1"
	if j.Request.Kind == "manifest" {
		profile = "k8s-workloads:rego:v1"
	}
	now := time.Now().UTC()
	return s.FinishEvidence(ctx, j, platform.ScanResult{Findings: findings, Evidence: &platform.ScanEvidence{DBUpdatedAt: &now, Tool: "fixture-scanner", ToolVersion: "1", Profile: profile, ArtifactDigest: "sha256:" + platform.RequestHash(j.Request), Complete: true, CapturedAt: now}}, nil)
}
