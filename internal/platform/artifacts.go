package platform

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
)

var hashHex = regexp.MustCompile(`^[a-f0-9]{64}$`)

type ArtifactReference struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
	Size   int    `json:"size_bytes"`
}

func validArtifactKind(kind string) bool {
	switch kind {
	case "sbom", "report", "signature", "provenance":
		return true
	}
	return false
}
func (s Store) archiveArtifacts(ctx context.Context, j Job, result *ScanResult) error {
	if result.Evidence == nil {
		return errors.New("artifact evidence missing")
	}
	kinds := []string{}
	for kind := range result.Artifacts {
		if !validArtifactKind(kind) || kind == "sbom" {
			return errors.New("invalid artifact kind")
		}
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	result.Evidence.Artifacts = nil
	for _, kind := range kinds {
		raw := result.Artifacts[kind]
		if len(raw) == 0 || !json.Valid(raw) {
			return errors.New("invalid artifact JSON")
		}
		digest := "sha256:" + hashBytes(raw)
		if sc := result.Evidence.SupplyChain; sc != nil && ((kind == "signature" && digest != "sha256:"+sc.SignatureDigest) || (kind == "provenance" && digest != "sha256:"+sc.ProvenanceDigest)) {
			return errors.New("supply chain artifact digest mismatch")
		}
		if _, err := s.archive(ctx, j, kind, digest, raw); err != nil {
			return err
		}
		result.Evidence.Artifacts = append(result.Evidence.Artifacts, ArtifactReference{Kind: kind, Digest: digest, Size: len(raw)})
	}
	return nil
}
func (s Store) Artifact(ctx context.Context, tenant, id, kind string) (json.RawMessage, error) {
	if !validArtifactKind(kind) {
		return nil, ErrInvalid
	}
	if _, err := s.Get(ctx, tenant, id); err != nil {
		return nil, err
	}
	if kind == "sbom" {
		return s.SBOM(ctx, tenant, id)
	}
	return s.readObject(ctx, tenant, id, kind)
}
