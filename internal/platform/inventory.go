package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

func registerAsset(ctx context.Context, tx *sql.Tx, tenant string, r Request, policy string) (string, string, string, error) {
	identity := r.Asset
	if identity == "" {
		identity = r.Target
	}
	series := r.Series
	if series == "" {
		series = "default"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO assets(id,tenant,kind,identity) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE id=assets.id`, NewID(), tenant, r.Kind, identity)
	if err != nil {
		return "", "", "", err
	}
	var assetID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant=? AND kind=? AND identity=?`, tenant, r.Kind, identity).Scan(&assetID); err != nil {
		return "", "", "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scan_series(id,asset_id,name) VALUES(?,?,?) ON DUPLICATE KEY UPDATE id=scan_series.id`, NewID(), assetID, series); err != nil {
		return "", "", "", err
	}
	var seriesID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM scan_series WHERE asset_id=? AND name=?`, assetID, series).Scan(&seriesID); err != nil {
		return "", "", "", err
	}
	coverage := []string{}
	if r.Kind == "manifest" {
		input, err := PolicyInput(r.Manifest)
		if err != nil {
			return "", "", "", err
		}
		for _, w := range input["workloads"].([]map[string]any) {
			for _, raw := range w["containers"].([]any) {
				c := raw.(map[string]any)
				name, _ := c["name"].(string)
				coverage = append(coverage, w["resource"].(string)+"/"+name)
			}
		}
		sort.Strings(coverage)
	}
	raw, _ := json.Marshal([]any{r.Kind, policy, scanProfile(r.Kind), coverage})
	return assetID, seriesID, hashBytes(raw), nil
}

type RiskDiff struct {
	Base          string    `json:"base"`
	Current       string    `json:"current"`
	Comparable    bool      `json:"comparable"`
	Reason        string    `json:"reason"`
	New           []Finding `json:"new"`
	Retained      []Finding `json:"retained"`
	Resolved      []Finding `json:"resolved"`
	PossiblyFixed []Finding `json:"possibly_fixed"`
}

func findingIdentity(f Finding) string {
	raw, _ := json.Marshal([]string{f.RuleID, f.Resource, f.Package})
	return hashBytes(raw)
}
func CompareScans(base, current Job, old, new []Finding) RiskDiff {
	d := RiskDiff{Base: base.ID, Current: current.ID, New: []Finding{}, Retained: []Finding{}, Resolved: []Finding{}, PossiblyFixed: []Finding{}}
	switch {
	case base.Tenant != current.Tenant || base.AssetID == "" || base.AssetID != current.AssetID || base.SeriesID == "" || base.SeriesID != current.SeriesID:
		d.Reason = "different or missing asset/series"
	case base.Status != "succeeded" || current.Status != "succeeded":
		d.Reason = "both scans must succeed"
	case base.Evidence == nil || current.Evidence == nil || !base.Evidence.Complete || !current.Evidence.Complete:
		d.Reason = "incomplete or unverified scan evidence"
	case base.ScopeHash != current.ScopeHash || base.Evidence.Profile != current.Evidence.Profile || base.Evidence.Tool != current.Evidence.Tool || base.Evidence.ToolVersion != current.Evidence.ToolVersion:
		d.Reason = "policy, scanner version or scope differs"
	case base.FinishedAt == nil || current.FinishedAt == nil || !current.CreatedAt.After(base.CreatedAt) || !current.FinishedAt.After(*base.FinishedAt):
		d.Reason = "scan order is not strictly increasing"
	default:
		d.Comparable = true
		d.Reason = "same asset/series, policy and complete scan profile"
	}
	if !d.Comparable {
		return d
	}
	for _, items := range [][]Finding{old, new} {
		for _, f := range items {
			if f.Severity == "UNKNOWN" {
				d.Comparable = false
				d.Reason = "unknown finding severity"
				return d
			}
		}
	}
	prior := map[string]Finding{}
	present := map[string]bool{}
	for _, f := range old {
		prior[findingIdentity(f)] = f
	}
	for _, f := range new {
		id := findingIdentity(f)
		present[id] = true
		if _, ok := prior[id]; ok {
			d.Retained = append(d.Retained, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for id, f := range prior {
		if present[id] {
			continue
		}
		d.Resolved = append(d.Resolved, f)
		if base.Request.Kind == "image" && base.Evidence.ArtifactDigest != current.Evidence.ArtifactDigest {
			d.PossiblyFixed = append(d.PossiblyFixed, f)
		}
	}
	for _, items := range [][]Finding{d.New, d.Retained, d.Resolved, d.PossiblyFixed} {
		sort.Slice(items, func(i, j int) bool { return items[i].Fingerprint < items[j].Fingerprint })
	}
	return d
}
func (s Store) allFindings(ctx context.Context, tenant, id string) ([]Finding, error) {
	if _, err := s.Get(ctx, tenant, id); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT finding_json FROM scan_findings WHERE scan_id=? ORDER BY fingerprint`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Finding{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var f Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		items = append(items, f)
	}
	return items, rows.Err()
}
func (s Store) Diff(ctx context.Context, tenant, base, current string) (RiskDiff, error) {
	a, err := s.Get(ctx, tenant, base)
	if err != nil {
		return RiskDiff{}, err
	}
	b, err := s.Get(ctx, tenant, current)
	if err != nil {
		return RiskDiff{}, err
	}
	old, err := s.allFindings(ctx, tenant, base)
	if err != nil {
		return RiskDiff{}, err
	}
	new, err := s.allFindings(ctx, tenant, current)
	if err != nil {
		return RiskDiff{}, err
	}
	return CompareScans(a, b, old, new), nil
}
func (s Store) SBOM(ctx context.Context, tenant, id string) (json.RawMessage, error) {
	j, err := s.Get(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	var raw []byte
	raw, err = s.readObject(ctx, tenant, id, "sbom")
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, ErrNotFound) {
		if err := s.DB.QueryRowContext(ctx, `SELECT sbom_json FROM scan_jobs WHERE tenant=? AND id=?`, tenant, id).Scan(&raw); err != nil {
			return nil, err
		}
	}
	if len(raw) == 0 {
		return nil, ErrNotFound
	}
	var canonical any
	if err := json.Unmarshal(raw, &canonical); err != nil {
		return nil, err
	}
	raw, err = json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	if j.Evidence == nil || j.Evidence.SBOMDigest != "sha256:"+hashBytes(raw) {
		return nil, ErrState
	}
	return raw, nil
}
