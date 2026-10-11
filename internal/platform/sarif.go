package platform

import "sort"

// SARIF uses logical resource locations when no trustworthy source map is available.
func SARIF(job Job, findings []Finding) map[string]any {
	unique := map[string]bool{}
	for _, f := range findings {
		unique[f.RuleID] = true
	}
	ids := make([]string, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := []map[string]any{}
	indexes := map[string]int{}
	for i, id := range ids {
		indexes[id] = i
		rules = append(rules, map[string]any{"id": id, "name": id})
	}
	results := []map[string]any{}
	for _, f := range findings {
		level := "note"
		if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
			level = "error"
		} else if f.Severity == "MEDIUM" || f.Severity == "UNKNOWN" {
			level = "warning"
		}
		results = append(results, map[string]any{"ruleId": f.RuleID, "ruleIndex": indexes[f.RuleID], "level": level, "message": map[string]string{"text": f.Title + ". " + f.Recommendation}, "partialFingerprints": map[string]string{"cloudguard/v1": f.Fingerprint}, "locations": []any{map[string]any{"logicalLocations": []any{map[string]string{"fullyQualifiedName": f.Resource, "kind": "resource"}}}}, "properties": map[string]string{"severity": f.Severity, "package": f.Package, "installedVersion": f.InstalledVersion, "fixedVersion": f.FixedVersion}})
	}
	summary := Summarize(job)
	return map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "CloudGuard", "informationUri": "https://github.com/zengqi7/cloud-security-platform", "rules": rules}}, "results": results, "invocations": []any{map[string]any{"executionSuccessful": job.Status == "succeeded", "properties": map[string]string{"scanId": job.ID, "gate": summary.Gate, "gateReason": summary.Reason, "evidenceSource": job.EvidenceSource}}}}}}
}
