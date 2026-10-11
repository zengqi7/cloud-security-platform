package platform

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestPolicyDigestCanonicalJSONAndContent(t *testing.T) {
	b := DefaultPolicy()
	b.Tests = []PolicyTest{{Manifest: json.RawMessage(`{"kind":"Pod","apiVersion":"v1"}`), ExpectedGate: "pass"}}
	original := b.Digest()
	b.Tests[0].Manifest = json.RawMessage(`{ "apiVersion":"v1", "kind":"Pod" }`)
	if b.Digest() != original {
		t.Fatal("JSON formatting changed digest")
	}
	b.Rego += "\n# new revision\n"
	if b.Digest() == original {
		t.Fatal("source not covered by digest")
	}
}
func TestPolicyValidationWithOPA(t *testing.T) {
	opa := os.Getenv("OPA_BIN")
	if opa == "" {
		t.Skip("OPA_BIN required")
	}
	safe, err := os.ReadFile("../../examples/safe-pod.json")
	if err != nil {
		t.Fatal(err)
	}
	unsafe, err := os.ReadFile("../../examples/unsafe-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	b := DefaultPolicy()
	b.Version = "tested-v1"
	b.Tests = []PolicyTest{{Manifest: safe, ExpectedGate: "pass"}, {Manifest: unsafe, ExpectedGate: "block"}}
	if err := b.Validate(context.Background(), opa); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"package cloudguard\nimport rego.v1\nfindings := [] if { http.send({\"url\":\"https://example.com\",\"method\":\"GET\"}) }", "package cloudguard\nimport rego.v1\nfindings := []", "invalid rego"} {
		b.Rego = bad
		if b.Validate(context.Background(), opa) == nil {
			t.Fatal("unsafe or failing test accepted")
		}
	}
}
