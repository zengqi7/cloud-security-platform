package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryTenantHostIsolationAndRotation(t *testing.T) {
	root := t.TempDir()
	catalog := filepath.Join(root, "bindings.json")
	t.Setenv("REGISTRY_BINDINGS_FILE", catalog)
	t.Setenv("REGISTRY_SECRET_DIR", root)
	raw, _ := json.Marshal([]registryBinding{{Tenant: "one", Ref: "robot", Registry: "registry.example", File: "robot"}})
	if err := os.WriteFile(catalog, raw, 0600); err != nil {
		t.Fatal(err)
	}
	write := func(password string) {
		t.Helper()
		data, _ := json.Marshal(map[string]any{"auths": map[string]any{"registry.example": map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte("robot:" + password))}}})
		if err := os.WriteFile(filepath.Join(root, "robot"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("first-secret")
	r := Request{Kind: "image", Target: "registry.example/team/image:1", RegistryCredential: "robot"}
	first, err := registryConfig("one", r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registryConfig("two", r); err == nil {
		t.Fatal("cross tenant credential")
	}
	r.Target = "evil.example/image:1"
	if _, err := registryConfig("one", r); err == nil {
		t.Fatal("cross host credential")
	}
	r.Target = "registry.example/team/image:1"
	write("rotated-secret")
	second, err := registryConfig("one", r)
	if err != nil || string(first) == string(second) {
		t.Fatal("rotation not reloaded")
	}
	s := ToolScanner{WorkDir: root}
	ctx, cleanup, err := s.registryContext(context.Background(), "one", r)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYSQL_DSN", "do-not-inherit")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "do-not-inherit")
	for _, e := range toolEnvironment(ctx) {
		if strings.Contains(e, "do-not-inherit") {
			t.Fatal("control plane secret inherited")
		}
	}
	scoped := ctx.Value(toolEnvKey{}).([]string)
	dir := strings.TrimPrefix(scoped[0], "DOCKER_CONFIG=")
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("credential workspace retained")
	}
}
