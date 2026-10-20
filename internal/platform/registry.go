package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type toolEnvKey struct{}

var credentialRef = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type registryBinding struct {
	Tenant   string `json:"tenant"`
	Ref      string `json:"ref"`
	Registry string `json:"registry"`
	File     string `json:"file"`
}

func readSecretFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("registry secret unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errors.New("invalid registry secret size")
	}
	return raw, nil
}
func registryHost(target string) string {
	first, _, slash := strings.Cut(target, "/")
	if slash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return strings.ToLower(first)
	}
	return "docker.io"
}
func registryConfig(tenant string, r Request) ([]byte, error) {
	if r.RegistryCredential == "" {
		return []byte(`{"auths":{}}`), nil
	}
	raw, err := readSecretFile(os.Getenv("REGISTRY_BINDINGS_FILE"))
	if err != nil {
		return nil, err
	}
	var bindings []registryBinding
	if json.Unmarshal(raw, &bindings) != nil {
		return nil, errors.New("invalid registry binding catalog")
	}
	var found *registryBinding
	for i := range bindings {
		b := &bindings[i]
		if b.Tenant == tenant && b.Ref == r.RegistryCredential {
			if found != nil {
				return nil, errors.New("duplicate registry binding")
			}
			found = b
		}
	}
	if found == nil || found.Registry != registryHost(r.Target) || !credentialRef.MatchString(found.File) {
		return nil, errors.New("registry credential not authorized for tenant and host")
	}
	root := os.Getenv("REGISTRY_SECRET_DIR")
	if !filepath.IsAbs(root) {
		return nil, errors.New("absolute registry secret directory required")
	}
	raw, err = readSecretFile(filepath.Join(root, found.File))
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return nil, errors.New("invalid registry Docker config")
	}
	entry, ok := cfg.Auths[found.Registry]
	decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
	if !ok || err != nil || !strings.Contains(string(decoded), ":") || strings.ContainsAny(string(decoded), "\r\n\x00") {
		return nil, errors.New("registry basic auth entry required")
	}
	return json.Marshal(map[string]any{"auths": map[string]any{found.Registry: entry}})
}
func (s ToolScanner) registryContext(ctx context.Context, tenant string, r Request) (context.Context, func(), error) {
	if r.Kind != "image" {
		return ctx, func() {}, nil
	}
	raw, err := registryConfig(tenant, r)
	if err != nil {
		return ctx, func() {}, err
	}
	dir, err := os.MkdirTemp(s.WorkDir, "registry-")
	if err != nil {
		return ctx, func() {}, errors.New("registry workspace unavailable")
	}
	cleanup := func() { os.RemoveAll(dir) }
	if err := os.WriteFile(filepath.Join(dir, "config.json"), raw, 0600); err != nil {
		cleanup()
		return ctx, func() {}, errors.New("registry workspace unavailable")
	}
	return context.WithValue(ctx, toolEnvKey{}, []string{"DOCKER_CONFIG=" + dir}), cleanup, nil
}
