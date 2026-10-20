package platform

import (
	"context"
	"os"
	"strings"
)

// Scanner children do not need control-plane SQL, OIDC or cloud credentials.
func toolEnvironment(ctx context.Context) []string {
	env := []string{}
	allowed := map[string]bool{"PATH": true, "SYSTEMROOT": true, "WINDIR": true, "TEMP": true, "TMP": true, "TMPDIR": true, "HOME": true, "USERPROFILE": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "HTTPS_PROXY": true, "HTTP_PROXY": true, "NO_PROXY": true, "TUF_ROOT": true, "XDG_CACHE_HOME": true}
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if allowed[strings.ToUpper(k)] {
			env = append(env, v)
		}
	}
	if scoped, ok := ctx.Value(toolEnvKey{}).([]string); ok {
		env = append(env, scoped...)
	}
	return env
}
