package deployments

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControllerIngressExampleIncludesRateLimiting(t *testing.T) {
	ingress := readFixture(t, "kubernetes", "controller", "examples", "ingress.yaml")

	assertContainsAll(t, "controller ingress example", ingress, []string{
		`nginx.ingress.kubernetes.io/limit-rps: "20"`,
		`nginx.ingress.kubernetes.io/limit-burst-multiplier: "5"`,
		`nginx.ingress.kubernetes.io/limit-req-status-code: "429"`,
		"name: arca-dns-controller",
		"number: 8080",
	})
}

func TestDeploymentDocsDescribeIngressRateLimiting(t *testing.T) {
	docs := map[string]string{
		"English deployment guide":  readFixture(t, "..", "docs", "deployment.md"),
		"Japanese deployment guide": readFixture(t, "..", "docs", "deployment.ja.md"),
		"deployment README":         readFixture(t, "README.md"),
	}

	for name, doc := range docs {
		assertContainsAll(t, name, doc, []string{
			"process-local",
			"ingress",
			"load balancer",
			"rate-limit",
		})
	}
}

func readFixture(t *testing.T, path ...string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(path...))
	if err != nil {
		t.Fatalf("read fixture %s: %v", filepath.Join(path...), err)
	}

	return string(data)
}

func assertContainsAll(t *testing.T, name string, got string, want []string) {
	t.Helper()

	for _, item := range want {
		if !strings.Contains(got, item) {
			t.Fatalf("%s does not contain %q", name, item)
		}
	}
}
