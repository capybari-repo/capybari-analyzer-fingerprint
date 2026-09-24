package fingerprint_test

import (
	"os"
	"path/filepath"
	"testing"

	fingerprint "github.com/capybari-repo/capybari-analyzer-fingerprint"
	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/analyzertest"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-schemas"
	"gopkg.in/yaml.v3"
)

// fixtures lives in the sibling capybari-fixtures checkout.
const fixtures = "../capybari-fixtures"

func TestCapabilityMetadata(t *testing.T) {
	b, err := os.ReadFile("capability.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := analyzer.ParseCapability(b); err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateValue("capability.schema.json", doc); err != nil {
		t.Fatal(err)
	}
}

func TestFixtures(t *testing.T) {
	for _, name := range []string{"node-express-legacy", "python-flask-app", "go-service", "static-site"} {
		t.Run(name, func(t *testing.T) {
			r := analyzertest.Run(t, fingerprint.New(), analyzertest.Repo(t, filepath.Join(fixtures, name)), analyzertest.Options{})
			fp := analyzertest.Fact[facts.Fingerprint](t, r, facts.KeyFingerprint)
			var rules []string
			for _, f := range r.Findings {
				rules = append(rules, f.Rule.ID)
			}
			analyzertest.Golden(t, name, map[string]any{"fingerprint": fp, "findings": rules})
		})
	}
}
