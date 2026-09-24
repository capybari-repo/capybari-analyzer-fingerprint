// Package fingerprint implements the Project Fingerprint capability: a
// compact, machine-readable identity of a repository built from its
// inventory, manifests and git history.
package fingerprint

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/facts"
	"github.com/capybari/capybari-core/finding"
)

//go:embed capability.yaml
var capabilityYAML []byte

var capability = analyzer.MustParseCapability(capabilityYAML)

// Analyzer implements the capability.
type Analyzer struct{}

// New returns the capability.
func New() *Analyzer { return &Analyzer{} }

// Capability implements analyzer.Analyzer.
func (*Analyzer) Capability() analyzer.Capability { return capability }

// Analyze implements analyzer.Analyzer.
func (*Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	var inv facts.Inventory
	if _, err := in.Evidence.Get(facts.KeyInventory, &inv); err != nil {
		return nil, err
	}
	s := newScan(in.Target.Root, &inv)
	s.manifests()
	s.runtimes()
	s.entryPoints()
	s.projectTypes()

	fp := &s.fp
	fp.Name = s.name(in.Target.Display)
	if len(inv.Languages) > 0 {
		fp.PrimaryLanguage = inv.Languages[0].Language
	}
	fp.HasTests = inv.KindCounts[facts.KindTest] > 0
	fp.HasContainers = inv.KindCounts[facts.KindContainer] > 0
	fp.HasDocs = inv.KindCounts[facts.KindDocs] > 0
	fp.HasCI = s.ciSystems()
	fp.HasIaC = s.iacTools()
	fp.License = s.license()
	fp.Size = sizeClass(&inv)
	if g, err := gitInfo(ctx, in.Target.Root); err == nil {
		fp.Git = g
	}
	fp.Digest = digest(&inv, fp)
	sortUnique := func(p *[]string) { slices.Sort(*p); *p = slices.Compact(*p) }
	sortUnique(&fp.PackageManagers)
	sortUnique(&fp.BuildSystems)
	sortUnique(&fp.Manifests)
	sortUnique(&fp.EntryPoints)
	sortUnique(&fp.Workspaces)
	sortUnique(&fp.ProjectTypes)
	fp.Monorepo = len(fp.Workspaces) > 1 || s.manifestDirs() >= 3

	findings := s.findings()
	var rt []string
	for _, r := range fp.Runtimes {
		rt = append(rt, strings.TrimSpace(r.Name+" "+r.Version))
	}
	summary := fmt.Sprintf("%s project", strings.Join(fp.ProjectTypes, "/"))
	if fp.PrimaryLanguage != "" {
		summary += " in " + fp.PrimaryLanguage
	}
	if len(rt) > 0 {
		summary += " on " + strings.Join(rt, ", ")
	}
	return &analyzer.Result{
		Evidence: map[string]any{facts.KeyFingerprint: fp},
		Findings: findings,
		Summary:  summary,
	}, nil
}

// scan holds the working state of one fingerprint run.
type scan struct {
	root   string
	inv    *facts.Inventory
	byPath map[string]facts.File
	fp     facts.Fingerprint
	// dependency names seen in manifests, used for project-type heuristics
	deps map[string]bool
	// package.json facts
	nodeBin, nodePrivate, nodeHasMain bool
	pyScripts                         bool
	lockfiles                         map[string]bool // ecosystem -> lockfile present
	manifestEco                       map[string]string
}

func newScan(root string, inv *facts.Inventory) *scan {
	s := &scan{root: root, inv: inv, byPath: map[string]facts.File{}, deps: map[string]bool{}, lockfiles: map[string]bool{}, manifestEco: map[string]string{}}
	for _, f := range inv.Files {
		s.byPath[f.Path] = f
	}
	return s
}

// ownFiles returns files that belong to the project (not vendored/generated).
func (s *scan) ownFiles() []facts.File {
	var out []facts.File
	for _, f := range s.inv.Files {
		if f.Kind != facts.KindVendored && f.Kind != facts.KindGenerated {
			out = append(out, f)
		}
	}
	return out
}

func (s *scan) has(p string) bool { _, ok := s.byPath[p]; return ok }

func (s *scan) name(fallback string) string {
	if n := s.fp.Name; n != "" {
		return n
	}
	return fallback
}

func (s *scan) manifestDirs() int {
	dirs := map[string]bool{}
	for p, eco := range s.manifestEco {
		if eco == "npm" || eco == "Go" || eco == "PyPI" || eco == "crates.io" || eco == "Maven" {
			dirs[path.Dir(p)] = true
		}
	}
	return len(dirs)
}

func (s *scan) ciSystems() []string {
	set := map[string]bool{}
	for _, f := range s.inv.Filter(facts.KindCI) {
		p := strings.ToLower(f.Path)
		switch {
		case strings.HasPrefix(p, ".github/workflows/"):
			set["GitHub Actions"] = true
		case strings.HasSuffix(p, ".gitlab-ci.yml"):
			set["GitLab CI"] = true
		case strings.HasPrefix(p, ".circleci/"):
			set["CircleCI"] = true
		case strings.HasSuffix(p, "jenkinsfile"):
			set["Jenkins"] = true
		case strings.HasSuffix(p, "azure-pipelines.yml"):
			set["Azure Pipelines"] = true
		case strings.HasSuffix(p, ".travis.yml"):
			set["Travis CI"] = true
		case strings.HasSuffix(p, "bitbucket-pipelines.yml"):
			set["Bitbucket Pipelines"] = true
		case strings.HasPrefix(p, ".buildkite/"):
			set["Buildkite"] = true
		default:
			set["Other CI"] = true
		}
	}
	return keys(set)
}

func (s *scan) iacTools() []string {
	set := map[string]bool{}
	for _, f := range s.inv.Filter(facts.KindIaC) {
		p := strings.ToLower(f.Path)
		base := path.Base(p)
		switch {
		case strings.HasSuffix(p, ".tf") || strings.HasSuffix(p, ".tfvars"):
			set["Terraform"] = true
		case strings.HasSuffix(p, ".bicep"):
			set["Bicep"] = true
		case base == "chart.yaml" || strings.Contains(p, "charts/") || strings.Contains(p, "helm/"):
			set["Helm"] = true
		case base == "pulumi.yaml":
			set["Pulumi"] = true
		case strings.HasPrefix(base, "serverless."):
			set["Serverless Framework"] = true
		case strings.Contains(p, "ansible"):
			set["Ansible"] = true
		case strings.Contains(p, "cloudformation") || strings.Contains(p, "cfn/") || strings.Contains(p, "sam/"):
			set["CloudFormation"] = true
		default:
			set["Kubernetes"] = true
		}
	}
	return keys(set)
}

func sizeClass(inv *facts.Inventory) string {
	lines := 0
	for _, l := range inv.Languages {
		lines += l.Lines
	}
	switch {
	case lines < 1_000:
		return "tiny"
	case lines < 10_000:
		return "small"
	case lines < 100_000:
		return "medium"
	case lines < 1_000_000:
		return "large"
	}
	return "very-large"
}

// digest is a content-independent structural identity: it changes when the
// project's shape (files, manifests, runtimes) changes, not on every edit.
func digest(inv *facts.Inventory, fp *facts.Fingerprint) string {
	h := sha256.New()
	var paths []string
	for _, f := range inv.Files {
		if f.Kind != facts.KindVendored && f.Kind != facts.KindGenerated {
			paths = append(paths, f.Path)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	for _, r := range fp.Runtimes {
		fmt.Fprintf(h, "%s=%s\n", r.Name, r.Version)
	}
	fmt.Fprint(h, strings.Join(fp.PackageManagers, ","), strings.Join(fp.ProjectTypes, ","))
	return "fp_" + hex.EncodeToString(h.Sum(nil))[:20]
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *scan) findings() []finding.Finding {
	var out []finding.Finding
	sourceFiles := len(s.inv.Filter(facts.KindSource))
	add := func(f finding.Finding) { out = append(out, f) }
	if sourceFiles >= 5 && !s.fp.HasTests {
		add(finding.Finding{
			Dimension: finding.DimMaintainability, Category: "missing-tests", Severity: finding.Medium, Confidence: finding.ConfidenceHigh,
			Title:                 "No automated tests found",
			Description:           fmt.Sprintf("%d source files and no test files were found. Changes cannot be verified automatically, so every modification carries regression risk.", sourceFiles),
			Rule:                  &finding.Rule{ID: "no-tests"},
			Impact:                &finding.Impact{Technical: "Regressions are found by users, not by CI.", Business: "Each change is slower and riskier to ship."},
			Remediation:           &finding.Remediation{Summary: "Start with tests around the most-changed and most business-critical code paths, and run them in CI.", Automatable: false},
			FalsePositiveGuidance: "Tests stored outside the repository, or named without common test conventions, are not detected.",
		})
	}
	if sourceFiles >= 5 && len(s.fp.HasCI) == 0 {
		add(finding.Finding{
			Dimension: finding.DimOperability, Category: "missing-ci", Severity: finding.Low, Confidence: finding.ConfidenceMedium,
			Title:                 "No CI/CD configuration found",
			Description:           "No pipeline definition (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure Pipelines, …) was found, so builds and tests are presumably run by hand.",
			Rule:                  &finding.Rule{ID: "no-ci"},
			Remediation:           &finding.Remediation{Summary: "Add a pipeline that builds, tests and scans every change.", Automatable: true},
			FalsePositiveGuidance: "CI may be configured outside the repository (e.g. in a separate pipelines repository or a hosted service UI).",
		})
	}
	if !s.hasReadme() {
		add(finding.Finding{
			Dimension: finding.DimOperability, Category: "missing-readme", Severity: finding.Low, Confidence: finding.ConfidenceHigh,
			Title:       "No README",
			Description: "There is no README explaining what the project is, how to build it and how to run it.",
			Rule:        &finding.Rule{ID: "no-readme"},
			Remediation: &finding.Remediation{Summary: "Add a README with purpose, setup, build, test and deployment instructions.", Automatable: true},
		})
	}
	for p, eco := range s.manifestEco {
		if s.lockfiles[path.Dir(p)+"|"+eco] {
			continue
		}
		if eco != "npm" && eco != "PyPI-pyproject" && eco != "RubyGems" && eco != "Packagist" && eco != "crates.io" {
			continue
		}
		if eco == "crates.io" && !slices.Contains(s.fp.ProjectTypes, "application") {
			continue // libraries conventionally do not commit Cargo.lock
		}
		label := map[string]string{"npm": "npm/yarn/pnpm", "PyPI-pyproject": "Python", "RubyGems": "Bundler", "Packagist": "Composer", "crates.io": "Cargo"}[eco]
		add(finding.Finding{
			Dimension: finding.DimOperability, Category: "missing-lockfile", Severity: finding.Low, Confidence: finding.ConfidenceMedium,
			Title:                 "Dependencies are not locked",
			Description:           fmt.Sprintf("%s declares %s dependencies but no lockfile was found next to it, so builds can silently pick up different versions.", p, label),
			Evidence:              []finding.Evidence{{Location: finding.Location{Path: p}}},
			Rule:                  &finding.Rule{ID: "no-lockfile"},
			Remediation:           &finding.Remediation{Summary: "Generate and commit the lockfile, and install from it in CI.", Automatable: true},
			FalsePositiveGuidance: "Libraries sometimes intentionally omit lockfiles.",
		})
	}
	if s.fp.License == "" && s.isLikelyOpenSource() {
		add(finding.Finding{
			Dimension: finding.DimOperability, Category: "missing-license", Severity: finding.Info, Confidence: finding.ConfidenceMedium,
			Title:       "No license file",
			Description: "The package looks publishable but has no LICENSE file, so others have no legal right to use it.",
			Rule:        &finding.Rule{ID: "no-license"},
			Remediation: &finding.Remediation{Summary: "Add a LICENSE file (or mark the package private if it is not meant to be shared).", Automatable: false},
		})
	}
	return out
}

func (s *scan) hasReadme() bool {
	for p := range s.byPath {
		if !strings.Contains(p, "/") && strings.HasPrefix(strings.ToLower(p), "readme") {
			return true
		}
	}
	return false
}

func (s *scan) isLikelyOpenSource() bool {
	return s.nodeHasMain && !s.nodePrivate
}
