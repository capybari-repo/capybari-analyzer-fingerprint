package fingerprint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/capybari/capybari-core/facts"
	"github.com/capybari/capybari-core/fsutil"
)

func (s *scan) read(p string) []byte {
	b, _, err := fsutil.ReadFile(s.root, p, 1<<20)
	if err != nil {
		return nil
	}
	return b
}

type packageJSON struct {
	Name            string            `json:"name"`
	Private         bool              `json:"private"`
	Main            string            `json:"main"`
	Module          string            `json:"module"`
	Exports         json.RawMessage   `json:"exports"`
	Bin             json.RawMessage   `json:"bin"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Engines         map[string]string `json:"engines"`
	Workspaces      json.RawMessage   `json:"workspaces"`
	PackageManager  string            `json:"packageManager"`
	License         json.RawMessage   `json:"license"`
}

type pyproject struct {
	Project struct {
		Name           string            `toml:"name"`
		RequiresPython string            `toml:"requires-python"`
		Dependencies   []string          `toml:"dependencies"`
		Scripts        map[string]string `toml:"scripts"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Name         string            `toml:"name"`
			Dependencies map[string]any    `toml:"dependencies"`
			Scripts      map[string]string `toml:"scripts"`
		} `toml:"poetry"`
	} `toml:"tool"`
	BuildSystem struct {
		BuildBackend string `toml:"build-backend"`
	} `toml:"build-system"`
}

type cargoToml struct {
	Package struct {
		Name        string `toml:"name"`
		RustVersion string `toml:"rust-version"`
		Edition     string `toml:"edition"`
	} `toml:"package"`
	Workspace struct {
		Members []string `toml:"members"`
	} `toml:"workspace"`
	Dependencies map[string]any `toml:"dependencies"`
	Bin          []any          `toml:"bin"`
}

var reqName = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

// manifests records package managers, build systems, manifests, workspaces,
// dependency names and lockfile presence.
func (s *scan) manifests() {
	for _, f := range s.ownFiles() {
		p := f.Path
		dir := path.Dir(p)
		base := strings.ToLower(path.Base(p))
		pm := func(names ...string) { s.fp.PackageManagers = append(s.fp.PackageManagers, names...) }
		bs := func(names ...string) { s.fp.BuildSystems = append(s.fp.BuildSystems, names...) }
		manifest := func(eco string) {
			s.fp.Manifests = append(s.fp.Manifests, p)
			s.manifestEco[p] = eco
		}
		lock := func(eco string) { s.lockfiles[dir+"|"+eco] = true }

		switch base {
		case "package.json":
			var pj packageJSON
			if json.Unmarshal(s.read(p), &pj) != nil {
				continue
			}
			manifest("npm")
			if dir == "." {
				s.fp.Name = pj.Name
				s.nodePrivate = pj.Private
				s.nodeHasMain = pj.Main != "" || pj.Module != "" || len(pj.Exports) > 0
				s.nodeBin = len(pj.Bin) > 0
				if v := pj.Engines["node"]; v != "" {
					s.addRuntime("Node.js", v, p)
				}
				for _, w := range workspaceGlobs(pj.Workspaces) {
					s.fp.Workspaces = append(s.fp.Workspaces, w)
				}
				switch {
				case strings.HasPrefix(pj.PackageManager, "pnpm"):
					pm("pnpm")
				case strings.HasPrefix(pj.PackageManager, "yarn"):
					pm("yarn")
				case strings.HasPrefix(pj.PackageManager, "bun"):
					pm("bun")
				}
			}
			for d := range pj.Dependencies {
				s.deps[strings.ToLower(d)] = true
			}
			for d := range pj.DevDependencies {
				s.deps[strings.ToLower(d)] = true
			}
			if len(pj.Scripts) > 0 {
				bs("npm scripts")
			}
		case "package-lock.json", "npm-shrinkwrap.json":
			pm("npm")
			lock("npm")
		case "yarn.lock":
			pm("yarn")
			lock("npm")
		case "pnpm-lock.yaml":
			pm("pnpm")
			lock("npm")
		case "bun.lockb", "bun.lock":
			pm("bun")
			lock("npm")
		case "pnpm-workspace.yaml":
			for _, line := range strings.Split(string(s.read(p)), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "- ") {
					s.fp.Workspaces = append(s.fp.Workspaces, strings.Trim(strings.TrimPrefix(line, "- "), `"'`))
				}
			}
		case "go.mod":
			manifest("Go")
			pm("Go modules")
			sc := bufio.NewScanner(bytes.NewReader(s.read(p)))
			inRequire := false
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				switch {
				case strings.HasPrefix(line, "module ") && dir == ".":
					mod := strings.TrimSpace(strings.TrimPrefix(line, "module "))
					s.fp.Name = path.Base(mod)
				case strings.HasPrefix(line, "go "):
					s.addRuntime("Go", strings.TrimSpace(strings.TrimPrefix(line, "go ")), p)
				case strings.HasPrefix(line, "toolchain go"):
					s.addRuntime("Go", strings.TrimPrefix(line, "toolchain go"), p)
				case line == "require (":
					inRequire = true
				case line == ")":
					inRequire = false
				case inRequire || strings.HasPrefix(line, "require "):
					fields := strings.Fields(strings.TrimPrefix(line, "require "))
					if len(fields) > 0 {
						s.deps[strings.ToLower(fields[0])] = true
					}
				}
			}
			lock("Go") // go.sum is not required for the purposes of this check
		case "go.work":
			for _, line := range strings.Split(string(s.read(p)), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "./") || strings.HasPrefix(line, "use ./") {
					s.fp.Workspaces = append(s.fp.Workspaces, strings.TrimPrefix(line, "use "))
				}
			}
		case "pyproject.toml":
			var pp pyproject
			if _, err := toml.Decode(string(s.read(p)), &pp); err != nil {
				continue
			}
			manifest("PyPI-pyproject")
			if dir == "." {
				if pp.Project.Name != "" {
					s.fp.Name = pp.Project.Name
				} else if pp.Tool.Poetry.Name != "" {
					s.fp.Name = pp.Tool.Poetry.Name
				}
			}
			if pp.Project.RequiresPython != "" {
				s.addRuntime("Python", pp.Project.RequiresPython, p)
			}
			if v, ok := pp.Tool.Poetry.Dependencies["python"].(string); ok {
				s.addRuntime("Python", v, p)
			}
			for _, d := range pp.Project.Dependencies {
				if m := reqName.FindStringSubmatch(d); m != nil {
					s.deps[strings.ToLower(m[1])] = true
				}
			}
			for d := range pp.Tool.Poetry.Dependencies {
				s.deps[strings.ToLower(d)] = true
			}
			s.pyScripts = len(pp.Project.Scripts) > 0 || len(pp.Tool.Poetry.Scripts) > 0
			switch {
			case strings.Contains(pp.BuildSystem.BuildBackend, "poetry"):
				pm("Poetry")
			case strings.Contains(pp.BuildSystem.BuildBackend, "hatch"):
				pm("Hatch")
			case strings.Contains(pp.BuildSystem.BuildBackend, "pdm"):
				pm("PDM")
			case strings.Contains(pp.BuildSystem.BuildBackend, "flit"):
				pm("Flit")
			default:
				pm("pip")
			}
		case "poetry.lock":
			pm("Poetry")
			lock("PyPI-pyproject")
		case "uv.lock":
			pm("uv")
			lock("PyPI-pyproject")
		case "pdm.lock":
			pm("PDM")
			lock("PyPI-pyproject")
		case "pipfile":
			pm("Pipenv")
			manifest("PyPI")
		case "pipfile.lock":
			pm("Pipenv")
		case "setup.py", "setup.cfg":
			pm("pip")
			manifest("PyPI")
		case "gemfile":
			pm("Bundler")
			manifest("RubyGems")
			for _, line := range strings.Split(string(s.read(p)), "\n") {
				if m := regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)`).FindStringSubmatch(line); m != nil {
					s.deps[strings.ToLower(m[1])] = true
				}
				if m := regexp.MustCompile(`^\s*ruby\s+['"]([^'"]+)`).FindStringSubmatch(line); m != nil {
					s.addRuntime("Ruby", m[1], p)
				}
			}
		case "gemfile.lock":
			lock("RubyGems")
		case "composer.json":
			pm("Composer")
			manifest("Packagist")
			var cj struct {
				Name    string            `json:"name"`
				Require map[string]string `json:"require"`
			}
			if json.Unmarshal(s.read(p), &cj) == nil {
				for d, v := range cj.Require {
					if d == "php" {
						s.addRuntime("PHP", v, p)
						continue
					}
					s.deps[strings.ToLower(d)] = true
				}
				if dir == "." && cj.Name != "" {
					s.fp.Name = cj.Name
				}
			}
		case "composer.lock":
			lock("Packagist")
		case "cargo.toml":
			var ct cargoToml
			if _, err := toml.Decode(string(s.read(p)), &ct); err != nil {
				continue
			}
			pm("Cargo")
			manifest("crates.io")
			if dir == "." && ct.Package.Name != "" {
				s.fp.Name = ct.Package.Name
			}
			if ct.Package.RustVersion != "" {
				s.addRuntime("Rust", ct.Package.RustVersion, p)
			}
			s.fp.Workspaces = append(s.fp.Workspaces, ct.Workspace.Members...)
			for d := range ct.Dependencies {
				s.deps[strings.ToLower(d)] = true
			}
		case "cargo.lock":
			lock("crates.io")
		case "pom.xml":
			pm("Maven")
			bs("Maven")
			manifest("Maven")
			body := string(s.read(p))
			for _, m := range regexp.MustCompile(`<artifactId>([^<]+)</artifactId>`).FindAllStringSubmatch(body, -1) {
				s.deps[strings.ToLower(m[1])] = true
			}
			if m := regexp.MustCompile(`<(?:maven\.compiler\.(?:source|release)|java\.version)>([^<]+)<`).FindStringSubmatch(body); m != nil {
				s.addRuntime("Java", m[1], p)
			}
			for _, m := range regexp.MustCompile(`<module>([^<]+)</module>`).FindAllStringSubmatch(body, -1) {
				s.fp.Workspaces = append(s.fp.Workspaces, m[1])
			}
		case "build.gradle", "build.gradle.kts":
			pm("Gradle")
			bs("Gradle")
			manifest("Maven")
			body := string(s.read(p))
			for _, m := range regexp.MustCompile(`["']([\w.-]+):([\w.-]+):[\w.+-]+["']`).FindAllStringSubmatch(body, -1) {
				s.deps[strings.ToLower(m[2])] = true
			}
			if m := regexp.MustCompile(`(?:JavaVersion\.VERSION_|languageVersion\.set\(JavaLanguageVersion\.of\()(\d+)`).FindStringSubmatch(body); m != nil {
				s.addRuntime("Java", m[1], p)
			}
			if strings.Contains(body, "com.android.application") {
				s.deps["android"] = true
			}
		case "settings.gradle", "settings.gradle.kts":
			for _, m := range regexp.MustCompile(`include\s*\(?\s*["']:?([^"']+)["']`).FindAllStringSubmatch(string(s.read(p)), -1) {
				s.fp.Workspaces = append(s.fp.Workspaces, m[1])
			}
		case "mix.exs":
			pm("Mix")
			manifest("Hex")
		case "pubspec.yaml":
			pm("pub")
			manifest("Pub")
			if bytes.Contains(s.read(p), []byte("flutter:")) {
				s.deps["flutter"] = true
			}
		case "package.swift":
			pm("Swift Package Manager")
			manifest("SwiftURL")
		case "podfile":
			pm("CocoaPods")
		case "makefile", "gnumakefile":
			bs("Make")
		case "cmakelists.txt":
			bs("CMake")
		case "justfile":
			bs("just")
		case "lerna.json":
			bs("Lerna")
		case "nx.json":
			bs("Nx")
		case "turbo.json":
			bs("Turborepo")
		case "deno.json", "deno.jsonc":
			pm("Deno")
			s.addRuntime("Deno", "", p)
		}
		switch {
		case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
			pm("pip")
			manifest("PyPI")
			lock("PyPI") // requirements files are the lock mechanism for pip
			for _, line := range strings.Split(string(s.read(p)), "\n") {
				if m := reqName.FindStringSubmatch(line); m != nil && !strings.HasPrefix(strings.TrimSpace(line), "#") && !strings.HasPrefix(strings.TrimSpace(line), "-") {
					s.deps[strings.ToLower(m[1])] = true
				}
			}
		case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") || strings.HasSuffix(base, ".vbproj"):
			pm("NuGet")
			bs("MSBuild")
			manifest("NuGet")
			body := string(s.read(p))
			if m := regexp.MustCompile(`<TargetFrameworks?>([^<]+)</TargetFrameworks?>`).FindStringSubmatch(body); m != nil {
				s.addRuntime(".NET", m[1], p)
			}
			for _, m := range regexp.MustCompile(`<PackageReference\s+Include="([^"]+)"`).FindAllStringSubmatch(body, -1) {
				s.deps[strings.ToLower(m[1])] = true
			}
			if strings.Contains(body, `Sdk="Microsoft.NET.Sdk.Web"`) {
				s.deps["aspnetcore"] = true
			}
		case strings.HasSuffix(base, ".sln"):
			bs("MSBuild")
		case strings.HasSuffix(base, ".gemspec"):
			pm("RubyGems")
		}
	}
}

func workspaceGlobs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Packages
	}
	return nil
}

func (s *scan) addRuntime(name, version, source string) {
	version = strings.TrimSpace(version)
	for i, r := range s.fp.Runtimes {
		if r.Name == name {
			// Prefer an exact pin (e.g. .nvmrc 18.19.0) over a range (>=18).
			if r.Version == "" || (isRange(r.Version) && !isRange(version) && version != "") {
				s.fp.Runtimes[i] = facts.Runtime{Name: name, Version: version, Source: source}
			}
			return
		}
	}
	s.fp.Runtimes = append(s.fp.Runtimes, facts.Runtime{Name: name, Version: version, Source: source})
}

func isRange(v string) bool {
	return strings.ContainsAny(v, "<>=^~*| ,")
}

var dockerFrom = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s:@]+)(?::([^\s@]+))?`)

// runtimes reads version pin files and container base images.
func (s *scan) runtimes() {
	pins := map[string]string{
		".nvmrc": "Node.js", ".node-version": "Node.js", ".python-version": "Python", ".ruby-version": "Ruby",
		".java-version": "Java", ".go-version": "Go", "runtime.txt": "Python", "rust-toolchain": "Rust",
	}
	for _, f := range s.ownFiles() {
		base := strings.ToLower(path.Base(f.Path))
		if name, ok := pins[base]; ok && path.Dir(f.Path) == "." {
			v := strings.TrimSpace(strings.SplitN(string(s.read(f.Path)), "\n", 2)[0])
			v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "python-")
			if v != "" && !strings.HasPrefix(v, "lts/") {
				s.addRuntime(name, v, f.Path)
			}
		}
		switch {
		case base == ".tool-versions" && path.Dir(f.Path) == ".":
			names := map[string]string{"nodejs": "Node.js", "python": "Python", "ruby": "Ruby", "golang": "Go", "java": "Java", "rust": "Rust", "elixir": "Elixir", "erlang": "Erlang", "php": "PHP"}
			for _, line := range strings.Split(string(s.read(f.Path)), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if n, ok := names[fields[0]]; ok {
						s.addRuntime(n, fields[1], f.Path)
					}
				}
			}
		case base == "rust-toolchain.toml":
			if m := regexp.MustCompile(`channel\s*=\s*"([^"]+)"`).FindStringSubmatch(string(s.read(f.Path))); m != nil {
				s.addRuntime("Rust", m[1], f.Path)
			}
		case base == "global.json":
			var g struct {
				SDK struct {
					Version string `json:"version"`
				} `json:"sdk"`
			}
			if json.Unmarshal(s.read(f.Path), &g) == nil && g.SDK.Version != "" {
				s.addRuntime(".NET", g.SDK.Version, f.Path)
			}
		case f.Kind == facts.KindContainer && (strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") || base == "containerfile"):
			for _, m := range dockerFrom.FindAllStringSubmatch(string(s.read(f.Path)), -1) {
				img, tag := strings.ToLower(path.Base(m[1])), m[2]
				name := map[string]string{"node": "Node.js", "python": "Python", "golang": "Go", "ruby": "Ruby", "php": "PHP", "openjdk": "Java", "eclipse-temurin": "Java", "amazoncorretto": "Java", "rust": "Rust"}[img]
				if name == "" || tag == "" {
					continue
				}
				v := regexp.MustCompile(`^\d+(\.\d+){0,2}`).FindString(tag)
				if v != "" {
					s.addRuntime(name, v, f.Path)
				}
			}
		}
	}
	// A declared language with no version still counts as a runtime.
	langRuntime := map[string]string{"Go": "Go", "Python": "Python", "JavaScript": "Node.js", "TypeScript": "Node.js", "Ruby": "Ruby", "PHP": "PHP", "Java": "Java", "C#": ".NET", "Rust": "Rust"}
	if len(s.inv.Languages) > 0 {
		if rt, ok := langRuntime[s.inv.Languages[0].Language]; ok {
			s.addRuntime(rt, "", "")
		}
	}
}
