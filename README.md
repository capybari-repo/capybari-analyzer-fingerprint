# capybari-analyzer-fingerprint

**Capybari Source Intelligence: Project Fingerprint: what is this repository?**

Produces a compact, machine-readable identity of a repository:

- project type(s): web-backend, web-frontend, cli, library, mobile-app, desktop-app, static-site, cms-site, infrastructure, data-science, application
- primary language, package managers, build systems
- runtimes and versions, from `.nvmrc`, `.python-version`, `.tool-versions`, `go.mod`, `engines`, `requires-python`, `global.json`, `*.csproj`, `pom.xml`, Dockerfile `FROM`, …
- manifests, entry points, workspaces and monorepo detection
- tests, CI systems, containers, IaC tools, docs, license (SPDX id)
- git history: commits, contributors, first/last commit, shallow-clone flag
- a structural digest (`fp_…`) that changes when the project's shape changes, not on every edit

Findings: missing tests, missing CI, missing README, unlocked dependencies, missing license on a publishable package.

| | |
|---|---|
| Requires | `inventory` (built into capybari-core) |
| Provides | `fingerprint` evidence |
| Network / AI | none / none, fully local |
| Methodology | [docs/methodology.md](docs/methodology.md) |

## Run on its own

```bash
go run ./cmd/capybari-fingerprint ./path/to/project
```

It is part of the unified [`capybari`](https://github.com/capybari/capybari-cli) tool.

## License

Apache-2.0
