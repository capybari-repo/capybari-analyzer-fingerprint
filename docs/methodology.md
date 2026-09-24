# Methodology: Project Fingerprint

## Inputs

The file inventory from the built-in `inventory` capability (`git ls-files` when available, so `.gitignore` is respected), plus the content of manifest and version-pin files, plus local `git log`.

## Project types

Types come from explicit signals only, and a repository can have several:

| Type | Signal |
|---|---|
| web-backend | server framework dependency (Express, Fastify, NestJS, Flask, Django, FastAPI, Gin, Echo, Fiber, Chi, Spring Web, Rails, Laravel, Symfony, Actix, Axum, ASP.NET Core, Phoenix, Ktor), or a full-stack framework (Next.js, Nuxt, SvelteKit, Remix, Astro) |
| web-frontend | UI framework dependency (React, Vue, Angular, Svelte, Solid, Preact, Lit) or Vite |
| mobile-app | React Native, Expo, Flutter, Android Gradle plugin, `AndroidManifest.xml`, `.xcodeproj` |
| desktop-app | Electron, Tauri |
| cli | CLI frameworks (Cobra, urfave/cli, Click, Typer, commander, yargs, clap), `bin` in package.json, Python console scripts, `cmd/` entry points |
| static-site | Jekyll/Hugo/Docusaurus/MkDocs config, or only HTML/CSS with no manifests |
| cms-site | WordPress (`wp-config.php`, `wp-content/`) |
| infrastructure | IaC lines ≥ source lines |
| data-science | three or more notebooks |
| application / library | fallback: entry points found → application; manifests without entry points → library |

## Runtimes

A pinned version (e.g. `.nvmrc` `12.22.0`) wins over a range (`engines.node >=12`). When nothing declares a version, the primary language's runtime is listed without one.

## Findings

| Rule | Severity | Confidence | Trigger |
|---|---|---|---|
| `no-tests` | medium | high | ≥ 5 source files and no test files |
| `no-ci` | low | medium | ≥ 5 source files and no CI configuration |
| `no-readme` | low | high | no README at the repository root |
| `no-lockfile` | low | medium | npm / pyproject / Bundler / Composer (and Cargo applications) manifest without a lockfile in the same directory |
| `no-license` | info | medium | package.json with an entry point, not `private`, and no LICENSE file |

`no-ci` and `no-readme` contribute to the **Operability** score. `no-tests` is a maintainability finding. The Code Health capability owns the Maintainability score.

## Known limitations

- Tests outside common naming conventions are not recognised.
- CI configured outside the repository is not visible.
- The digest is structural: it ignores file contents by design.
