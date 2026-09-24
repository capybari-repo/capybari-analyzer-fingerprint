package fingerprint

import (
	"bytes"
	"encoding/json"
	"context"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/capybari/capybari-core/facts"
)

var (
	goMain     = regexp.MustCompile(`(?m)^package main\b`)
	goMainFunc = regexp.MustCompile(`(?m)^func main\(\)`)
	pyMain     = regexp.MustCompile(`(?m)^if __name__ == ['"]__main__['"]`)
	javaMain   = regexp.MustCompile(`public\s+static\s+void\s+main\s*\(`)
	csMain     = regexp.MustCompile(`static\s+(?:async\s+)?(?:void|int|Task)\s+Main\s*\(`)
)

// entryPoints finds executables and servers: Go main packages, Node
// main/bin/start scripts, Python __main__ guards, Java/C# Main methods,
// Rust binaries, Dockerfile commands and Procfiles.
func (s *scan) entryPoints() {
	add := func(p string) { s.fp.EntryPoints = append(s.fp.EntryPoints, p) }
	for _, f := range s.ownFiles() {
		if f.Kind != facts.KindSource && f.Kind != facts.KindContainer && f.Kind != facts.KindBuild && f.Kind != facts.KindOther && f.Kind != facts.KindConfig {
			continue
		}
		base := strings.ToLower(path.Base(f.Path))
		switch {
		case f.Language == "Go" && f.Kind == facts.KindSource:
			b := s.read(f.Path)
			if goMain.Match(b) && goMainFunc.Match(b) {
				add(path.Dir(f.Path) + "/")
			}
		case f.Language == "Python" && f.Kind == facts.KindSource:
			if base == "__main__.py" || base == "manage.py" || base == "wsgi.py" || base == "asgi.py" {
				add(f.Path)
				continue
			}
			if pyMain.Match(s.read(f.Path)) {
				add(f.Path)
			}
		case f.Language == "Java" && f.Kind == facts.KindSource:
			if javaMain.Match(s.read(f.Path)) {
				add(f.Path)
			}
		case f.Language == "C#" && f.Kind == facts.KindSource:
			if base == "program.cs" || csMain.Match(s.read(f.Path)) {
				add(f.Path)
			}
		case f.Language == "Rust" && (f.Path == "src/main.rs" || strings.HasPrefix(f.Path, "src/bin/")):
			add(f.Path)
		case base == "procfile":
			add(f.Path)
		case f.Kind == facts.KindContainer && strings.HasPrefix(base, "dockerfile"):
			if bytes.Contains(s.read(f.Path), []byte("CMD")) || bytes.Contains(s.read(f.Path), []byte("ENTRYPOINT")) {
				add(f.Path)
			}
		}
	}
	// Node: package.json main / bin / start script.
	if s.has("package.json") {
		var pj packageJSON
		if err := json.Unmarshal(s.read("package.json"), &pj); err == nil {
			if pj.Main != "" && s.has(path.Clean(pj.Main)) {
				add(path.Clean(pj.Main))
			}
			if start := pj.Scripts["start"]; start != "" {
				for _, tok := range strings.Fields(start) {
					if (strings.HasSuffix(tok, ".js") || strings.HasSuffix(tok, ".ts") || strings.HasSuffix(tok, ".mjs")) && s.has(path.Clean(tok)) {
						add(path.Clean(tok))
					}
				}
			}
		}
	}
}

// projectTypes classifies the repository with transparent heuristics.
func (s *scan) projectTypes() {
	set := map[string]bool{}
	anyDep := func(names ...string) bool {
		for _, n := range names {
			if s.deps[n] {
				return true
			}
		}
		return false
	}
	if anyDep("express", "fastify", "koa", "@nestjs/core", "hapi", "@hapi/hapi", "restify", "flask", "django", "fastapi", "starlette", "tornado", "aiohttp",
		"github.com/gin-gonic/gin", "github.com/labstack/echo/v4", "github.com/gofiber/fiber/v2", "github.com/go-chi/chi/v5", "github.com/gorilla/mux",
		"spring-boot-starter-web", "spring-boot-starter-webflux", "rails", "sinatra", "laravel/framework", "symfony/framework-bundle", "slim/slim",
		"actix-web", "axum", "rocket", "aspnetcore", "phoenix", "ktor-server-core") {
		set["web-backend"] = true
	}
	if anyDep("react", "vue", "@angular/core", "svelte", "solid-js", "preact", "lit", "next", "nuxt", "@sveltejs/kit", "astro", "gatsby", "@remix-run/react", "vite") {
		set["web-frontend"] = true
	}
	if anyDep("next", "nuxt", "@sveltejs/kit", "@remix-run/node", "astro") {
		set["web-backend"] = true
	}
	if anyDep("react-native", "expo", "flutter", "android") || s.hasSuffixFile("androidmanifest.xml") || s.hasSuffixDir(".xcodeproj") {
		set["mobile-app"] = true
	}
	if anyDep("electron", "tauri", "@tauri-apps/api") {
		set["desktop-app"] = true
	}
	if anyDep("github.com/spf13/cobra", "github.com/urfave/cli/v2", "click", "typer", "commander", "yargs", "clap") || s.nodeBin || s.pyScripts {
		set["cli"] = true
	}
	for _, e := range s.fp.EntryPoints {
		if strings.HasPrefix(e, "cmd/") && !set["web-backend"] {
			set["cli"] = true
		}
	}
	if s.has("_config.yml") || s.has("hugo.toml") || s.has("config.toml") && s.hasSuffixDir("content") || s.hasSuffixFile("docusaurus.config.js") || s.has("mkdocs.yml") {
		set["static-site"] = true
	}
	if s.has("wp-config.php") || s.has("wp-content") || s.hasPrefix("wp-content/") {
		set["cms-site"] = true
	}

	var lines = map[facts.FileKind]int{}
	for _, f := range s.ownFiles() {
		lines[f.Kind] += f.Lines
	}
	if lines[facts.KindIaC] > 0 && lines[facts.KindIaC] >= lines[facts.KindSource] {
		set["infrastructure"] = true
	}
	notebooks := 0
	for _, f := range s.ownFiles() {
		if f.Language == "Jupyter Notebook" {
			notebooks++
		}
	}
	if notebooks >= 3 {
		set["data-science"] = true
	}
	htmlOnly := len(s.fp.Manifests) == 0 && len(s.inv.Languages) > 0 && (s.inv.Languages[0].Language == "HTML" || s.inv.Languages[0].Language == "CSS")
	if htmlOnly {
		set["static-site"] = true
	}
	if len(set) == 0 {
		switch {
		case len(s.fp.EntryPoints) > 0:
			set["application"] = true
		case s.nodeHasMain && !s.nodePrivate, len(s.fp.Manifests) > 0:
			set["library"] = true
		default:
			set["unknown"] = true
		}
	}
	if len(s.fp.EntryPoints) > 0 && !set["library"] && !set["unknown"] {
		set["application"] = true
	}
	s.fp.ProjectTypes = keys(set)
}

func (s *scan) hasSuffixFile(suffix string) bool {
	for p := range s.byPath {
		if strings.HasSuffix(strings.ToLower(p), suffix) {
			return true
		}
	}
	return false
}

func (s *scan) hasSuffixDir(suffix string) bool {
	for p := range s.byPath {
		if strings.Contains(strings.ToLower(p), suffix+"/") {
			return true
		}
	}
	return false
}

func (s *scan) hasPrefix(prefix string) bool {
	for p := range s.byPath {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

var licensePatterns = []struct {
	id    string
	match []string
}{
	{"AGPL-3.0", []string{"GNU AFFERO GENERAL PUBLIC LICENSE"}},
	{"LGPL-3.0", []string{"GNU LESSER GENERAL PUBLIC LICENSE", "Version 3"}},
	{"LGPL-2.1", []string{"GNU LESSER GENERAL PUBLIC LICENSE", "Version 2.1"}},
	{"GPL-3.0", []string{"GNU GENERAL PUBLIC LICENSE", "Version 3"}},
	{"GPL-2.0", []string{"GNU GENERAL PUBLIC LICENSE", "Version 2"}},
	{"Apache-2.0", []string{"Apache License", "Version 2.0"}},
	{"MPL-2.0", []string{"Mozilla Public License", "2.0"}},
	{"MIT", []string{"Permission is hereby granted, free of charge"}},
	{"BSD-3-Clause", []string{"Redistribution and use in source and binary forms", "Neither the name"}},
	{"BSD-2-Clause", []string{"Redistribution and use in source and binary forms"}},
	{"ISC", []string{"Permission to use, copy, modify, and/or distribute this software for any purpose"}},
	{"Unlicense", []string{"This is free and unencumbered software released into the public domain"}},
	{"EPL-2.0", []string{"Eclipse Public License", "2.0"}},
}

// license identifies the root license file by its characteristic text.
func (s *scan) license() string {
	for p := range s.byPath {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "/") {
			continue
		}
		if !(strings.HasPrefix(lower, "license") || strings.HasPrefix(lower, "licence") || strings.HasPrefix(lower, "copying")) {
			continue
		}
		body := string(s.read(p))
		if len(body) > 8192 {
			body = body[:8192]
		}
		for _, lp := range licensePatterns {
			ok := true
			for _, m := range lp.match {
				if !strings.Contains(body, m) {
					ok = false
					break
				}
			}
			if ok {
				return lp.id
			}
		}
		return "Other"
	}
	return ""
}

// gitInfo summarises local history using the git binary.
func gitInfo(ctx context.Context, root string) (*facts.GitInfo, error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return nil, err
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, err
	}
	run := func(args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, git, append([]string{"-C", root}, args...)...).Output()
		return strings.TrimSpace(string(out)), err
	}
	log, err := run("log", "--no-merges", "--format=%ae%x09%at", "-n", "20000")
	if err != nil {
		return nil, err
	}
	g := &facts.GitInfo{}
	authors := map[string]bool{}
	for _, line := range strings.Split(log, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		g.Commits++
		authors[strings.ToLower(parts[0])] = true
		sec, _ := strconv.ParseInt(parts[1], 10, 64)
		t := time.Unix(sec, 0).UTC()
		if g.LastCommit.IsZero() || t.After(g.LastCommit) {
			g.LastCommit = t
		}
		if g.FirstCommit.IsZero() || t.Before(g.FirstCommit) {
			g.FirstCommit = t
		}
	}
	g.Contributors = len(authors)
	g.Branch, _ = run("rev-parse", "--abbrev-ref", "HEAD")
	g.Head, _ = run("rev-parse", "--short=12", "HEAD")
	if _, err := os.Stat(filepath.Join(root, ".git", "shallow")); err == nil {
		g.Shallow = true
	}
	return g, nil
}
