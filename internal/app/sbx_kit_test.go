// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

package app

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enclave/internal/backend"
	"enclave/internal/config"
	"enclave/internal/model"
)

func TestPrepareSBXKitComposesPublicNativeArtifactWithoutDocker(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	paths := model.Paths{AppRoot: root, Dockerfile: filepath.Join(root, "Dockerfile"), ExtensionsDir: filepath.Join(root, "extensions"), ToolsDir: filepath.Join(root, "extensions/tools"), FeaturesDir: filepath.Join(root, "extensions/features")}
	profile, err := config.LoadProfile(paths, "codex")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENAI_API_KEY", "ambient-secret-must-not-enter-artifact")
	// Artifact preparation must work without a Docker or SBX executable.
	t.Setenv("PATH", t.TempDir())
	opts := config.DefaultOptions()
	opts.Tool = "codex"
	opts.Features = []string{"github-cli"}
	host := model.Host{Home: t.TempDir()}
	input := &CommandInput{Ctx: NewAppContext(paths, t.TempDir())}
	req := backend.Request{Network: backend.NetworkPolicy{Mode: backend.NetworkModeRestricted, Egress: backend.EgressPolicy{AllowedDomains: []string{"api.openai.com"}}}}
	kit, err := prepareSBXKit(input, opts, profile, host, req)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"extensions/tools/codex/spec.yaml", "extensions/features/github-cli/spec.yaml", "native-env.sh", "entrypoint.sh"} {
		assertPathExists(t, filepath.Join(kit, file))
	}
	descriptor, err := os.ReadFile(filepath.Join(kit, "enclave.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"schemaVersion: \"3\"", "kind: workload", "proxyManaged: true"} {
		if !strings.Contains(string(descriptor), want) {
			t.Fatalf("missing %q in native declaration: %s", want, descriptor)
		}
	}
	recipe, err := os.ReadFile(filepath.Join(kit, "enclave.dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(recipe), "# feature: github-cli") || !strings.Contains(string(recipe), `ENTRYPOINT ["/usr/bin/env"]`) {
		t.Fatalf("native recipe lost composition: %s", recipe)
	}
	err = filepath.WalkDir(kit, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), "ambient-secret-must-not-enter-artifact") {
			t.Errorf("ambient credential copied into %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	again, err := prepareSBXKit(input, opts, profile, host, req)
	if err != nil {
		t.Fatal(err)
	}
	if again != kit {
		t.Fatalf("identical inputs produced distinct artifacts: %s and %s", kit, again)
	}
}
