// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enclave/internal/backend"
	"enclave/internal/config"
	"enclave/internal/model"
	"enclave/internal/network"
)

func nativeTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	home := resolvedTempDir(t)
	project := resolvedTempDir(t)
	writeRuntimeTestFile(t, filepath.Join(home, ".gitconfig"), "[user]\n name = Native Tester\n email = native@example.test\n")
	profile := model.Profile{Name: "native-test", Command: "native-tool", ConfigDir: ".native", SettingsFile: "native-test-settings.json", SettingsTarget: ".native/settings.json", AllowedDomains: []string{"api.example.test"}, Providers: []model.ProviderConfig{{Name: "provider", AuthFiles: []string{"auth.json"}}}, Secrets: map[string]model.SecretConfig{"token": {EnvVars: []string{"NATIVE_TOKEN"}}}, EnvVariables: map[string]string{"PUBLIC_SETTING": "public", "NATIVE_TOKEN": "do-not-inject"}}
	r := New(model.RuntimeConfig{Host: model.Host{Home: home, UID: "1000", GID: "1000"}, Project: model.Project{Dir: project, RealDir: project, Hash: "project", Name: "project"}, Profile: profile, Run: model.RunOptions{Tool: profile.Name, Persist: true, NoCache: true}, Paths: model.Paths{ToolsDir: filepath.Join(home, "extensions", "tools")}})
	writeRuntimeTestFile(t, filepath.Join(r.paths.ToolsDir, profile.Name, "templates", "settings.json"), "{\"base\":true}")
	writeRuntimeTestFile(t, filepath.Join(config.HostToolConfigDir(home, profile.Name), "auth.json"), "private-token")
	if err := os.Symlink("auth.json", filepath.Join(config.HostToolConfigDir(home, profile.Name), "alias.json")); err != nil {
		t.Fatal(err)
	}
	writeRuntimeTestFile(t, filepath.Join(project, ".env"), "PROJECT_SECRET=do-not-load\n")
	return r
}

func TestPrepareNativePreservesPublicSettingsWithoutCredentialStores(t *testing.T) {
	r := nativeTestRuntime(t)
	plan, err := r.PrepareNative()
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Release()
	if plan.ConfigDir == "" || plan.ConfigTarget != "/home/agent/.native" {
		t.Fatalf("config seed=%+v", plan)
	}
	if _, err := os.Stat(filepath.Join(plan.ConfigDir, "settings.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"auth.json", "alias.json"} {
		if _, err := os.Stat(filepath.Join(plan.ConfigDir, name)); !os.IsNotExist(err) {
			t.Fatalf("credential %s seeded: %v", name, err)
		}
	}
	if plan.Request.AuthSync != nil || len(plan.Request.Stores) > 0 || len(plan.Request.Secrets) > 0 {
		t.Fatal("native plan uses Enclave credential persistence")
	}
	for _, entry := range plan.Request.Env {
		if strings.Contains(entry.Name, "NATIVE_TOKEN") || strings.Contains(entry.Name, "PROJECT_SECRET") || strings.Contains(entry.Name, "GATEWAY") || strings.Contains(entry.Name, "ENCLAVE_AUTH") {
			t.Fatalf("unexpected credential/gateway env %q", entry.Name)
		}
	}
	for _, mount := range plan.Request.Mounts {
		if strings.Contains(mount.Source, "/auth/") || strings.Contains(mount.Source, "/secrets/") || mount.Source == filepath.Join(r.host.Home, ".gitconfig") {
			t.Fatalf("credential store mounted: %+v", mount)
		}
	}
	if len(plan.Request.Argv) < 3 || plan.Request.Argv[0] != "/usr/local/bin/enclave-native-env" || plan.Request.Argv[1] != "/usr/local/bin/entrypoint.sh" {
		t.Fatalf("native workload=%v", plan.Request.Argv)
	}
	if len(plan.Request.Network.Egress.AllowedDomains) != 1 || plan.Request.Network.Egress.AllowedDomains[0] != "api.example.test" {
		t.Fatalf("network policy=%+v", plan.Request.Network)
	}
	if _, err := os.Stat(config.HostStoreAuthRootDir(r.host.Home)); !os.IsNotExist(err) {
		t.Fatalf("Enclave auth store created: %v", err)
	}
}

func TestPrepareNativeRejectsPassingDeclaredCredentials(t *testing.T) {
	r := nativeTestRuntime(t)
	r.auth.PassEnv = []string{"NATIVE_TOKEN"}
	if _, err := r.PrepareNative(); err == nil || !strings.Contains(err.Error(), "SBX owns credential") {
		t.Fatalf("error=%v", err)
	}
}

func TestPrepareNativeUnrestrictedUsesNativeHostname(t *testing.T) {
	r := nativeTestRuntime(t)
	r.run.AllowAllNetwork = true
	plan, err := r.PrepareNative()
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Release()
	if plan.Request.Hostname != "" || plan.Request.Network.Mode != backend.NetworkModeUnrestricted {
		t.Fatalf("native unrestricted request=%+v", plan.Request)
	}
}
func TestPrepareNativeRejectsExplicitDNSResolvers(t *testing.T) {
	r := nativeTestRuntime(t)
	if err := network.SavePolicy(network.GlobalPolicyPath(r.host.Home), network.Policy{Advanced: network.PolicyAdvanced{Resolvers: []string{"1.1.1.1"}}}); err != nil {
		t.Fatal(err)
	}
	plan, err := r.PrepareNative()
	if plan != nil {
		plan.Release()
	}
	if err == nil || !strings.Contains(err.Error(), "owns DNS") {
		t.Fatalf("native resolver override accepted: %v", err)
	}
}
