// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

package sbxkit

import (
	"reflect"
	"strings"
	"testing"

	"enclave/internal/backend"
	"enclave/internal/model"
	"sigs.k8s.io/yaml"
)

func TestNativeKitDeclaresProxyOnlyCredentialsAndPolicy(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "must-never-enter-kit")
	raw, aliases, err := Render("codex", backend.NetworkPolicy{Mode: backend.NetworkModeRestricted, Egress: backend.EgressPolicy{AllowedDomains: []string{"api.openai.com", "github.com", "api.openai.com"}, DeniedDomains: []string{"blocked.example"}}}, map[string]model.SecretConfig{"openai-api-key": {EnvVars: []string{"CODEX_API_KEY", "OPENAI_API_KEY"}, Release: &model.SecretReleaseConfig{HTTP: &model.HTTPSecretReleaseConfig{Hosts: []string{"api.openai.com"}, Header: "Authorization", Format: "Bearer %s"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "must-never-enter-kit") {
		t.Fatal("secret value in kit")
	}
	if aliases["OPENAI_API_KEY"] != "CODEX_API_KEY" {
		t.Fatalf("aliases=%v", aliases)
	}
	var doc struct {
		SchemaVersion string `json:"schemaVersion"`
		Kind          string `json:"kind"`
		Capabilities  []struct {
			Type     string         `json:"type"`
			Optional bool           `json:"optional"`
			Config   map[string]any `json:"config"`
		} `json:"capabilities"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != "3" || doc.Kind != "workload" {
		t.Fatalf("wrong kit: %s", raw)
	}
	if len(doc.Capabilities) != 3 {
		t.Fatalf("capabilities=%v", doc.Capabilities)
	}
	credential := doc.Capabilities[2]
	if credential.Type != "com.docker.sandbox/credential@1" || !credential.Optional || credential.Config["service"] != "openai" {
		t.Fatalf("credential=%v", credential)
	}
	key := credential.Config["apiKey"].(map[string]any)
	if key["proxyManaged"] != true || key["name"] != "CODEX_API_KEY" {
		t.Fatalf("unsafe credential=%v", key)
	}
	rules := doc.Capabilities[1].Config["runtime"].(map[string]any)
	if !reflect.DeepEqual(rules["allow"], []any{"**.api.openai.com", "**.github.com", "api.openai.com", "github.com"}) {
		t.Fatalf("rules=%v", rules)
	}
	if !reflect.DeepEqual(rules["deny"], []any{"**.blocked.example", "blocked.example"}) {
		t.Fatalf("rules=%v", rules)
	}
}

func TestNativeKitDoesNotReinterpretOAuthAsAPIKey(t *testing.T) {
	apiKey := false
	raw, _, err := Render("codex", backend.NetworkPolicy{}, map[string]model.SecretConfig{"codex-access-token": {APIKey: &apiKey, EnvVars: []string{"CODEX_ACCESS_TOKEN"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "credential@1") {
		t.Fatalf("OAuth imported as API key: %s", raw)
	}
}
func TestNativeKitRejectsUntranslatableCredentialDeclaration(t *testing.T) {
	_, _, err := Render("custom", backend.NetworkPolicy{}, map[string]model.SecretConfig{"custom-api-key": {EnvVars: []string{"UNKNOWN_API_KEY"}, Release: &model.SecretReleaseConfig{HTTP: &model.HTTPSecretReleaseConfig{Hosts: []string{"example.com"}}}}})
	if err == nil {
		t.Fatal("silently accepted unknown credential mapping")
	}
}

func githubRelease(header string, hosts ...string) *model.SecretReleaseConfig {
	return &model.SecretReleaseConfig{HTTP: &model.HTTPSecretReleaseConfig{Hosts: hosts, Header: header, Format: "Bearer %s"}}
}

func TestNativeKitMapsCopilotTokenToSBXGitHubService(t *testing.T) {
	raw, aliases, err := Render("copilot", backend.NetworkPolicy{}, map[string]model.SecretConfig{
		"copilot-github-token": {EnvVars: []string{"COPILOT_GITHUB_TOKEN"}, Release: githubRelease("Authorization", "api.github.com", "*.githubcopilot.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := nativeCredentials(t, raw)
	if len(credentials) != 1 || credentials[0].Service != "github" || credentials[0].APIKey.Name != "COPILOT_GITHUB_TOKEN" || !credentials[0].APIKey.ProxyManaged {
		t.Fatalf("credentials=%+v", credentials)
	}
	if len(aliases) != 0 {
		t.Fatalf("aliases=%v", aliases)
	}
}

func TestNativeKitMergesDeclarationsForOneSBXService(t *testing.T) {
	raw, aliases, err := Render("copilot", backend.NetworkPolicy{}, map[string]model.SecretConfig{
		"copilot-github-token": {EnvVars: []string{"COPILOT_GITHUB_TOKEN"}, Release: githubRelease("Authorization", "api.github.com", "*.githubcopilot.com")},
		"github-token":         {EnvVars: []string{"GH_TOKEN", "GITHUB_TOKEN"}, Release: githubRelease("authorization", "api.github.com", "*.githubusercontent.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := nativeCredentials(t, raw)
	if len(credentials) != 1 || credentials[0].Service != "github" || credentials[0].APIKey.Name != "COPILOT_GITHUB_TOKEN" {
		t.Fatalf("credentials=%+v", credentials)
	}
	var domains []string
	for _, injection := range credentials[0].APIKey.Inject {
		domains = append(domains, injection.Domain)
	}
	if !reflect.DeepEqual(domains, []string{"*.githubcopilot.com", "*.githubusercontent.com", "api.github.com"}) {
		t.Fatalf("domains=%v", domains)
	}
	if !reflect.DeepEqual(aliases, map[string]string{"GH_TOKEN": "COPILOT_GITHUB_TOKEN", "GITHUB_TOKEN": "COPILOT_GITHUB_TOKEN"}) {
		t.Fatalf("aliases=%v", aliases)
	}
}

func TestNativeKitRejectsConflictingInjectionForOneSBXService(t *testing.T) {
	_, _, err := Render("copilot", backend.NetworkPolicy{}, map[string]model.SecretConfig{
		"copilot-github-token": {EnvVars: []string{"COPILOT_GITHUB_TOKEN"}, Release: githubRelease("Authorization", "api.github.com")},
		"github-token":         {EnvVars: []string{"GH_TOKEN"}, Release: githubRelease("X-Token", "api.github.com")},
	})
	if err == nil || !strings.Contains(err.Error(), "conflicting injection rules for api.github.com") {
		t.Fatalf("accepted conflicting injection rules for one domain: %v", err)
	}
}

func nativeCredentials(t *testing.T, raw []byte) []Credential {
	t.Helper()
	var doc struct {
		Capabilities []struct {
			Type   string     `json:"type"`
			Config Credential `json:"config"`
		} `json:"capabilities"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var credentials []Credential
	for _, capability := range doc.Capabilities {
		if capability.Type == "com.docker.sandbox/credential@1" {
			credentials = append(credentials, capability.Config)
		}
	}
	return credentials
}
