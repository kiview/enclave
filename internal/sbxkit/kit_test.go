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
