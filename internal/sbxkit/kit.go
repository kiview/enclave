// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

// Package sbxkit translates Enclave requirements into native SBX capabilities.
package sbxkit

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"enclave/internal/backend"
	"enclave/internal/model"
	"sigs.k8s.io/yaml"
)

type Descriptor struct {
	SchemaVersion string       `json:"schemaVersion"`
	Kind          string       `json:"kind"`
	Description   string       `json:"description"`
	Capabilities  []Capability `json:"capabilities"`
}
type Capability struct {
	Type     string `json:"type"`
	Optional bool   `json:"optional,omitempty"`
	Config   any    `json:"config,omitempty"`
}
type Network struct {
	Runtime Rules `json:"runtime"`
}
type Rules struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}
type Credential struct {
	Service string `json:"service"`
	Phase   string `json:"phase"`
	APIKey  APIKey `json:"apiKey"`
}
type APIKey struct {
	Name         string      `json:"name"`
	ProxyManaged bool        `json:"proxyManaged"`
	Inject       []Injection `json:"inject"`
}
type Injection struct {
	Domain string `json:"domain"`
	Header string `json:"header"`
	Format string `json:"format"`
}

// Render accepts declarations only. Secret values never belong in a kit.
// aliases maps additional tool environment names to SBX's sentinel variable.
func Render(tool string, network backend.NetworkPolicy, secrets map[string]model.SecretConfig) ([]byte, map[string]string, error) {
	d := Descriptor{SchemaVersion: "3", Kind: "workload", Description: "Enclave environment for " + tool,
		Capabilities: []Capability{{Type: "com.docker.sandbox/sbx@1"}}}
	rules := Rules{Allow: nativeDomains(network.Egress.AllowedDomains), Deny: nativeDomains(network.Egress.DeniedDomains)}
	if network.Mode == backend.NetworkModeUnrestricted {
		rules.Allow = []string{"**"}
	}
	d.Capabilities = append(d.Capabilities, Capability{Type: "com.docker.sandbox/network-policy@1", Config: Network{Runtime: rules}})
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	aliases := map[string]string{}
	for _, name := range names {
		secret := secrets[name]
		// OAuth/file authentication is owned by SBX; Enclave does not import it
		// into a workload or reinterpret a bearer token as a provider API key.
		if secret.APIKey != nil && !*secret.APIKey {
			continue
		}
		if secret.Release == nil || secret.Release.HTTP == nil || len(secret.EnvVars) == 0 {
			continue
		}
		release := secret.Release.HTTP
		if release.HostsFromSecret != "" || release.RequiredValuePrefix != "" {
			return nil, nil, fmt.Errorf("SBX credential %s requires a static HTTP release declaration", name)
		}
		service, ok := serviceFor(name, secret.EnvVars)
		if !ok {
			return nil, nil, fmt.Errorf("SBX has no service mapping for credential %s; use an SBX custom secret instead", name)
		}
		primary := secret.EnvVars[0]
		key := APIKey{Name: primary, ProxyManaged: true}
		for _, host := range sortedUnique(release.Hosts) {
			format := release.Format
			if format == "" {
				format = "%s"
			}
			key.Inject = append(key.Inject, Injection{Domain: host, Header: release.Header, Format: format})
			rules.Allow = append(rules.Allow, host)
		}
		if len(key.Inject) == 0 {
			return nil, nil, fmt.Errorf("SBX credential %s has no release hosts", name)
		}
		d.Capabilities = append(d.Capabilities, Capability{Type: "com.docker.sandbox/credential@1", Optional: true, Config: Credential{Service: service, Phase: "runtime", APIKey: key}})
		for _, alias := range secret.EnvVars[1:] {
			aliases[alias] = primary
		}
	}
	rules.Allow = sortedUnique(rules.Allow)
	d.Capabilities[1].Config = Network{Runtime: rules}
	raw, err := yaml.Marshal(d)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte("# syntax=docker/sandbox-kit:3\n"), raw...), aliases, nil
}

func serviceFor(name string, env []string) (string, bool) {
	byEnv := map[string]string{"ANTHROPIC_API_KEY": "anthropic", "OPENAI_API_KEY": "openai", "CODEX_API_KEY": "openai", "GH_TOKEN": "github", "GITHUB_TOKEN": "github", "GEMINI_API_KEY": "google", "GOOGLE_API_KEY": "google", "GROQ_API_KEY": "groq", "MISTRAL_API_KEY": "mistral", "NEBIUS_API_KEY": "nebius", "OPENROUTER_API_KEY": "openrouter", "XAI_API_KEY": "xai"}
	for _, key := range env {
		if service, ok := byEnv[key]; ok {
			return service, true
		}
	}
	service := strings.TrimSuffix(name, "-api-key")
	for _, known := range []string{"anthropic", "openai", "github", "copilot", "cursor", "devin", "droid", "google", "groq", "mistral", "nebius", "openrouter", "xai"} {
		if service == known {
			return service, true
		}
	}
	return "", false
}
func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

// Enclave domain rules include the apex and every subdomain. SBX bare hosts
// are exact matches, so preserve the declaration's scope explicitly.
func nativeDomains(domains []string) []string {
	var result []string
	for _, domain := range domains {
		result = append(result, domain)
		if domain != "localhost" && net.ParseIP(domain) == nil && !strings.ContainsAny(domain, "*:[]") {
			result = append(result, "**."+domain)
		}
	}
	return sortedUnique(result)
}
