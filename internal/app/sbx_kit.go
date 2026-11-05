// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"enclave/internal/backend"
	"enclave/internal/config"
	"enclave/internal/logx"
	"enclave/internal/model"
	"enclave/internal/sbxkit"
	"enclave/internal/util"
)

func prepareSBXKit(input *CommandInput, opts model.Options, profile model.Profile, host model.Host, req backend.Request) (string, error) {
	paths := input.Ctx.Paths
	selection, err := resolveRuntimeImageSelection(paths, opts.BuildOptions, profile.Name)
	if err != nil {
		return "", err
	}
	installs, err := resolveFeatureInstalls(paths, selection.Features, true)
	if err != nil {
		return "", err
	}
	recipe, err := renderDockerfile(paths.Dockerfile, selection.Tools, installs, nil, nil)
	if err != nil {
		return "", err
	}
	// A native workload uses SBX's agent identity, not a nested Docker user.
	defaults := map[string]string{"AGENT_TOOLS": strings.Join(selection.Tools, ","), "FEATURES": strings.Join(selection.Features, ",")}
	if opts.BaseImage != "" {
		defaults["BASE_IMAGE"] = opts.BaseImage
	}
	for key, value := range defaults {
		if strings.ContainsAny(value, "\r\n") {
			return "", fmt.Errorf("invalid native build argument %s", key)
		}
		lines := strings.Split(recipe, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "ARG "+key+"=") {
				lines[i] = "ARG " + key + "=" + value
			}
		}
		recipe = strings.Join(lines, "\n")
	}
	lines := strings.Split(recipe, "\n")
	var filtered []string
	for _, line := range lines {
		if strings.HasPrefix(line, "ENTRYPOINT ") || strings.HasPrefix(line, "CMD ") {
			continue
		}
		filtered = append(filtered, line)
	}
	recipe = strings.Join(filtered, "\n")
	// The SBX workload is the image itself; it has no engine or gateway sidecar.
	recipe += "\nUSER root\nRUN apt-get update && apt-get install -y --no-install-recommends tmux && rm -rf /var/lib/apt/lists/*\nUSER agent\nENTRYPOINT [\"/usr/bin/env\"]\nCMD [\"/bin/bash\"]\n"
	secrets := map[string]model.SecretConfig{}
	for name, secret := range profile.Secrets {
		secrets[name] = secret
	}
	features, err := resolveFeatureSelection(paths, opts.BuildOptions)
	if err != nil {
		return "", err
	}
	for _, feature := range features.enabled {
		for name, secret := range feature.Secrets {
			if name == "github-enterprise-token" {
				logx.Warnf("Native SBX does not import GitHub Enterprise credentials from Enclave; configure a custom secret with sbx for enterprise hosts")
				continue
			}
			if _, exists := secrets[name]; exists {
				return "", fmt.Errorf("duplicate native SBX credential declaration %s", name)
			}
			secrets[name] = secret
		}
	}
	if opts.NoAPIKey || (opts.Ephemeral && !opts.PassAPIKey) {
		secrets = nil
	}
	descriptor, aliases, err := sbxkit.Render(profile.Name, req.Network, secrets)
	if err != nil {
		return "", err
	}
	cache := filepath.Join(config.HostCacheDir(host.Home), "sbx-kits")
	if err = os.MkdirAll(cache, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(cache, ".prepare-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	copyInput := func(src, dst string, mode os.FileMode) error {
		if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
			return err
		}
		return copyFile(src, dst, mode)
	}
	for _, name := range []string{"entrypoint.sh", "runtime-assets", "docs"} {
		if err = util.CopyTree(filepath.Join(paths.AppRoot, name), filepath.Join(dir, name), copyInput); err != nil {
			return "", err
		}
	}
	for _, name := range []string{"tools", "features"} {
		if err = os.MkdirAll(filepath.Join(dir, "extensions", name), 0750); err != nil {
			return "", err
		}
	}
	files, err := mergedExtensionFiles(paths, selection)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if err = copyInput(file.SourcePath, filepath.Join(dir, filepath.FromSlash(file.RelativePath)), file.Mode.Perm()); err != nil {
			return "", err
		}
	}
	// Alias only SBX-issued sentinels, never values from host environment/state.
	var aliasScript strings.Builder
	aliasScript.WriteString("#!/bin/sh\nset -eu\n")
	aliasScript.WriteString(`if [ -r /etc/ssl/certs/ca-certificates.crt ]; then
 : "${NODE_EXTRA_CA_CERTS:=/etc/ssl/certs/ca-certificates.crt}"
 : "${REQUESTS_CA_BUNDLE:=/etc/ssl/certs/ca-certificates.crt}"
 : "${SSL_CERT_FILE:=/etc/ssl/certs/ca-certificates.crt}"
 export NODE_EXTRA_CA_CERTS REQUESTS_CA_BUNDLE SSL_CERT_FILE
fi
`)
	names := make([]string, 0, len(aliases))
	for name := range aliases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !nativeEnvName(name) || !nativeEnvName(aliases[name]) {
			return "", fmt.Errorf("invalid credential environment alias %q", name)
		}
		fmt.Fprintf(&aliasScript, "if [ -n \"${%s:-}\" ]; then export %s=\"$%s\"; fi\n", aliases[name], name, aliases[name])
	}
	aliasScript.WriteString("exec \"$@\"\n")
	recipe += "USER root\nCOPY native-env.sh /usr/local/bin/enclave-native-env\nRUN chmod 0755 /usr/local/bin/enclave-native-env\nUSER agent\n"
	// Native mount provisioning can create missing parent directories as root.
	// Prepare only guest-home destinations while the image is still trusted.
	homeDirs := map[string]bool{}
	if profile.ConfigDir != "" {
		target := profile.ConfigDir
		if !filepath.IsAbs(target) {
			target = filepath.Join("/home/agent", target)
		}
		if util.PathWithin("/home/agent", target) {
			homeDirs[filepath.Clean(target)] = true
		}
	}
	for _, mount := range req.Mounts {
		target := filepath.Clean(mount.ContainerPath)
		if util.PathWithin("/home/agent", target) {
			homeDirs[filepath.Dir(target)] = true
		}
	}
	destinations := make([]string, 0, len(homeDirs))
	for target := range homeDirs {
		if util.PathWithin("/home/agent", target) {
			destinations = append(destinations, target)
		}
	}
	sort.Strings(destinations)
	if len(destinations) > 0 {
		quoted := make([]string, 0, len(destinations))
		for _, target := range destinations {
			quoted = append(quoted, util.ShellQuote(filepath.ToSlash(target)))
		}
		recipe += "USER root\nRUN mkdir -p -- " + strings.Join(quoted, " ") + " && chown -R agent:agent /home/agent\nUSER agent\n"
	}

	for name, data := range map[string]string{"enclave.yaml": string(descriptor), "enclave.dockerfile": recipe, "native-env.sh": aliasScript.String()} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			return "", err
		}
	}
	digest, err := nativeKitHash(dir)
	if err != nil {
		return "", err
	}
	target := filepath.Join(cache, "enclave-"+digest)
	if _, err = os.Stat(target); err == nil {
		return target, nil
	}
	if err = os.Rename(dir, target); err != nil {
		if _, statErr := os.Stat(target); statErr != nil {
			return "", err
		}
	}
	return target, nil
}
func nativeEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		letter := c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
		digit := i > 0 && c >= '0' && c <= '9'
		if !letter && !digit {
			return false
		}
	}
	return true
}
func nativeKitHash(root string) (string, error) {
	hash := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported native kit input %s", rel)
		}
		_, _ = fmt.Fprintf(hash, "%s\x00%d\x00", filepath.ToSlash(rel), info.Mode().Perm())
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(hash, f)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
