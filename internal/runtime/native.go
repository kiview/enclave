// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"enclave/internal/backend"
	"enclave/internal/config"
	"enclave/internal/model"
	"enclave/internal/mounts"
	"enclave/internal/network"
	"enclave/internal/util"
)

// NativeSession contains public execution inputs. Credentials and tool state
// stay in the native sandbox; ConfigDir is a settings seed, never an auth store.
type NativeSession struct {
	Request      backend.Request
	ConfigDir    string
	ConfigTarget string
	Release      func()
}

// PrepareNative composes Enclave's tooling settings without its Docker image,
// credential stores, gateway, CA, or credential persistence machinery.
func (r *Runtime) PrepareNative() (*NativeSession, error) {
	r.run.Backend = backend.NameSBX
	release, err := r.acquireSessionStartLock()
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			release()
		}
	}()

	name := r.baseContainerName()
	if r.run.SessionName != "" || r.run.Background {
		name = r.containerName()
	}
	r.configVolReady = true
	r.configVolSuffix = model.ShortHash(util.HashString(name + "\x00" + r.project.RealDir))
	base, env := r.baseMounts()
	acc := newMountAccumulator(base, env)
	r.addAdditionalMounts(acc)
	r.addUserCommandMount(acc)
	r.addWorktreeMetadataMounts(acc)
	identity, err := resolveHostGitIdentity(r.host.Home, r.project.Dir)
	if err != nil {
		return nil, err
	}
	addHostGitIdentityEnv(acc, identity)
	if err := validateGitIdentity(identity, acc.Env()); err != nil {
		return nil, err
	}
	if err := r.protectGitConfigFiles(acc); err != nil {
		return nil, err
	}
	if err := r.addCacheMounts(acc); err != nil {
		return nil, err
	}
	r.addHistoryMounts(acc)
	r.addMemoryMounts(acc)
	if r.run.NoHistory {
		acc.AddEnv("HISTFILE", "/dev/null")
	}
	known := map[string]bool{}
	for _, key := range r.profile.DeclaredSecretEnvVars() {
		known[key] = true
	}
	for _, feature := range r.features {
		for _, key := range feature.DeclaredSecretEnvVars() {
			known[key] = true
		}
	}
	for _, key := range r.specProxyManaged() {
		known[key] = true
	}
	for _, key := range r.auth.PassEnv {
		if known[key] {
			return nil, fmt.Errorf("native SBX owns credential %s; configure it through sbx instead of --pass-env", key)
		}
		if value, ok := os.LookupEnv(key); ok {
			acc.AddEnv(key, value)
		}
	}
	publicEnv := []string{}
	for _, entry := range acc.Env() {
		key, _, _ := strings.Cut(entry, "=")
		if !known[key] {
			publicEnv = append(publicEnv, entry)
		}
	}
	plan := &NativeSession{Release: release}
	if r.profile.ConfigDir != "" {
		global := config.HostToolConfigDir(r.host.Home, r.profile.Name)
		project := config.HostProjectConfigDir(r.host.Home, r.project.Hash, r.profile.Name)
		generated := r.generatedConfigSourceDir()
		for _, dir := range []string{global, project, generated} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, err
			}
		}
		if err := r.withToolDataLock(config.HostProjectToolDir(r.host.Home, r.project.Hash, r.profile.Name), "config-source", func() error {
			if err := r.composeGeneratedConfigDir(generated, global, project); err != nil {
				return err
			}
			return scrubNativeConfig(generated, config.HostConfigPassthroughDeniedPaths(r.profile))
		}); err != nil {
			return nil, err
		}
		plan.ConfigDir = generated
		plan.ConfigTarget = resolveContainerProfilePath(r.containerHome, r.profile.ConfigDir)
	}
	runCtx := r.prepareRunContext(model.AuthState{})
	r.applyPortHints(&runCtx)
	r.applyProfilePorts()
	r.applyFeaturePorts()
	resolved, err := r.resolveEffectivePolicy()
	if err != nil {
		return nil, err
	}
	if len(resolved.Effective.Resolvers) > 0 {
		return nil, fmt.Errorf("native SBX owns DNS; Enclave network advanced.resolvers overrides are unavailable")
	}
	allowed, denied, err := network.EffectiveRenderDomainsForTool(resolved.Effective, r.profile.Name)
	if err != nil {
		return nil, err
	}
	mode := backend.NetworkModeRestricted
	if resolved.Effective.Mode == model.NetworkModeUnrestricted {
		mode = backend.NetworkModeUnrestricted
	}
	ctx := &ExecutionContext{ContainerName: name, Env: publicEnv, Mounts: acc.Mounts(), ProtectedFiles: acc.protectedFiles, Network: backend.NetworkPolicy{Mode: mode, Egress: backend.EgressPolicy{AllowedDomains: allowed, DeniedDomains: denied, Resolvers: resolved.Effective.Resolvers}}, Ports: mounts.ResolvePorts(r.run.Ports)}
	plan.Request = r.backendRequest(ctx, r.run.Background, true)
	plan.Request.Image = ""
	plan.Request.Hostname = ""
	plan.Request.Ephemeral = r.run.Ephemeral
	plan.Request.Argv = append([]string{"/usr/local/bin/enclave-native-env", "/usr/local/bin/entrypoint.sh"}, plan.Request.Argv...)
	ready = true
	return plan, nil
}

func scrubNativeConfig(root string, denied []string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		for _, pattern := range denied {
			pattern = strings.TrimSuffix(filepath.ToSlash(pattern), "/")
			match, _ := filepath.Match(pattern, relative)
			if match || relative == pattern || strings.HasPrefix(relative, pattern+"/") {
				if err := os.RemoveAll(path); err != nil {
					return err
				}
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		return nil
	})
}
