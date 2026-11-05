// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

package app

import (
	"testing"

	"enclave/internal/backend"
	"enclave/internal/config"
	"enclave/internal/model"
)

func TestNativeSBXSkipsDockerButPreservesFeatureSelection(t *testing.T) {
	paths := testPathsWithFeatureDefaults(t)
	opts := config.DefaultOptions()
	opts.Backend = backend.NameSBX
	opts.Tool = "codex"
	opts.Features = []string{"node-dev"}
	if executionRequiresDocker("run", opts) {
		t.Fatal("native SBX requires host Docker")
	}
	got, _, _, build, err := ValidateRunOptions(opts, model.DefaultOptionSources(), ValidationContext{Action: "run", Paths: paths}, model.Project{Dir: t.TempDir(), Hash: "project"})
	if err != nil {
		t.Fatal(err)
	}
	if build == nil || got.AllowAllNetwork || len(got.Features) != 1 || got.Features[0] != "node-dev" {
		t.Fatalf("native composition changed: %+v", got)
	}
}

func TestNativeSBXRejectsDockerAndCredentialStoreFlags(t *testing.T) {
	for _, change := range []func(*model.Options){func(o *model.Options) { o.BridgePorts = []string{"3000"} }, func(o *model.Options) { o.NetworkLog = model.NetworkLogRequests }, func(o *model.Options) { o.NoRebuild = true }, func(o *model.Options) { o.ForceRebuild = true }, func(o *model.Options) { o.Slim = true }, func(o *model.Options) { o.BuildUID = "501" }, func(o *model.Options) { o.PassAPIKey = true }, func(o *model.Options) { o.ResetAuth = true }, func(o *model.Options) { o.Background = true; o.Ephemeral = true }} {
		opts := config.DefaultOptions()
		change(&opts)
		if err := validateNativeSBXOptions(opts, model.DefaultOptionSources()); err == nil {
			t.Fatal("unsupported native options accepted")
		}
	}
}

func TestNativeSBXGatewayAndAuthActionsFailBeforeDispatch(t *testing.T) {
	for _, action := range []string{"cleanup", "auth-import", "auth-export", "network-apply", "network-status", "update"} {
		opts := config.DefaultOptions()
		opts.Backend = backend.NameSBX
		if _, err := resolveActionBackend(action, &opts, false); err == nil {
			t.Fatalf("unsupported %s action accepted", action)
		}
	}
}
