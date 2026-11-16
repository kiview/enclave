// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"enclave/internal/backend"
	backendsbx "enclave/internal/backend/sbx"
	"enclave/internal/logx"
	"enclave/internal/model"
	"enclave/internal/runtime"
	"enclave/internal/tools"
)

func validateNativeSBXAction(action string) error {
	switch action {
	case "run", "shell", actionContinue, "resume", "exec", "ps", "attach", "stop", "config", "tools", "features", "commands", "extension-list", "extension-manage", "validate-extensions", "network-print", "network-diff", "review-target":
		return nil
	default:
		return fmt.Errorf("native SBX does not support %s; SBX owns sandbox policy, credentials, and lifecycle state", action)
	}
}

func validateNativeSBXOptions(opts model.Options, sources model.OptionSources) error {
	if len(opts.BridgePorts) > 0 || opts.NetworkLog == model.NetworkLogRequests {
		return fmt.Errorf("native SBX owns networking; Enclave --bridge-port and --network-log=requests are unavailable")
	}
	if opts.Slim || opts.NoRebuild || opts.ForceRebuild || opts.ForceBaseImage || opts.ImageNameSet || opts.BuildUID != "" || opts.BuildGID != "" || len(opts.CacheFrom) > 0 || opts.BuildxCacheDir != "" || len(opts.BuildxCacheFrom) > 0 || len(opts.BuildxCacheTo) > 0 {
		return fmt.Errorf("native SBX uses content-addressed kit builds; Docker image, rebuild, UID, and build-cache flags are unavailable")
	}
	if opts.Background && len(opts.HostEnv) > 0 {
		return fmt.Errorf("native SBX host_env currently requires a foreground agent session")
	}
	if opts.Ephemeral && opts.Background {
		return fmt.Errorf("native SBX ephemeral sessions run in the foreground only")
	}
	if opts.Devcontainer || opts.UseRemoteUser || opts.RuntimeUIDRemap || opts.Admin {
		return fmt.Errorf("native SBX does not support Docker devcontainer user overrides, runtime UID remapping, or --admin")
	}
	if opts.ResetAuth || opts.NoAPIKey || opts.PassAPIKey || opts.AuthName != "" || sources.AuthScope > model.SourceDefault || sources.SecretsScope > model.SourceDefault || sources.AuthName > model.SourceDefault {
		return fmt.Errorf("SBX owns credentials; configure native credentials with sbx instead of Enclave auth-store options")
	}
	return nil
}

var nativeSBXBackend = func(host model.Host, paths model.Paths, source, target string) backend.Backend {
	return backendsbx.New(backendsbx.Options{Host: host, Paths: paths, ConfigSource: source, ConfigTarget: target})
}

func runNativeSBXExecution(input *CommandInput, opts model.Options, profile model.Profile, host model.Host, project model.Project, writable, readonly []string, yolo bool) int {
	if err := validateNativeSBXOptions(opts, opts.Sources); err != nil {
		logx.Errorf("%v", err)
		return 1
	}
	if profile.PostStart != nil && profile.PostStart.OpenIDE != "" && !opts.Shell && input.Action != "exec" {
		logx.Errorf("native SBX host IDE launching is not supported; use shell or exec with this tool")
		return 1
	}
	features, provenance := sessionFeaturesAndProvenance(input, opts, profile)
	runner := runtime.New(model.RuntimeConfig{Paths: input.Ctx.Paths, Host: host, Project: project, Profile: profile, Run: opts.RunOptions, Auth: opts.AuthOptions, Build: opts.BuildOptions, RunSources: opts.Sources.RunSources(), Handler: tools.Resolve(profile.Name), ValidatedDirs: writable, ValidatedReadonlyDirs: readonly, YoloEnabled: yolo, Features: features.enabled, Provenance: provenance, UserCommandMount: input.UserCommandMount})
	if input.Action == "exec" {
		be := nativeSBXBackend(host, input.Ctx.Paths, "", "")
		runner.SetBackend(be)
		target, err := execSessionTarget(context.Background(), be, opts, project)
		if err != nil {
			logx.Errorf("%v", err)
			return 1
		}
		if err := runner.Exec(target); err != nil {
			return runErrorExitCode(err)
		}
		return 0
	}
	plan, err := runner.PrepareNative()
	if err != nil {
		logx.Errorf("%v", err)
		return 1
	}
	defer plan.Release()
	plan.Request.Image, err = prepareSBXKit(input, opts, profile, host, plan.Request)
	if err != nil {
		logx.Errorf("prepare native SBX kit: %v", err)
		return 1
	}
	be := nativeSBXBackend(host, input.Ctx.Paths, plan.ConfigDir, plan.ConfigTarget)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	if opts.Background {
		ref, err := be.Start(ctx, plan.Request)
		if err != nil {
			return runErrorExitCode(err)
		}
		fmt.Println(ref.Name)
		return 0
	}
	attach := backend.AttachIO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, TTY: term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())), HostEnv: opts.HostEnv, OnStarted: plan.Release}
	if opts.Shell {
		attach.HostEnv = nil
	}
	status, err := be.Run(ctx, plan.Request, attach)
	if err != nil {
		return runErrorExitCode(err)
	}
	return status.Code
}

func requireBackend(opts model.Options) int {
	if opts.Backend != backend.NameSBX {
		return requireDocker()
	}
	be, err := selectBackend(opts, dockerBackendOptions(model.Host{}, model.Paths{}, opts.BuildOptions, opts.RunOptions))
	if err == nil {
		err = be.Check(context.Background())
	}
	if err != nil {
		logx.Errorf("%v", err)
		return 1
	}
	return 0
}
