// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

package sbx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"enclave/internal/backend"
	"enclave/internal/model"
)

type fakeSBX struct {
	rows        []nativeSession
	calls       [][]string
	workloadErr error
}

func fakeBackend(t *testing.T) (*Backend, *fakeSBX, backend.Request) {
	t.Helper()
	project := t.TempDir()
	req := backend.Request{Session: backend.SessionMeta{Tool: "codex", ProjectHash: "project-hash", Name: "enclave-codex-project"}, Image: t.TempDir(), WorkingDir: project, Argv: []string{"/usr/local/bin/entrypoint.sh", "codex", "argument with spaces"}, Mounts: []backend.Mount{{Type: backend.MountTypeBind, Source: project, ContainerPath: project}}, Env: []backend.EnvVar{{Name: "PUBLIC_SETTING", Value: "enabled"}}, Network: backend.NetworkPolicy{Mode: backend.NetworkModeRestricted}}
	b := New(Options{Host: model.Host{Home: t.TempDir()}})
	fake := &fakeSBX{}
	b.command = func(_ context.Context, args []string, attach backend.AttachIO) error {
		fake.calls = append(fake.calls, append([]string{}, args...))
		switch args[0] {
		case "ls":
			return json.NewEncoder(attach.Out).Encode(fake.rows)
		case "create":
			fake.rows = []nativeSession{{Name: args[2], ID: "native-immutable-id", Status: "running", Workspaces: []string{project}}}
		case "stop":
			fake.rows[0].Status = "stopped"
		case "rm":
			fake.rows = nil
		case "exec":
			joined := strings.Join(args, " ")
			if strings.Contains(joined, " id -u") {
				_, err := attach.Out.Write([]byte("1000\n"))
				return err
			}
			if strings.Contains(joined, " id -g") {
				_, err := attach.Out.Write([]byte("1000\n"))
				return err
			}
			if strings.Contains(joined, "/usr/local/bin/entrypoint.sh") && !strings.Contains(joined, "tmux") {
				return fake.workloadErr
			}
		}
		return nil
	}
	return b, fake, req
}
func TestRunNativeKitPreservesArgumentsAndStopsWithoutRemoving(t *testing.T) {
	b, fake, req := fakeBackend(t)
	fake.workloadErr = exec.Command("sh", "-c", "exit 17").Run()
	started := 0
	status, err := b.Run(context.Background(), req, backend.AttachIO{OnStarted: func() { started++ }})
	if err != nil || status.Code != 17 || started != 1 {
		t.Fatalf("status=%v err=%v started=%d", status, err, started)
	}
	create, workload, stopped := false, false, false
	for _, args := range fake.calls {
		switch args[0] {
		case "create":
			create = true
			if !strings.Contains(strings.Join(args, " "), req.Image+" "+req.WorkingDir) {
				t.Fatalf("not creating generated native kit: %v", args)
			}
		case "exec":
			if strings.Contains(strings.Join(args, " "), "/usr/local/bin/entrypoint.sh") {
				workload = true
				if !reflect.DeepEqual(args[len(args)-len(req.Argv):], req.Argv) {
					t.Fatalf("changed workload argv: %v", args)
				}
			}
		case "stop":
			stopped = true
		case "rm", "policy", "secret":
			t.Fatalf("unexpected mutation: %v", args)
		}
		if args[0] == "docker" {
			t.Fatal("called Docker")
		}
	}
	if !create || !workload || !stopped {
		t.Fatalf("create=%v workload=%v stopped=%v", create, workload, stopped)
	}
}
func TestReuseRejectsChangedNativeIdentityBeforeMutation(t *testing.T) {
	b, fake, req := fakeBackend(t)
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	fake.rows[0].ID = "foreign-replacement"
	fake.calls = nil
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err == nil {
		t.Fatal("reused changed native identity")
	}
	if len(fake.calls) != 1 || fake.calls[0][0] != "ls" {
		t.Fatalf("mutated changed native identity: %v", fake.calls)
	}
}
func TestReuseRejectsChangedKitOrMountSpecification(t *testing.T) {
	b, fake, req := fakeBackend(t)
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	req.Image = t.TempDir()
	fake.calls = nil
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err == nil {
		t.Fatal("reused changed kit")
	}
	if len(fake.calls) != 1 {
		t.Fatalf("mutated stale kit: %v", fake.calls)
	}
}
func TestUnownedNameCollisionIsNeverAdopted(t *testing.T) {
	b, fake, req := fakeBackend(t)
	fake.rows = []nativeSession{{Name: req.Session.Name, ID: "unrelated", Status: "running"}}
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err == nil {
		t.Fatal("adopted unrelated sandbox")
	}
	if len(fake.calls) != 1 {
		t.Fatalf("mutated unrelated sandbox: %v", fake.calls)
	}
}
func TestConfigSeedIsReadOnlyAndRemovedBeforeWorkload(t *testing.T) {
	b, fake, req := fakeBackend(t)
	b.opts.ConfigSource = t.TempDir()
	b.opts.ConfigTarget = "/home/agent/.codex"
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	mount, unmount, workload := -1, -1, -1
	for index, args := range fake.calls {
		switch args[0] {
		case "mount":
			mount = index
			if !strings.HasSuffix(args[2], ":ro") {
				t.Fatalf("writable seed: %v", args)
			}
		case "umount":
			unmount = index
			if args[2] != b.opts.ConfigSource+":/run/enclave/config-seed" {
				t.Fatalf("wrong seed target: %v", args)
			}
		case "exec":
			if strings.Contains(strings.Join(args, " "), "/usr/local/bin/entrypoint.sh") {
				workload = index
			}
		}
	}
	if mount < 0 || unmount < mount || workload < unmount {
		t.Fatalf("seed lifecycle mount=%d unmount=%d workload=%d", mount, unmount, workload)
	}
}
func TestBackgroundUsesNativeTmuxAndOwnedLifecycle(t *testing.T) {
	b, fake, req := fakeBackend(t)
	req.Session.Background = true
	ref, err := b.Start(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, args := range fake.calls {
		if args[0] == "exec" && strings.Contains(strings.Join(args, " "), "tmux -L enclave new-session -d") {
			found = true
			if !reflect.DeepEqual(args[len(args)-len(req.Argv):], req.Argv) {
				t.Fatalf("changed background argv: %v", args)
			}
		}
	}
	if !found {
		t.Fatal("no native tmux launch")
	}
	session, err := b.Inspect(context.Background(), ref)
	if err != nil || !session.Background {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	if err := b.Stop(context.Background(), ref, backend.StopOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := b.Remove(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
}
func TestEphemeralNativeSessionIsRemoved(t *testing.T) {
	b, fake, req := fakeBackend(t)
	req.Ephemeral = true
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	if len(fake.rows) != 0 {
		t.Fatal("ephemeral native sandbox retained")
	}
	for _, args := range fake.calls {
		if args[0] == "create" && args[2] == req.Session.Name {
			t.Fatal("ephemeral session reused stable name")
		}
	}
}
func TestNativeRejectsRawSecretsBeforeAnyCommand(t *testing.T) {
	b, fake, req := fakeBackend(t)
	req.Secrets = []backend.SecretRelease{{Value: "never-send"}}
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err == nil {
		t.Fatal("accepted raw secret")
	}
	if len(fake.calls) != 0 {
		t.Fatalf("raw secret request reached CLI: %v", fake.calls)
	}
}

func TestSuccessfulCreateSurfacesNativeCredentialWarnings(t *testing.T) {
	b, fake, req := fakeBackend(t)
	previous := b.command
	b.command = func(ctx context.Context, args []string, attach backend.AttachIO) error {
		if args[0] == "create" {
			if _, err := attach.Err.Write([]byte("WARN: credential not sent: no binding authorizes this service\n")); err != nil {
				return err
			}
		}
		return previous(ctx, args, attach)
	}
	var stderr bytes.Buffer
	if _, err := b.Run(context.Background(), req, backend.AttachIO{Err: &stderr}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "credential not sent") {
		t.Fatal("successful create swallowed SBX credential warning")
	}
	for _, args := range fake.calls {
		if args[0] == "secret" {
			t.Fatal("implicitly changed native credentials")
		}
	}
}
func TestFailedSeedCleanupIsRecoveredBeforeNativeRestart(t *testing.T) {
	b, _, req := fakeBackend(t)
	b.opts.ConfigSource = t.TempDir()
	b.opts.ConfigTarget = "/home/agent/.codex"
	previous := b.command
	failUnmount := true
	b.command = func(ctx context.Context, args []string, attach backend.AttachIO) error {
		if args[0] == "umount" && failUnmount {
			failUnmount = false
			return errors.New("temporary unmount failure")
		}
		if args[0] == "inspect" {
			source, err := filepath.EvalSymlinks(b.opts.ConfigSource)
			if err != nil {
				return err
			}
			return json.NewEncoder(attach.Out).Encode(map[string]any{"mounts": map[string]string{"/run/enclave/config-seed": source}})
		}
		return previous(ctx, args, attach)
	}
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err == nil {
		t.Fatal("ignored temporary config share cleanup failure")
	}
	record, err := b.owner(req.Session.Name)
	if err != nil {
		t.Fatal(err)
	}
	if record.SeedSource == "" {
		t.Fatal("lost failed config share recovery record")
	}
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	record, err = b.owner(req.Session.Name)
	if err != nil {
		t.Fatal(err)
	}
	if record.SeedSource != "" {
		t.Fatal("config share not recovered")
	}
}

func TestConfigSeedCopiesAsGuestAgent(t *testing.T) {
	b, fake, req := fakeBackend(t)
	b.opts.ConfigSource = t.TempDir()
	b.opts.ConfigTarget = "/home/agent/.codex"
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, args := range fake.calls {
		if args[0] == "exec" && strings.Contains(strings.Join(args, " "), "cp -R") {
			found = true
			for _, arg := range args {
				if arg == "root" || arg == "chown" {
					t.Fatalf("privileged config seed: %v", args)
				}
			}
			if !strings.Contains(strings.Join(args, " "), "Refusing symlinked native config") {
				t.Fatal("no destination symlink guard")
			}
		}
	}
	if !found {
		t.Fatal("no agent config overlay")
	}
}
func TestNativeDynamicPortSyntaxAndProtocolReadback(t *testing.T) {
	b, fake, req := fakeBackend(t)
	req.Ports = []backend.PortMapping{{HostIP: "127.0.0.1", HostPort: "0", ContainerPort: "1455", Protocol: "tcp"}, {HostIP: "::1", HostPort: "0", ContainerPort: "8080", Protocol: "udp"}, {HostIP: "::1", HostPort: "9000", ContainerPort: "9001", Protocol: "tcp"}}
	args := b.createArgs(req.Session.Name, req)
	published := []string{}
	for i, arg := range args {
		if arg == "--publish" {
			published = append(published, args[i+1])
		}
	}
	if !reflect.DeepEqual(published, []string{"1455/tcp4", "8080/udp6", "[::1]:9000:9001/tcp"}) {
		t.Fatalf("invalid native publish syntax: %v", published)
	}
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	fake.rows[0].Ports = []nativePort{{HostIP: "127.0.0.1", HostPort: 32100, SandboxPort: 1455, Protocol: "tcp4"}}
	session, err := b.Inspect(context.Background(), backend.SessionRef{Name: req.Session.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Ports) != 1 || session.Ports[0].Protocol != "tcp" || session.Ports[0].HostPort != "32100" {
		t.Fatalf("ports=%v", session.Ports)
	}
}

func TestReuseRejectsExternallyChangedNativeMounts(t *testing.T) {
	b, fake, req := fakeBackend(t)
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	fake.rows[0].Mounts = []string{"/unrequested:/unexpected"}
	fake.calls = nil
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err == nil {
		t.Fatal("reused externally changed native mounts")
	}
	if len(fake.calls) != 1 || fake.calls[0][0] != "ls" {
		t.Fatalf("mutated altered native session: %v", fake.calls)
	}
}
func TestConfigSeedRejectsRootImageIdentity(t *testing.T) {
	b, _, req := fakeBackend(t)
	b.opts.ConfigSource = t.TempDir()
	b.opts.ConfigTarget = "/home/agent/.codex"
	previous := b.command
	b.command = func(ctx context.Context, args []string, attach backend.AttachIO) error {
		if args[0] == "exec" && strings.HasSuffix(strings.Join(args, " "), "id -u") {
			_, err := attach.Out.Write([]byte("0\n"))
			return err
		}
		if args[0] == "exec" && strings.Contains(strings.Join(args, " "), "cp -R") {
			t.Fatal("seed copied as root image user")
		}
		return previous(ctx, args, attach)
	}
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err == nil || !strings.Contains(err.Error(), "unprivileged") {
		t.Fatalf("expected unprivileged-image error, got %v", err)
	}
}

func TestExecSuppliesAmbientTerminalStreamsForLifecycleCaller(t *testing.T) {
	b, _, req := fakeBackend(t)
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	previous := b.command
	found := false
	b.command = func(ctx context.Context, args []string, attach backend.AttachIO) error {
		if args[0] == "exec" && args[len(args)-1] == "stdio-proof" {
			found = true
			if attach.In != os.Stdin || attach.Out != os.Stdout || attach.Err != os.Stderr {
				t.Fatal("native lifecycle exec did not attach ambient stdio")
			}
		}
		return previous(ctx, args, attach)
	}
	if err := b.Exec(context.Background(), backend.SessionRef{Name: req.Session.Name}, backend.ExecRequest{Argv: []string{"stdio-proof"}}, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no lifecycle exec")
	}
}

func TestLifecycleExecUsesNativeCredentialAndTrustWrapper(t *testing.T) {
	b, fake, req := fakeBackend(t)
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	fake.calls = nil
	ref := backend.SessionRef{Name: req.Session.Name}
	if err := b.Exec(context.Background(), ref, backend.ExecRequest{Argv: []string{"node", "--version"}}, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ExecOutput(context.Background(), ref, []string{"python3", "--version"}, ""); err != nil {
		t.Fatal(err)
	}
	wrapped := 0
	for _, args := range fake.calls {
		if args[0] == "exec" && strings.Contains(strings.Join(args, " "), "/usr/local/bin/enclave-native-env") {
			wrapped++
		}
	}
	if wrapped != 2 {
		t.Fatalf("wrapped execs=%d calls=%v", wrapped, fake.calls)
	}
}

func TestSessionDisplayNameIsSeparateFromNativeReference(t *testing.T) {
	b, fake, req := fakeBackend(t)
	req.Session.DisplayName = "my-task"
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	sessions, err := b.List(context.Background(), backend.SessionFilter{ExactName: req.Session.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Name != "my-task" || sessions[0].Ref.Name != req.Session.Name {
		t.Fatalf("sessions=%+v", sessions)
	}
	prefixed, err := b.List(context.Background(), backend.SessionFilter{NamePrefix: "enclave-codex-"})
	if err != nil || len(prefixed) != 1 {
		t.Fatalf("physical prefix filter sessions=%+v err=%v", prefixed, err)
	}
	ref := backend.SessionRef{Name: req.Session.Name}
	session, err := b.Inspect(context.Background(), ref)
	if err != nil || session.Name != "my-task" || session.Ref.Name != req.Session.Name {
		t.Fatalf("inspect=%+v err=%v", session, err)
	}
	fake.calls = nil
	if err := b.Exec(context.Background(), ref, backend.ExecRequest{Argv: []string{"display-proof"}}, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ExecOutput(context.Background(), ref, []string{"display-proof"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := b.Stop(context.Background(), ref, backend.StopOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := b.Remove(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	for _, args := range fake.calls {
		for _, arg := range args {
			if arg == "my-task" {
				t.Fatalf("display name used as native selector: %v", args)
			}
		}
	}
}
func TestUnnamedSessionKeepsEmptyDisplayName(t *testing.T) {
	b, _, req := fakeBackend(t)
	req.Session.DisplayName = ""
	if _, err := b.Run(context.Background(), req, backend.AttachIO{}); err != nil {
		t.Fatal(err)
	}
	sessions, err := b.List(context.Background(), backend.SessionFilter{})
	if err != nil || len(sessions) != 1 || sessions[0].Name != "" {
		t.Fatalf("sessions=%+v err=%v", sessions, err)
	}
}

func TestNativeConfigSeedPreservesUnrelatedCodexSymlinks(t *testing.T) {
	source := t.TempDir()
	target, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "config.toml"), []byte("model = 'updated'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(target, "tmp", "arg0-linux", "codex-arg0")
	if err := os.MkdirAll(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(temp, "apply_patch")
	if err := os.Symlink("/usr/local/bin/codex", link); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", "-c", nativeConfigSeedScript, "sh", source, target)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("seed rejected unrelated Codex state: %v: %s", err, output)
	}
	if _, err := os.Readlink(link); err != nil {
		t.Fatalf("Codex temporary symlink lost: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(target, "config.toml"))
	if err != nil || !strings.Contains(string(data), "updated") {
		t.Fatalf("settings=%q err=%v", data, err)
	}
}
func TestNativeConfigSeedRejectsTouchedDestinationSymlink(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(strconv.FormatBool(nested), func(t *testing.T) {
			source := t.TempDir()
			target, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			victim := filepath.Join(outside, "config.toml")
			if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(target, "config.toml")
			src := filepath.Join(source, "config.toml")
			linked := victim
			if nested {
				destination = filepath.Join(target, "settings")
				src = filepath.Join(source, "settings", "config.toml")
				linked = outside
				if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(src, []byte("must-not-write"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(linked, destination); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("sh", "-c", nativeConfigSeedScript, "sh", source, target)
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("seed followed destination symlink: %s", output)
			}
			data, err := os.ReadFile(victim)
			if err != nil || string(data) != "unchanged" {
				t.Fatalf("outside config modified: %q %v", data, err)
			}
		})
	}
}
