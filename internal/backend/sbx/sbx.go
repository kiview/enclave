// Copyright (C) 2026 EclipseSource GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the MIT License, which is available in the project root.
//
// SPDX-License-Identifier: MIT

// Package sbx executes Enclave workloads directly in native Docker Sandboxes.
package sbx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"enclave/internal/backend"
	"enclave/internal/config"
	"enclave/internal/model"
	"enclave/internal/util"
)

type Options struct {
	Host                       model.Host
	Paths                      model.Paths
	Binary, AppName            string
	ConfigSource, ConfigTarget string
}
type Backend struct {
	opts    Options
	command func(context.Context, []string, backend.AttachIO) error
}
type nativeSession struct {
	Name       string       `json:"name"`
	ID         string       `json:"id"`
	Status     string       `json:"status"`
	Workspaces []string     `json:"workspaces"`
	Mounts     []string     `json:"mounts"`
	CreatedAt  time.Time    `json:"created_at"`
	Ports      []nativePort `json:"ports"`
}
type nativePort struct {
	HostIP      string `json:"host_ip"`
	HostPort    int    `json:"host_port"`
	SandboxPort int    `json:"sandbox_port"`
	Protocol    string `json:"protocol"`
}
type ownership struct {
	ID            string              `json:"id"`
	Meta          backend.SessionMeta `json:"session"`
	Project       string              `json:"project"`
	Fingerprint   string              `json:"fingerprint"`
	Active        bool                `json:"active"`
	SeedSource    string              `json:"seed_source,omitempty"`
	MountSnapshot []string            `json:"mount_snapshot,omitempty"`
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]+$`)

func New(opts Options) *Backend {
	if opts.Binary == "" {
		opts.Binary = "sbx"
	}
	if opts.AppName == "" {
		opts.AppName = os.Getenv("ENCLAVE_SBX_APP_NAME")
	}
	b := &Backend{opts: opts}
	b.command = b.execute
	return b
}
func (b *Backend) Name() string                    { return "sbx" }
func (b *Backend) Check(ctx context.Context) error { _, err := b.capture(ctx, "version"); return err }
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{RestrictedNetwork: true, SecretHTTPRelease: true}
}
func (b *Backend) Storage() backend.StoreManager { return nil }
func (b *Backend) PrepareStores(context.Context, backend.StorePrep) (backend.StoreState, error) {
	return backend.StoreState{}, errors.New("SBX owns native authentication and configuration; Enclave stores are unsupported")
}
func (b *Backend) execute(ctx context.Context, args []string, attach backend.AttachIO) error {
	prefix := []string{}
	if len(args) == 0 || args[0] != "create" || !attach.TTY || attach.In == nil {
		prefix = append(prefix, "--no-input")
	}
	if b.opts.AppName != "" {
		prefix = append(prefix, "--app-name", b.opts.AppName)
	}
	cmd := exec.CommandContext(ctx, b.opts.Binary, append(prefix, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = attach.In, attach.Out, attach.Err
	cmd.Env = attach.CommandEnv()
	if len(args) > 0 && args[0] == "create" {
		cmd.Env = append(os.Environ(), "SBX_KIT_BUILDER=sandbox")
	}
	return cmd.Run()
}
func (b *Backend) capture(ctx context.Context, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	err := b.command(ctx, args, backend.AttachIO{Out: &stdout, Err: &stderr})
	if err != nil {
		return nil, fmt.Errorf("sbx %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
func (b *Backend) directory() string {
	sum := sha256.Sum256([]byte(b.opts.Binary + "\x00" + b.opts.AppName))
	return filepath.Join(config.HostStateRootDir(b.opts.Host.Home), "sbx-native", hex.EncodeToString(sum[:8]))
}
func (b *Backend) ownerPath(name string) string { return filepath.Join(b.directory(), name+".json") }
func (b *Backend) lock(name string) (func(), error) {
	if b.opts.Host.Home == "" {
		return nil, errors.New("SBX requires a host home for ownership records")
	}
	if !validName.MatchString(name) {
		return nil, errors.New("SBX session name must contain only letters, numbers, hyphens, and periods")
	}
	return util.AcquireFileLock(filepath.Join(b.directory(), name+".lock"), nil)
}
func (b *Backend) owner(name string) (ownership, error) {
	var record ownership
	if !validName.MatchString(name) {
		return record, errors.New("invalid SBX session reference")
	}
	data, err := os.ReadFile(b.ownerPath(name))
	if err != nil {
		return record, err
	}
	if err = json.Unmarshal(data, &record); err != nil {
		return record, err
	}
	if record.ID == "" {
		return record, errors.New("invalid SBX ownership record")
	}
	return record, nil
}
func (b *Backend) save(name string, record ownership) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(b.directory(), "ownership-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), b.ownerPath(name))
}
func (b *Backend) rows(ctx context.Context) ([]nativeSession, error) {
	data, err := b.capture(ctx, "ls", "--json")
	if err != nil {
		return nil, err
	}
	var rows []nativeSession
	if err = json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("decode SBX list: %w", err)
	}
	return rows, nil
}
func (b *Backend) lookup(ctx context.Context, name string) (*nativeSession, error) {
	rows, err := b.rows(ctx)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Name == name {
			return &rows[i], nil
		}
	}
	return nil, nil
}
func sessionName(req backend.Request) (string, error) {
	name := req.Session.Name
	if name == "" {
		sum := sha256.Sum256([]byte(req.Session.Tool + "\x00" + req.Session.ProjectHash + "\x00" + req.WorkingDir))
		name = "enclave-" + req.Session.Tool + "-" + hex.EncodeToString(sum[:8])
	}
	if req.Ephemeral {
		var suffix [5]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", err
		}
		name += "-" + hex.EncodeToString(suffix[:])
	}
	if !validName.MatchString(name) {
		return "", fmt.Errorf("invalid native SBX session name %q", name)
	}
	return name, nil
}
func fingerprint(req backend.Request) string {
	data, _ := json.Marshal(struct {
		Kit, Project, User string
		Mounts             []backend.Mount
		Ports              []backend.PortMapping
	}{req.Image, req.WorkingDir, req.User, req.Mounts, req.Ports})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validate(req backend.Request) error {
	if !filepath.IsAbs(req.Image) || !filepath.IsAbs(req.WorkingDir) || req.Session.Tool == "" || len(req.Argv) == 0 {
		return errors.New("native SBX requires an absolute kit path, project workspace, tool, and command")
	}
	if len(req.Stores) > 0 || len(req.Secrets) > 0 || req.AuthSync != nil || req.RuntimeUIDRemap || req.Hostname != "" {
		return errors.New("native SBX does not accept Docker stores, raw secrets, auth reconciliation, UID remapping, or hostname overrides")
	}
	if req.Ephemeral && (req.Detached || req.Session.Background) {
		return errors.New("native SBX ephemeral background sessions are unsupported")
	}
	for _, port := range req.Ports {
		if (port.HostPort == "" || port.HostPort == "0") && port.HostIP != "" && port.HostIP != "127.0.0.1" && port.HostIP != "::1" {
			return errors.New("native SBX dynamic ports require loopback host IP (127.0.0.1 or ::1)")
		}
	}
	for _, mount := range req.Mounts {
		if mount.Type != backend.MountTypeBind || !filepath.IsAbs(mount.Source) || !filepath.IsAbs(mount.ContainerPath) || strings.Contains(mount.Source, ":") || strings.Contains(mount.ContainerPath, ":") {
			return errors.New("native SBX requires absolute bind mounts without colon characters")
		}
		if mount.CreateSourceDir {
			if err := os.MkdirAll(mount.Source, 0o700); err != nil {
				return err
			}
		}
	}
	return nil
}
func (b *Backend) createArgs(name string, req backend.Request) []string {
	args := []string{"create", "--name", name, "--no-progress", "--skills", "off", "--static-mcp", "none"}
	for _, port := range req.Ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		spec := ""
		if port.HostPort == "" || port.HostPort == "0" {
			family := "4"
			if port.HostIP == "::1" {
				family = "6"
			}
			spec = port.ContainerPort + "/" + protocol + family
		} else {
			spec = port.HostPort + ":" + port.ContainerPort
			if port.HostIP != "" {
				spec = net.JoinHostPort(port.HostIP, port.HostPort) + ":" + port.ContainerPort
			}
			spec += "/" + protocol
		}
		args = append(args, "--publish", spec)
	}
	args = append(args, req.Image, req.WorkingDir)
	for _, mount := range req.Mounts {
		if mount.Source == req.WorkingDir && mount.ContainerPath == req.WorkingDir && !mount.ReadOnly {
			continue
		}
		spec := mount.Source + ":" + mount.ContainerPath
		if mount.ReadOnly {
			spec += ":ro"
		}
		args = append(args, spec)
	}
	return args
}
func (b *Backend) ensure(ctx context.Context, name string, req backend.Request, attach backend.AttachIO) (record ownership, err error) {
	existing, err := b.lookup(ctx, name)
	if err != nil {
		return record, err
	}
	if existing != nil {
		record, err = b.owner(name)
		if err != nil {
			return record, fmt.Errorf("refusing unowned native sandbox %s: %w", name, err)
		}
		if record.ID != existing.ID || record.Project != req.WorkingDir || record.Fingerprint != fingerprint(req) {
			return record, errors.New("native sandbox identity or kit/mount configuration changed; use a new session name or remove the owned sandbox")
		}
		if record.Active && existing.Status == "running" {
			return record, errors.New("native SBX session is already active; attach or stop it before reusing its name")
		}
	} else {
		createIO := attach
		if createIO.Err == nil {
			createIO.Err = os.Stderr
		}
		createIO.Out = createIO.Err
		if err = b.command(ctx, b.createArgs(name, req), createIO); err != nil {
			return record, err
		}
		saved := false
		defer func() {
			if !saved {
				cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_, stopErr := b.capture(cleanup, "stop", name)
				err = errors.Join(err, stopErr)
			}
		}()
		existing, err = b.lookup(ctx, name)
		if err != nil {
			return record, err
		}
		if existing == nil || existing.ID == "" {
			return record, errors.New("created native sandbox has no immutable identity")
		}
		record = ownership{ID: existing.ID, Meta: req.Session, Project: req.WorkingDir, Fingerprint: fingerprint(req), MountSnapshot: sortedMounts(existing.Mounts)}
		if err = b.save(name, record); err != nil {
			return record, err
		}
		saved = true
	}
	if record.SeedSource != "" {
		data, inspectErr := b.capture(ctx, "inspect", name, "--json")
		if inspectErr != nil {
			return record, inspectErr
		}
		var view struct {
			Mounts map[string]string `json:"mounts"`
		}
		if err = json.Unmarshal(data, &view); err != nil {
			return record, err
		}
		if source, ok := view.Mounts["/run/enclave/config-seed"]; ok {
			if source != record.SeedSource {
				return record, errors.New("native config seed mount no longer matches ownership")
			}
			if _, err = b.capture(ctx, "umount", name, record.SeedSource+":/run/enclave/config-seed"); err != nil {
				return record, err
			}
		}
		record.SeedSource = ""
		if err = b.save(name, record); err != nil {
			return record, err
		}
		existing, err = b.lookup(ctx, name)
		if err != nil {
			return record, err
		}
	}

	if existing == nil || existing.ID != record.ID || !slices.Equal(sortedMounts(existing.Mounts), record.MountSnapshot) {
		return record, errors.New("native SBX workspace mounts changed outside Enclave; refusing to reuse the session")
	}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, stopErr := b.capture(cleanup, "stop", name)
			err = errors.Join(err, stopErr)
		}
	}()
	if _, err = b.capture(ctx, "run", "--detach", "--name", name); err != nil {
		return record, err
	}
	if err = b.seedConfig(ctx, name); err != nil {
		return record, err
	}
	record.Meta = req.Session
	record.Active = true
	err = b.save(name, record)
	return record, err
}
func (b *Backend) seedConfig(ctx context.Context, name string) (retErr error) {
	source, target := b.opts.ConfigSource, b.opts.ConfigTarget
	if source == "" {
		return nil
	}
	if !filepath.IsAbs(source) || !filepath.IsAbs(target) || target == "/" {
		return errors.New("native config seed paths must be absolute and target a configuration directory")
	}
	const seed = "/run/enclave/config-seed"
	if _, err := b.capture(ctx, "mount", name, source+":"+seed+":ro"); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := b.capture(cleanup, "umount", name, source+":"+seed)
		if err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("remove native config seed: %w", err))
			return
		}
		record, err := b.owner(name)
		if err != nil {
			retErr = errors.Join(retErr, err)
			return
		}
		record.SeedSource = ""
		retErr = errors.Join(retErr, b.save(name, record))
	}()
	record, err := b.owner(name)
	if err != nil {
		return err
	}
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	record.SeedSource = resolvedSource
	if err = b.save(name, record); err != nil {
		return err
	}
	uidBytes, err := b.capture(ctx, "exec", name, "id", "-u")
	if err != nil {
		return err
	}
	gidBytes, err := b.capture(ctx, "exec", name, "id", "-g")
	if err != nil {
		return err
	}
	uid, gid := strings.TrimSpace(string(uidBytes)), strings.TrimSpace(string(gidBytes))
	numericUID, err := strconv.ParseUint(uid, 10, 32)
	if err != nil || numericUID == 0 {
		return errors.New("native config seeding requires an unprivileged image user")
	}
	if _, err = strconv.ParseUint(gid, 10, 32); err != nil {
		return err
	}
	_, err = b.capture(ctx, "exec", "-u", uid+":"+gid, name, "sh", "-c", nativeConfigSeedScript, "sh", seed, target)

	return err
}
func execArgs(name string, req backend.Request, tty bool, input bool) []string {
	args := []string{"exec"}
	if input {
		args = append(args, "-i")
	}
	if tty {
		args = append(args, "-t")
	}
	if req.User != "" {
		args = append(args, "-u", req.User)
	}
	if req.WorkingDir != "" {
		args = append(args, "-w", req.WorkingDir)
	}
	for _, env := range req.Env {
		args = append(args, "-e", env.Name+"="+env.Value)
	}
	args = append(args, name)
	args = append(args, req.Entrypoint...)
	return append(args, req.Argv...)
}
func exitStatus(ctx context.Context, err error) (backend.ExitStatus, error) {
	if err == nil {
		return backend.ExitStatus{}, nil
	}
	if ctx.Err() != nil {
		return backend.ExitStatus{Code: 130}, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return backend.ExitStatus{Code: exit.ExitCode()}, nil
	}
	return backend.ExitStatus{}, err
}
func (b *Backend) Run(ctx context.Context, req backend.Request, attach backend.AttachIO) (status backend.ExitStatus, retErr error) {
	if err := validate(req); err != nil {
		return status, err
	}
	name, err := sessionName(req)
	if err != nil {
		return status, err
	}
	unlock, err := b.lock(name)
	if err != nil {
		return status, err
	}
	record, err := b.ensure(ctx, name, req, attach)
	unlock()
	if err != nil {
		return status, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		stopErr := b.Stop(cleanup, backend.SessionRef{Name: name, ID: record.ID}, backend.StopOptions{})
		retErr = errors.Join(retErr, stopErr)
		if req.Ephemeral {
			retErr = errors.Join(retErr, b.Remove(cleanup, backend.SessionRef{Name: name, ID: record.ID}))
		}
	}()
	if attach.Err != nil {
		_, _ = fmt.Fprintf(attach.Err, "Native SBX session: %s\n", name)
	}
	if attach.OnStarted != nil {
		attach.OnStarted()
	}
	args := execArgs(name, req, attach.TTY, nativeInputAttached(attach.In))
	if attach.DetachKeys != "" {
		args = append([]string{"exec", "--detach-keys", attach.DetachKeys}, args[1:]...)
	}
	return exitStatus(ctx, b.command(ctx, args, attach))
}
func (b *Backend) Start(ctx context.Context, req backend.Request) (backend.SessionRef, error) {
	if err := validate(req); err != nil {
		return backend.SessionRef{}, err
	}
	name, err := sessionName(req)
	if err != nil {
		return backend.SessionRef{}, err
	}
	unlock, err := b.lock(name)
	if err != nil {
		return backend.SessionRef{}, err
	}
	defer unlock()
	req.Session.Background = true
	record, err := b.ensure(ctx, name, req, backend.AttachIO{})
	if err != nil {
		return backend.SessionRef{}, err
	}
	argv := []string{"tmux", "-L", "enclave", "new-session", "-d", "-s", "enclave", "-c", req.WorkingDir}
	for _, env := range req.Env {
		argv = append(argv, "-e", env.Name+"="+env.Value)
	}
	argv = append(argv, req.Entrypoint...)
	argv = append(argv, req.Argv...)
	launch := req
	launch.Argv = argv
	launch.Entrypoint = nil
	if _, err = b.capture(ctx, execArgs(name, launch, false, false)...); err != nil {
		record.Active = false
		_ = b.save(name, record)
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, stopErr := b.capture(cleanup, "stop", name)
		return backend.SessionRef{}, errors.Join(err, stopErr)
	}
	return backend.SessionRef{Name: name, ID: record.ID}, nil
}
func (b *Backend) List(ctx context.Context, filter backend.SessionFilter) ([]backend.Session, error) {
	rows, err := b.rows(ctx)
	if err != nil {
		return nil, err
	}
	sessions := []backend.Session{}
	for _, row := range rows {
		record, err := b.owner(row.Name)
		if err != nil || record.ID != row.ID {
			continue
		}
		status := row.Status
		if record.Meta.Background && status == "running" {
			if _, err := b.capture(ctx, "exec", row.Name, "tmux", "-L", "enclave", "has-session", "-t", "enclave"); err != nil {
				status = "exited"
			}
		}
		session := backend.Session{Ref: backend.SessionRef{Name: row.Name, ID: row.ID}, Tool: record.Meta.Tool, ProjectHash: record.Meta.ProjectHash, Worktree: record.Meta.Worktree, ProjectDir: record.Project, Name: record.Meta.DisplayName, Status: status, CreatedAt: row.CreatedAt, Background: record.Meta.Background, Yolo: record.Meta.Yolo, Provenance: record.Meta.Provenance}
		for _, port := range row.Ports {
			session.Ports = append(session.Ports, backend.PortMapping{HostIP: port.HostIP, HostPort: strconv.Itoa(port.HostPort), ContainerPort: strconv.Itoa(port.SandboxPort), Protocol: portProtocol(port.Protocol)})
		}
		if filter.Tool != "" && session.Tool != filter.Tool || filter.ProjectHash != "" && session.ProjectHash != filter.ProjectHash || filter.ExactName != "" && session.Ref.Name != filter.ExactName || filter.NamePrefix != "" && !strings.HasPrefix(session.Ref.Name, filter.NamePrefix) || filter.RunningOnly && status != "running" || filter.Background != nil && *filter.Background != session.Background {
			continue
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}
func (b *Backend) Inspect(ctx context.Context, ref backend.SessionRef) (*backend.Session, error) {
	sessions, err := b.List(ctx, backend.SessionFilter{})
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if (ref.Name != "" && session.Ref.Name == ref.Name || ref.Name == "" && ref.ID != "" && session.Ref.ID == ref.ID) && (ref.ID == "" || ref.ID == session.Ref.ID) {
			return &session, nil
		}
	}
	return nil, errors.New("native SBX session not found or not owned by Enclave")
}
func (b *Backend) Attach(ctx context.Context, ref backend.SessionRef, attach backend.AttachIO) error {
	session, err := b.Inspect(ctx, ref)
	if err != nil {
		return err
	}
	if !session.Background {
		return errors.New("native SBX attach requires a background session")
	}
	return b.Exec(ctx, session.Ref, backend.ExecRequest{Argv: []string{"tmux", "-L", "enclave", "attach-session", "-t", "enclave"}, TTY: true}, attach)
}
func (b *Backend) Exec(ctx context.Context, ref backend.SessionRef, req backend.ExecRequest, attach backend.AttachIO) error {
	if attach.In == nil {
		attach.In = os.Stdin
	}
	if attach.Out == nil {
		attach.Out = os.Stdout
	}
	if attach.Err == nil {
		attach.Err = os.Stderr
	}
	session, err := b.Inspect(ctx, ref)
	if err != nil {
		return err
	}
	args := execArgs(session.Ref.Name, backend.Request{Argv: nativeCommand(req.Argv), User: req.User}, req.TTY, nativeInputAttached(attach.In))
	if attach.DetachKeys != "" {
		args = append([]string{"exec", "--detach-keys", attach.DetachKeys}, args[1:]...)
	}
	status, err := exitStatus(ctx, b.command(ctx, args, attach))
	if err != nil {
		return err
	}
	if status.Code != 0 {
		return &backend.ExitError{Code: status.Code}
	}
	return nil
}
func (b *Backend) ExecOutput(ctx context.Context, ref backend.SessionRef, argv []string, user string) (string, error) {
	session, err := b.Inspect(ctx, ref)
	if err != nil {
		return "", err
	}
	output, err := b.capture(ctx, execArgs(session.Ref.Name, backend.Request{Argv: nativeCommand(argv), User: user}, false, false)...)
	return string(output), err
}
func (b *Backend) Stop(ctx context.Context, ref backend.SessionRef, _ backend.StopOptions) error {
	session, err := b.Inspect(ctx, ref)
	if err != nil {
		return err
	}
	unlock, err := b.lock(session.Ref.Name)
	if err != nil {
		return err
	}
	defer unlock()
	current, checkErr := b.lookup(ctx, session.Ref.Name)
	if checkErr != nil {
		return checkErr
	}
	if current == nil || current.ID != session.Ref.ID {
		return errors.New("native SBX identity changed before stop")
	}
	if _, err = b.capture(ctx, "stop", session.Ref.Name); err != nil {
		return err
	}
	record, err := b.owner(session.Ref.Name)
	if err != nil {
		return err
	}
	record.Active = false
	return b.save(session.Ref.Name, record)
}
func (b *Backend) Remove(ctx context.Context, ref backend.SessionRef) error {
	session, err := b.Inspect(ctx, ref)
	if err != nil {
		return err
	}
	unlock, err := b.lock(session.Ref.Name)
	if err != nil {
		return err
	}
	defer unlock()
	current, checkErr := b.lookup(ctx, session.Ref.Name)
	if checkErr != nil {
		return checkErr
	}
	if current == nil || current.ID != session.Ref.ID {
		return errors.New("native SBX identity changed before removal")
	}
	if _, err = b.capture(ctx, "rm", "--force", session.Ref.Name); err != nil {
		return err
	}
	return os.Remove(b.ownerPath(session.Ref.Name))
}

var _ backend.Backend = (*Backend)(nil)
var _ backend.Execer = (*Backend)(nil)

func portProtocol(protocol string) string {
	switch protocol {
	case "tcp4", "tcp6":
		return "tcp"
	case "udp4", "udp6":
		return "udp"
	}
	return protocol
}

func sortedMounts(mounts []string) []string {
	result := append([]string(nil), mounts...)
	slices.Sort(result)
	return result
}

func nativeCommand(argv []string) []string {
	const wrapper = "/usr/local/bin/enclave-native-env"
	if len(argv) > 0 && argv[0] == wrapper {
		return argv
	}
	return append([]string{wrapper}, argv...)
}

const nativeConfigSeedScript = `set -eu
 target=$2
 parent=$target
 while [ "$parent" != / ]; do
  if [ -L "$parent" ]; then printf 'Refusing symlinked native config path: %s\n' "$parent" >&2; exit 1; fi
  parent=$(dirname "$parent")
 done
 mkdir -p "$target"
 find "$1" -mindepth 1 -exec sh -c '
  source=$1 target=$2
  shift 2
  for file; do
   relative=${file#"$source"/}
   destination=$target/$relative
   while [ "$destination" != "$target" ]; do
    if [ -L "$destination" ]; then printf "Refusing symlinked native config destination: %s\n" "$destination" >&2; exit 1; fi
    destination=$(dirname "$destination")
   done
  done
 ' sh "$1" "$target" {} +
 cp -R "$1"/. "$target"/`

// A detached caller often inherits /dev/null. Forwarding its immediate EOF
// through SBX's interactive stream can discard delayed command output.
func nativeInputAttached(reader io.Reader) bool {
	if reader == nil {
		return false
	}
	file, ok := reader.(*os.File)
	if !ok {
		return true
	}
	inputInfo, err := file.Stat()
	if err != nil {
		return true
	}
	nullInfo, err := os.Stat(os.DevNull)
	if err != nil {
		return true
	}
	return !os.SameFile(inputInfo, nullInfo)
}
