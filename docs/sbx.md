# Native SBX backend

`--backend sbx` runs an Enclave-composed workload directly in Docker Sandboxes.
SBX owns isolation, network governance, and outbound credential injection. The
running workload has neither a nested Docker engine nor Enclave's gateway.

## Run

Install and authenticate a compatible `sbx` CLI with v3 workload-kit support.
Run Enclave from the project directory:

```bash
enclave shell --backend sbx --tool codex --name work
enclave --backend sbx --tool codex --name work
enclave ps --backend sbx --all --json
enclave stop --backend sbx --name work
```

Enclave translates its selected tool and features into an SBX workload kit.
SBX builds the image in its managed builder; a host Docker daemon is not
required. This build service is separate from the running agent sandbox.
Generated public settings and skills seed the tool's native configuration.
Project paths and selected cache/history/memory paths are explicitly shared;
the host home, Enclave auth stores, and credential files are not automatically
mounted. Sensitive-project and additional-mount checks still apply.

The backend supports foreground tools and shells, background sessions, `ps`,
`exec`, `attach`, and `stop`. Use `--backend sbx` consistently with these commands.
Each named session owns a distinct SBX sandbox and records its immutable ID.
Foreground completion stops the sandbox while retaining its native filesystem;
reusing that session resumes its state. `stop` also retains this filesystem. `--ephemeral` removes the foreground
sandbox afterward. Background sessions use native tmux. Configuration changes
that alter the kit, mounts, or published ports require a new session name, or
explicit removal of the old sandbox with `sbx rm`.

## Policy authority

SBX is the sole policy authority. Enclave translates its effective domain
requirements into native kit network declarations. These requests are evaluated
under the existing SBX user/organization policy; they are **not an independent
Enclave allowlist boundary**. Existing SBX rules can permit other destinations,
and organization rules can deny destinations the workload requests.

The backend never initializes, resets, or weakens global SBX policy.
`--allow-all-network` requests broad access but cannot override SBX governance.
Use `sbx policy` to inspect enforcement, decisions, and logs. Enclave's offline
`network print` describes Enclave's declarations, not the effective SBX policy;
Enclave gateway reload/apply operations are unavailable for this backend.

## Credentials

Configure credentials in SBX, for example with the interactive command:

```bash
sbx secret set openai
```

Supported Enclave API-key declarations become SBX credential capabilities with
`proxyManaged: true`, including destination hosts and header formats. The guest
receives SBX sentinels; SBX releases the credential outside the guest. Enclave
does not read/import host provider environment variables, its env-secret store,
or existing provider auth files for native sessions. Known credential variables
cannot be passed with `--pass-env`; use SBX credential management instead.

SBX's credential bindings and kit trust rules still apply. Foreground terminal
creation permits SBX's normal consent flow. Missing or unapproved credentials
can leave the workload logged out; the backend preserves SBX's warnings and does
not infer successful authentication from successful sandbox creation. Use
sandbox-scoped credentials where different sessions need different authority.

This first integration maps supported SBX provider API-key services. Enclave's
OAuth/file-auth stores and custom token-prefix/dynamic-host release rules are
not migrated. Configure SBX custom secrets explicitly for other services;
the default GitHub feature skips its optional Enterprise declaration with a
warning. Other untranslatable API-key declarations fail rather than injecting
raw values.
Native provider OAuth onboarding remains a follow-up.

## Current scope

This backend is experimental. Docker-specific image/cache/rebuild controls,
devcontainers, UID remapping, administrator shells, Enclave auth-store controls,
SSH-agent mounts, host IDE auto-launch, bridge ports, request logs, DNS resolver
overrides, and Enclave gateway management are not
supported. Unsupported execution options fail explicitly. `sbx` manages native
sandbox removal and build-cache lifecycle; Enclave's Docker cleanup/update
commands are unavailable. Feature installation runs during the native kit
build, but features that assume a Docker socket or Enclave gateway require
backend-specific support.

For isolated development, `ENCLAVE_SBX_APP_NAME` selects an independently
authenticated SBX namespace. Use synthetic credentials and isolated SBX binding
configuration when testing injection; never change the user's default policy,
credential bindings, or daemon as part of a test.
