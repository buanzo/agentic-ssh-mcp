# SSH Session MCP

Standalone MCP server for persistent, unrestricted SSH sessions.

This server exposes explicit lifecycle tools so an agent can open one SSH transport, execute multiple commands efficiently, inspect state, and close sessions deterministically.

## Security Notice (Early Release)

This project is useful today for controlled environments, but it is not a hardened multi-tenant security product.

- Intended for trusted operators and trusted workflows.
- Commands are intentionally unrestricted.
- You should add your own guardrails (network isolation, allowlists, policy enforcement, secret governance, and centralized audit review) before production use.

## Security Model and Boundaries

- Secrets are not stored in repository files.
- Password auth is supported only through environment variables (`password_env` and `ONEMCP_SSH_PASSWORD` fallback).
- SSH key/agent auth is preferred when available.
- Session data is process-local and in-memory only.
- Sessions are cleaned up on process exit.
- In default mode, normal SSH config resolution applies (for example `~/.ssh/config`, aliases, `ProxyJump`) because the server invokes the system `ssh` client without forcing a config path.
- In strict directory-only mode, SSH config files are bypassed with `ssh -F /dev/null`, and only literal IP targets are allowed at session-open time.

## Features

- Persistent sessions: `ssh_session_open`, `ssh_session_close`
- Reuse a session for command execution: `ssh_session_exec`
- Session visibility: `ssh_session_list`
- Explicit cleanup: `ssh_session_gc`
- Two execution modes:
  - `isolated`: persistent ControlMaster transport; each command runs in a clean execution context
  - `shell`: long-lived remote shell with shared state (`cd`, shell vars, exports)
- Auto-reconnect support for transport drops (`ONEMCP_SSH_SESSION_RECONNECT_*`)
- Per-command env overrides with key-pattern redaction counters in logs
- Optional SSH target directory (named targets) with optional strict enforcement mode

## Project Layout

```text
agentic-ssh-mcp/
├── pyproject.toml
├── README.md
├── ssh_directory.sample.json
└── src/ssh_session_mcp/
    ├── __init__.py
    ├── models.py
    ├── output.py
    ├── server.py
    └── ssh_sessions.py
```

## Requirements

- Python 3.10+
- OpenSSH client (`ssh`)
- Optional: `sshpass` (only needed when password auth is used)

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Dry-run boot:

```bash
ssh-session-mcp --dry-run
```

Use a custom SSH directory path:

```bash
ssh-session-mcp --ssh-directory /abs/path/to/ssh_directory.json
```

Codex MCP registration example:

```bash
codex mcp add ssh-session -- ssh-session-mcp --ssh-directory /abs/path/to/ssh_directory.json
```

## Operating Modes

### Default Mode (`ONEMCP_SSH_DIRECTORY_ONLY=0`)

- SSH directory is optional.
- You can open sessions via configured `target` ids or direct `host`.
- Unknown `target` values are treated as direct host/alias values for backward compatibility.
- User/system SSH config is honored.

### Directory-Only Strict Mode (`ONEMCP_SSH_DIRECTORY_ONLY=1`)

- Startup requires at least one valid directory target entry.
- `ssh_session_open` must resolve to a configured target id.
- Direct host mode is blocked.
- The resolved target host must be a literal IP address (IPv4/IPv6) at open time.
- SSH config is disabled with `ssh -F /dev/null`.

## Startup and Directory Behavior

- Missing SSH directory path: server starts with zero configured targets.
- Existing directory with invalid JSON/list shape: startup fails.
- Existing directory with zero valid entries: startup fails.
- Strict mode + no valid configured targets: startup fails.
- Startup validation failures return exit code `2`.

## SSH Directory Format

Directory usage is optional in default mode and mandatory in strict mode.

Example:

```json
[
  {
    "id": "vortex1",
    "host": "203.0.113.10",
    "user": "root",
    "port": 22,
    "password_env": "ONEMCP_SSH_PASSWORD",
    "description": "Prod node",
    "allow_agent": true
  }
]
```

Fields:

- `id` (required): tool-facing target id (`name` is also accepted as an input alias in parser)
- `host` (required): hostname/IP/alias in default mode; must be literal IP when strict mode is enabled and the session is opened
- `port` (optional): default `22`
- `user` (optional): remote username
- `password_env` (optional): env var name used for password auth
- `description` or `comment` (optional)
- `allow_agent` (optional): default `true`; when `false`, SSH agent variables are removed from env

## MCP Tools

### `ssh_target_list()`

- Lists configured targets from the directory.
- If none are configured, returns guidance to use direct `host` mode.

### `ssh_session_open(...)`

Input fields:

- `target` (string, optional): configured target id; if not found in default mode, treated as direct host/alias
- `id` (string, optional): alias for `target` in handler
- `host` (string, optional): direct host/IP/alias or `user@host`
- `user` (string, optional): explicit username override
- `port` (int, optional): override port (`1..65535`)
- `password_env` (string, optional): override password env var name
- `allow_agent` (bool, optional): override agent usage
- `exec_mode` (string, optional): `isolated` (default) or `shell`
- `idle_timeout_s` (number, optional): must be positive and cannot exceed server limit
- `max_lifetime_s` (number, optional): must be positive and cannot exceed server limit
- `metadata` (object, optional): caller metadata

Resolution behavior:

- One of `target` or `host` is required.
- If `target` matches a configured entry, that entry is used.
- If `target` matches and `host` is also supplied, request is rejected.
- If `target` does not match and default mode is enabled, `target` is treated as direct host/alias.
- If both unknown `target` and `host` are supplied, `host` is used.
- Username precedence: `user` override -> parsed `user@host` -> configured `user` -> `ONEMCP_SSH_USERNAME` -> remote default.
- Password env precedence: `password_env` override -> configured `password_env` -> `ONEMCP_SSH_PASSWORD`.

### `ssh_session_exec(session_id, command, timeout?, cwd?, env?, stream?)`

- Executes a command inside an existing open session.
- `cwd` applies only to `shell` mode; in `isolated` mode it is ignored (logged as informational).
- `env` accepts string keys with string/number/boolean values (converted to strings).
- `env` keys must be shell-safe names (alnum/underscore, not starting with digit).
- `stream` is accepted but currently informational; responses are buffered.
- Non-zero remote exit codes produce `isError=true`.
- Command timeout resets transport and returns an error response.
- Transport drop triggers reconnect attempts according to session env settings.
- Output is truncated to keep response size bounded (`stdout` and `stderr` independently).

### `ssh_session_list(target?, include_closed?)`

- Lists tracked sessions.
- `include_closed` defaults to `false`.
- `target` filters by target id (case-insensitive).

### `ssh_session_close(session_id, reason?)`

- Closes one session.
- If already closed, returns current closed state details.

### `ssh_session_gc(force?)`

- Runs GC and reports counts:
  - `closed_count`
  - `expired_count`
  - `lru_count`
  - `forced_count`
  - `remaining_open`

## Environment Variables

Auth and transport defaults:

- `ONEMCP_SSH_USERNAME` default username fallback
- `ONEMCP_SSH_PASSWORD` default password fallback
- `ONEMCP_SSH_BINARY` SSH executable name/path (default `ssh`)
- `ONEMCP_SSH_TIMEOUT` default SSH timeout in seconds (default `10`)

Session controls:

- `ONEMCP_SSH_SESSION_ENABLED` enable/disable session tools (default `1`)
- `ONEMCP_SSH_SESSION_IDLE_TIMEOUT_S` server idle timeout limit/default (default `900`)
- `ONEMCP_SSH_SESSION_MAX_LIFETIME_S` server max lifetime limit/default (default `3600`)
- `ONEMCP_SSH_SESSION_MAX_GLOBAL` max open sessions globally (default `64`)
- `ONEMCP_SSH_SESSION_MAX_PER_TARGET` max open sessions per target id (default `6`)
- `ONEMCP_SSH_SESSION_RECONNECT_ATTEMPTS` retries after transport drop (default `1`)
- `ONEMCP_SSH_SESSION_RECONNECT_BACKOFF_S` reconnect backoff (default `3`)
- `ONEMCP_SSH_SESSION_REDACT_ENV_KEYS` comma-separated key patterns for redaction counters (default includes `TOKEN,SECRET,KEY,PASSWORD,PASS,AUTH,COOKIE`)
- `ONEMCP_SSH_DIRECTORY_ONLY` strict directory mode toggle (default `0`)

Server runtime:

- `SSH_SESSION_MCP_SSH_DIRECTORY_PATH` default value for `--ssh-directory`
- `SSH_SESSION_MCP_LOG_LEVEL` default value for `--log-level`
- `SSH_SESSION_MCP_LOG_FILE` default value for `--log-file`

Boolean parsing accepts truthy values: `1`, `true`, `yes`, `on` (case-insensitive).

## Execution Notes

- `isolated` mode uses SSH ControlMaster sockets under a temp directory.
- `shell` mode opens a persistent remote shell and uses a marker protocol for command completion.
- Nested interactive commands (including nested `ssh`) run with stdin detached in shell mode to avoid marker deadlocks.
- Session GC runs before tool operations and enforces idle/lifetime plus LRU caps.
- The server exposes resources for:
  - `README.md`
  - active SSH directory JSON (when the file exists)

## Example Flows

Direct host mode:

```json
{"name":"ssh_session_open","arguments":{"host":"ops@bastion-prod","exec_mode":"shell"}}
```

Directory target mode:

```json
{"name":"ssh_session_open","arguments":{"target":"vortex1","exec_mode":"isolated"}}
```

Command execution:

```json
{"name":"ssh_session_exec","arguments":{"session_id":"<id>","command":"uname -a","timeout":20}}
```

Close:

```json
{"name":"ssh_session_close","arguments":{"session_id":"<id>","reason":"done"}}
```

Strict mode startup example:

```bash
ONEMCP_SSH_DIRECTORY_ONLY=1 ssh-session-mcp --ssh-directory /abs/path/to/ssh_directory.json
```

## License

MIT
