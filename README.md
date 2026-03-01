# SSH Session MCP

A standalone, agent-focused MCP server for **persistent SSH sessions**.

This project provides explicit lifecycle tools so agents can open a remote SSH transport once, run many commands efficiently, and close it when done.

## Why this exists

Most naive SSH tooling opens one connection per command. That causes:

- extra latency per command
- unnecessary network overhead
- worse scaling when agents parallelize tasks

`ssh-session-mcp` solves this by exposing session primitives directly.

## Features

- Persistent SSH sessions (`ssh_session_open` / `ssh_session_close`)
- Command execution inside an existing session (`ssh_session_exec`)
- Session inventory (`ssh_session_list`)
- Explicit garbage collection (`ssh_session_gc`)
- Two execution modes:
  - `isolated`: persistent control socket, each command runs in clean execution context
  - `shell`: long-lived remote shell with shared state (`cd`, shell vars, exports)
- One-shot auto-reconnect with backoff for transport drops (configurable)
- Per-command env injection with secret-safe key redaction counters in logs
- Process-local, in-memory session pool (sessions do not survive process restart)

## Security model

- No secrets in repository files.
- Password auth is optional and sourced from env vars only.
- SSH agent/key auth is preferred.
- Session metadata is process-local and ephemeral.
- Commands are unrestricted by design; you should run this server only in trusted workflows.

## Project layout

```text
ssh_session_mcp/
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
- Optional: `sshpass` if you use password-based auth

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Dry-run boot check:

```bash
ssh-session-mcp --dry-run
```

Run with a custom target directory:

```bash
ssh-session-mcp --ssh-directory /abs/path/to/ssh_directory.json
```

## Use from Codex

Example MCP registration:

```bash
codex mcp add ssh-session -- ssh-session-mcp --ssh-directory /abs/path/to/ssh_directory.json
```

## SSH target directory format

`ssh_directory.sample.json` shows the schema:

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

- `id` (required): tool-facing target id
- `host` (required): hostname or IP
- `port` (optional): default `22`
- `user` (optional): remote username; otherwise env fallback
- `password_env` (optional): env var name for password auth
- `description` (optional)
- `allow_agent` (optional, default `true`)

## Tools

- `ssh_target_list()`
  - lists loaded targets and auth hints
- `ssh_session_open(target, exec_mode?, idle_timeout_s?, max_lifetime_s?, metadata?)`
- `ssh_session_exec(session_id, command, timeout?, cwd?, env?, stream?)`
- `ssh_session_list(target?, include_closed?)`
- `ssh_session_close(session_id, reason?)`
- `ssh_session_gc(force?)`

## Environment variables

Auth and transport defaults:

- `ONEMCP_SSH_USERNAME` (optional fallback username)
- `ONEMCP_SSH_PASSWORD` (optional fallback password)
- `ONEMCP_SSH_BINARY` (default `ssh`)
- `ONEMCP_SSH_TIMEOUT` (default `10`)

Session controls:

- `ONEMCP_SSH_SESSION_ENABLED` (default `1`)
- `ONEMCP_SSH_SESSION_IDLE_TIMEOUT_S` (default `900`)
- `ONEMCP_SSH_SESSION_MAX_LIFETIME_S` (default `3600`)
- `ONEMCP_SSH_SESSION_MAX_GLOBAL` (default `64`)
- `ONEMCP_SSH_SESSION_MAX_PER_TARGET` (default `6`)
- `ONEMCP_SSH_SESSION_RECONNECT_ATTEMPTS` (default `1`)
- `ONEMCP_SSH_SESSION_RECONNECT_BACKOFF_S` (default `3`)
- `ONEMCP_SSH_SESSION_REDACT_ENV_KEYS` (default patterns include `TOKEN,SECRET,KEY,PASSWORD,PASS,AUTH,COOKIE`)

Server runtime:

- `SSH_SESSION_MCP_SSH_DIRECTORY_PATH`
- `SSH_SESSION_MCP_LOG_LEVEL`
- `SSH_SESSION_MCP_LOG_FILE`

## Behavior notes

- `shell` mode preserves shell context between commands.
- `isolated` mode preserves transport, not shell state.
- For nested SSH in `shell` mode, command stdin is isolated to avoid marker parsing hangs.
- Sessions are automatically cleaned on process exit.

## Example flow

1. Open session:

```json
{"name":"ssh_session_open","arguments":{"target":"vortex1","exec_mode":"shell"}}
```

2. Execute commands:

```json
{"name":"ssh_session_exec","arguments":{"session_id":"<id>","command":"export X=42"}}
{"name":"ssh_session_exec","arguments":{"session_id":"<id>","command":"echo $X"}}
```

3. Close session:

```json
{"name":"ssh_session_close","arguments":{"session_id":"<id>","reason":"done"}}
```

## License

MIT
