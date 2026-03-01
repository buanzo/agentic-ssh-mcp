"""Standalone MCP server exposing persistent SSH session tools."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import logging
from logging import FileHandler, StreamHandler
import os
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import SshTarget
from .ssh_sessions import SshSessionManager, _SESSION_DIRECTORY_ONLY_ENV

SERVER_NAME = "ssh-session-mcp"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"
DEFAULT_MIME = "text/plain"
MAX_PAYLOAD_BYTES = 120_000
SSH_DEFAULT_TIMEOUT = float(os.environ.get("ONEMCP_SSH_TIMEOUT", 10))
SSH_USERNAME_ENV = "ONEMCP_SSH_USERNAME"
SSH_PASSWORD_ENV = "ONEMCP_SSH_PASSWORD"

DEFAULT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SSH_DIRECTORY_PATH = Path(__file__).resolve().parents[2] / "ssh_directory.sample.json"
DEFAULT_README_PATH = Path(__file__).resolve().parents[2] / "README.md"

LOGGER = logging.getLogger(SERVER_NAME)
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s [req=%(request_id)s method=%(method)s tool=%(tool)s] %(message)s"


class _SafeFormatter(logging.Formatter):
    """Formatter that backfills missing structured fields to avoid KeyError."""

    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover
        for field in ("request_id", "method", "tool"):
            if not hasattr(record, field):
                setattr(record, field, "-")
        return super().format(record)


class _ContextFilter(logging.Filter):
    """Ensure optional log fields always exist so formatters never KeyError."""

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        if not hasattr(record, "method"):
            record.method = "-"
        if not hasattr(record, "tool"):
            record.tool = "-"
        return True


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[..., Any]


@dataclass(frozen=True)
class ResourceEntry:
    name: str
    path: Path
    description: str
    mime_type: str = DEFAULT_MIME

    @property
    def uri(self) -> str:
        return f"file://{self.path}"


def _read_text(path: Path, limit: int = MAX_PAYLOAD_BYTES) -> str:
    data = path.read_bytes()
    if len(data) > limit:
        raise ValueError(f"Refusing to read {path} because it is larger than {limit} bytes")
    return data.decode("utf-8", errors="replace")


def _send_message(message: Dict[str, Any], wire_mode: str = "framed") -> None:
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if wire_mode == "ndjson":
        sys.stdout.buffer.write(payload + b"\n")
    else:
        sys.stdout.buffer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("utf-8"))
        sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _error_response(request_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    error: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _success_response(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _read_message() -> Tuple[Optional[Dict[str, Any]], str]:
    """Read one JSON-RPC request supporting Content-Length framing and NDJSON."""

    while True:
        first = sys.stdin.buffer.readline()
        if not first:
            return None, "framed"
        if first.strip():
            break

    # NDJSON fallback: line starts with JSON object directly.
    if first.lstrip().startswith(b"{"):
        try:
            payload = json.loads(first.decode("utf-8"))
        except json.JSONDecodeError:
            return None, "ndjson"
        return payload, "ndjson"

    header_lines = [first]
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None, "framed"
        header_lines.append(line)
        if line in (b"\n", b"\r\n"):
            break

    content_length: Optional[int] = None
    for raw in header_lines:
        text = raw.decode("utf-8", errors="replace").strip()
        if not text or ":" not in text:
            continue
        key, value = text.split(":", 1)
        if key.lower() == "content-length":
            try:
                content_length = int(value.strip())
            except ValueError:
                return None, "framed"

    if content_length is None or content_length < 0:
        return None, "framed"
    if content_length > MAX_PAYLOAD_BYTES:
        # Drain oversized payload then reject.
        _ = sys.stdin.buffer.read(content_length)
        return None, "framed"

    body = sys.stdin.buffer.read(content_length)
    if len(body) != content_length:
        return None, "framed"

    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return None, "framed"
    return payload, "framed"


def _configure_logging(level: str, log_file: Optional[Path]) -> None:
    lvl = getattr(logging, str(level).upper(), logging.INFO)
    formatter = _SafeFormatter(LOG_FORMAT)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(lvl)
    root.addFilter(_ContextFilter())

    console = StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    console.addFilter(_ContextFilter())
    root.addHandler(console)

    if log_file:
        try:
            fh = FileHandler(log_file)
            fh.setFormatter(formatter)
            fh.addFilter(_ContextFilter())
            root.addHandler(fh)
        except OSError as exc:
            LOGGER.error("Failed to set file handler for logs: %s", exc, extra={"method": "init"})


def _load_ssh_directory(path: Path) -> List[SshTarget]:
    if not path.exists():
        LOGGER.info("SSH directory %s not found; continuing without predefined targets", path)
        return []

    text = _read_text(path)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid SSH directory JSON: {exc}") from exc

    if not isinstance(payload, list):
        raise ValueError("SSH directory JSON must be a list of entries")

    targets: List[SshTarget] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        try:
            targets.append(SshTarget.from_dict(entry))
        except ValueError as exc:
            LOGGER.warning("Skipping SSH target entry: %s", exc)

    if not targets:
        raise ValueError(f"SSH directory contains no valid target entries: {path}")
    return targets


def _targets_by_id(targets: List[SshTarget]) -> Dict[str, SshTarget]:
    return {target.target_id.lower(): target for target in targets}


class SshSessionMcpServer:
    def __init__(self, *, root: Path, ssh_directory_path: Path) -> None:
        self.root = root
        self.ssh_directory_path = ssh_directory_path
        self.initialized = False
        self.ssh_targets = _load_ssh_directory(ssh_directory_path)
        self.ssh_targets_index = _targets_by_id(self.ssh_targets)
        self.ssh_timeout = float(os.environ.get("ONEMCP_SSH_TIMEOUT", SSH_DEFAULT_TIMEOUT))
        self.ssh_binary = os.environ.get("ONEMCP_SSH_BINARY", "ssh")
        self.ssh_session_manager = SshSessionManager(
            targets_index=self.ssh_targets_index,
            ssh_binary=self.ssh_binary,
            ssh_timeout=self.ssh_timeout,
            password_env_default=SSH_PASSWORD_ENV,
            username_env_default=SSH_USERNAME_ENV,
            logger=LOGGER,
        )
        if self.ssh_session_manager.directory_only and not self.ssh_targets:
            raise ValueError(
                f"{_SESSION_DIRECTORY_ONLY_ENV}=1 requires a non-empty SSH target directory file"
            )
        self.resources = self._build_resources()
        self.tools = self._build_tools()

    def _build_resources(self) -> Dict[str, ResourceEntry]:
        entries = {
            "ssh_session_readme": ResourceEntry(
                name="README.md",
                path=DEFAULT_README_PATH,
                description="Standalone SSH Session MCP documentation.",
                mime_type="text/markdown",
            ),
            "ssh_directory": ResourceEntry(
                name=str(self.ssh_directory_path),
                path=self.ssh_directory_path,
                description="Active SSH target directory used by this server.",
                mime_type="application/json",
            ),
        }
        return {key: value for key, value in entries.items() if value.path.exists()}

    def _build_tools(self) -> Dict[str, ToolDefinition]:
        return {
            "ssh_target_list": ToolDefinition(
                name="ssh_target_list",
                description="List SSH targets loaded from the SSH directory file.",
                input_schema={"type": "object", "properties": {}},
                handler=self._tool_ssh_target_list,
            ),
            "ssh_session_open": ToolDefinition(
                name="ssh_session_open",
                description="Open a persistent unrestricted SSH session (process-local, in-memory).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Configured target id (or host alias if no matching configured target exists).",
                        },
                        "host": {
                            "type": "string",
                            "description": "Direct host/IP/alias (or user@host) when not using configured targets.",
                        },
                        "user": {
                            "type": "string",
                            "description": "Optional remote username override (direct mode or configured target).",
                        },
                        "port": {
                            "type": "integer",
                            "description": "Optional SSH port override (1-65535).",
                        },
                        "password_env": {
                            "type": "string",
                            "description": "Optional password env-var name override.",
                        },
                        "allow_agent": {
                            "type": "boolean",
                            "description": "Optional override to enable/disable SSH agent forwarding/use.",
                        },
                        "exec_mode": {
                            "type": "string",
                            "description": "Session mode: isolated (default) or shell (shared state).",
                        },
                        "idle_timeout_s": {
                            "type": "number",
                            "description": "Optional per-session idle timeout; cannot exceed server limit.",
                        },
                        "max_lifetime_s": {
                            "type": "number",
                            "description": "Optional per-session max lifetime; cannot exceed server limit.",
                        },
                        "metadata": {
                            "type": "object",
                            "description": "Optional non-secret caller metadata hints.",
                        },
                    },
                    "anyOf": [{"required": ["target"]}, {"required": ["host"]}],
                },
                handler=self.ssh_session_manager.tool_ssh_session_open,
            ),
            "ssh_session_exec": ToolDefinition(
                name="ssh_session_exec",
                description="Execute a command in a persistent unrestricted SSH session.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Session id from ssh_session_open."},
                        "command": {"type": "string", "description": "Remote command (no validation)."},
                        "timeout": {
                            "type": "number",
                            "description": "Optional timeout in seconds (defaults to ONEMCP_SSH_TIMEOUT or 10s).",
                        },
                        "cwd": {
                            "type": "string",
                            "description": "Optional working directory hint (effective in exec_mode=shell).",
                        },
                        "env": {
                            "type": "object",
                            "description": "Optional per-command environment overrides (non-persistent).",
                        },
                        "stream": {
                            "type": "boolean",
                            "description": "Request streaming behavior (v1 returns buffered output).",
                        },
                    },
                    "required": ["session_id", "command"],
                },
                handler=self.ssh_session_manager.tool_ssh_session_exec,
            ),
            "ssh_session_list": ToolDefinition(
                name="ssh_session_list",
                description="List tracked SSH sessions (open by default).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Optional target id filter."},
                        "include_closed": {
                            "type": "boolean",
                            "description": "Include closed sessions in output (default false).",
                        },
                    },
                },
                handler=self.ssh_session_manager.tool_ssh_session_list,
            ),
            "ssh_session_close": ToolDefinition(
                name="ssh_session_close",
                description="Close an existing persistent SSH session.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Session id from ssh_session_open."},
                        "reason": {"type": "string", "description": "Optional close reason for audit output."},
                    },
                    "required": ["session_id"],
                },
                handler=self.ssh_session_manager.tool_ssh_session_close,
            ),
            "ssh_session_gc": ToolDefinition(
                name="ssh_session_gc",
                description="Run session garbage collection (TTL/LRU) or force-close all sessions.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "force": {
                            "type": "boolean",
                            "description": "When true, force-close all open SSH sessions.",
                        },
                    },
                },
                handler=self.ssh_session_manager.tool_ssh_session_gc,
            ),
        }

    def _tool_ssh_target_list(self, _: Dict[str, Any]) -> Dict[str, Any]:
        if not self.ssh_targets:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "No SSH targets configured. Use ssh_session_open(host=...) for direct mode.",
                    }
                ],
                "isError": False,
            }

        lines = ["id | host | port | user_source | agent | description", "-- | -- | -- | -- | -- | --"]
        for target in self.ssh_targets:
            user_hint = target.user or f"env:{SSH_USERNAME_ENV} or remote default"
            agent_state = "enabled" if target.allow_agent else "disabled"
            lines.append(
                f"{target.target_id} | {target.host} | {target.port} | {user_hint} | {agent_state} | {target.description}"
            )
        return {"content": [{"type": "text", "text": "\n".join(lines)}], "isError": False}

    # --- MCP handlers -------------------------------------------------- #

    def handle(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(message, dict):
            return _error_response(None, -32600, "Invalid request")

        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params", {})

        if method == "initialize":
            return self._handle_initialize(request_id)
        if method == "initialized":
            return None
        if not self.initialized and method not in {"shutdown"}:
            return _error_response(request_id, -32002, "Server not initialized")

        if method in {"resources/list", "list_resources"}:
            return self._handle_list_resources(request_id)
        if method in {"resources/read", "read_resource"}:
            return self._handle_read_resource(request_id, params)
        if method in {"resources/templates/list"}:
            return _success_response(request_id, {"resourceTemplates": []})

        if method in {"tools/list", "list_tools"}:
            return self._handle_list_tools(request_id)
        if method in {"tools/call", "call_tool"}:
            return self._handle_call_tool(request_id, params)
        if method == "shutdown":
            return _success_response(request_id, {})

        if request_id is None:
            return None
        return _error_response(request_id, -32601, f"Method not found: {method}")

    def _handle_initialize(self, request_id: Any) -> Dict[str, Any]:
        self.initialized = True
        return _success_response(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "capabilities": {
                    "resources": {"listChanged": False},
                    "prompts": {},
                    "tools": {"listChanged": False},
                },
            },
        )

    def _handle_list_resources(self, request_id: Any) -> Dict[str, Any]:
        resources = [
            {
                "uri": entry.uri,
                "name": entry.name,
                "description": entry.description,
                "mimeType": entry.mime_type,
            }
            for entry in self.resources.values()
        ]
        return _success_response(request_id, {"resources": resources})

    def _handle_read_resource(self, request_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        uri = params.get("uri")
        if not isinstance(uri, str):
            return _error_response(request_id, -32602, "uri is required")

        matched = next((entry for entry in self.resources.values() if entry.uri == uri), None)
        if not matched:
            return _error_response(request_id, -32001, f"Unknown resource: {uri}")

        try:
            text = _read_text(matched.path)
        except Exception as exc:  # pylint: disable=broad-except
            return _error_response(request_id, -32000, str(exc))

        return _success_response(
            request_id,
            {"contents": [{"uri": matched.uri, "mimeType": matched.mime_type, "text": text}]},
        )

    def _handle_list_tools(self, request_id: Any) -> Dict[str, Any]:
        tools = [
            {
                "name": definition.name,
                "description": definition.description,
                "inputSchema": definition.input_schema,
            }
            for definition in self.tools.values()
        ]
        return _success_response(request_id, {"tools": tools})

    def _handle_call_tool(self, request_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str):
            return _error_response(request_id, -32602, "name is required")

        definition = self.tools.get(name)
        if not definition:
            return _error_response(request_id, -32001, f"Unknown tool: {name}")

        try:
            result = definition.handler(arguments)
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.exception("tool failed: %s", name, extra={"tool": name})
            result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}

        return _success_response(
            request_id,
            {"content": result.get("content", []), "isError": result.get("isError", False)},
        )


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Standalone MCP server for persistent SSH sessions")
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_ROOT,
        help="Project root path (default: this project).",
    )
    parser.add_argument(
        "--ssh-directory",
        type=Path,
        default=Path(os.environ.get("SSH_SESSION_MCP_SSH_DIRECTORY_PATH", DEFAULT_SSH_DIRECTORY_PATH)),
        help="Path to SSH targets JSON (or SSH_SESSION_MCP_SSH_DIRECTORY_PATH).",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("SSH_SESSION_MCP_LOG_LEVEL", "INFO"),
        help="Logging level (DEBUG, INFO, WARNING).",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=os.environ.get("SSH_SESSION_MCP_LOG_FILE"),
        help="Optional log file path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load config and initialize server, then exit before MCP loop.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    _configure_logging(str(args.log_level), args.log_file)

    try:
        server = SshSessionMcpServer(
            root=args.root.resolve(),
            ssh_directory_path=args.ssh_directory.resolve(),
        )
    except ValueError as exc:
        LOGGER.error("startup failed: %s", exc, extra={"method": "init"})
        return 2

    LOGGER.info(
        "booted targets=%s tools=%s dry_run=%s",
        len(server.ssh_targets),
        len(server.tools),
        args.dry_run,
    )

    if args.dry_run:
        return 0

    while True:
        message, wire_mode = _read_message()
        if message is None:
            break
        response = server.handle(message)
        if response:
            _send_message(response, wire_mode=wire_mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
