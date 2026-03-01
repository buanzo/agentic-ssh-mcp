"""SSH tool handlers, including persistent session lifecycle tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import atexit
import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .output import truncate_output
from .models import SshTarget

_TRUTHY = {"1", "true", "yes", "on"}

_SESSION_ENABLED_ENV = "ONEMCP_SSH_SESSION_ENABLED"
_SESSION_IDLE_TIMEOUT_ENV = "ONEMCP_SSH_SESSION_IDLE_TIMEOUT_S"
_SESSION_MAX_LIFETIME_ENV = "ONEMCP_SSH_SESSION_MAX_LIFETIME_S"
_SESSION_MAX_GLOBAL_ENV = "ONEMCP_SSH_SESSION_MAX_GLOBAL"
_SESSION_MAX_PER_TARGET_ENV = "ONEMCP_SSH_SESSION_MAX_PER_TARGET"
_SESSION_RECONNECT_ATTEMPTS_ENV = "ONEMCP_SSH_SESSION_RECONNECT_ATTEMPTS"
_SESSION_RECONNECT_BACKOFF_ENV = "ONEMCP_SSH_SESSION_RECONNECT_BACKOFF_S"
_SESSION_REDACT_ENV_KEYS_ENV = "ONEMCP_SSH_SESSION_REDACT_ENV_KEYS"

_SESSION_IDLE_TIMEOUT_DEFAULT = 900.0
_SESSION_MAX_LIFETIME_DEFAULT = 3600.0
_SESSION_MAX_GLOBAL_DEFAULT = 64
_SESSION_MAX_PER_TARGET_DEFAULT = 6
_SESSION_RECONNECT_ATTEMPTS_DEFAULT = 1
_SESSION_RECONNECT_BACKOFF_DEFAULT = 3.0

_SESSION_MARKER_PREFIX = "__ONEMCP_DONE__"
_SESSION_SHELL_REMOTE = "if command -v bash >/dev/null 2>&1; then exec bash --noprofile --norc; else exec sh; fi"
_REDACT_PATTERNS_DEFAULT = ("TOKEN", "SECRET", "KEY", "PASSWORD", "PASS", "AUTH", "COOKIE")
_TRANSPORT_DROP_HINTS = (
    "control socket connect",
    "mux_client_request_session",
    "master is dead",
    "broken pipe",
    "connection reset",
    "connection timed out",
    "connection closed",
    "closed by remote host",
    "kex_exchange_identification",
    "no route to host",
    "network is unreachable",
)


def _mcp_text(text: str, *, is_error: bool = False) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in _TRUTHY


def _parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return _is_truthy(value)


def _iso_ts(epoch_s: Optional[float]) -> str:
    if epoch_s is None:
        return "-"
    return datetime.fromtimestamp(epoch_s, tz=timezone.utc).isoformat(timespec="seconds")


def _sanitize_log_command(command: str) -> str:
    flattened = " ".join(command.splitlines())
    return flattened[:197] + "..." if len(flattened) > 200 else flattened


def _looks_like_transport_drop(stderr: str) -> bool:
    text = (stderr or "").lower()
    return any(hint in text for hint in _TRANSPORT_DROP_HINTS)


def _parse_positive_float(raw: Any, *, field_name: str) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a positive number") from exc
    if value <= 0:
        raise ValueError(f"{field_name} must be a positive number")
    return value


def _parse_positive_int(raw: Any, *, field_name: str) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _parse_env_map(raw: Any) -> Dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("env must be an object of string keys to string values")
    mapped: Dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key:
            raise ValueError("env keys must be non-empty strings")
        if not key.replace("_", "a").isalnum() or key[0].isdigit():
            raise ValueError(f"invalid env key: {key}")
        if value is None:
            mapped[key] = ""
        elif isinstance(value, (str, int, float, bool)):
            mapped[key] = str(value)
        else:
            raise ValueError(f"env value for key '{key}' must be string/number/boolean")
    return mapped


def _env_prefixed_command(command: str, env_map: Dict[str, str]) -> str:
    if not env_map:
        return command
    assignments = " ".join(f"{key}={shlex.quote(value)}" for key, value in env_map.items())
    return f"{assignments} {command}"


def _bytes_len(text: str) -> int:
    return len((text or "").encode("utf-8", errors="replace"))


def _safe_session_reason(reason: Optional[str], fallback: str) -> str:
    if not reason:
        return fallback
    return reason.strip() or fallback


def _env_bool(name: str, default: bool, logger) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = _is_truthy(raw)
    logger.debug("ssh_session_env_bool name=%s value=%s", name, value, extra={"tool": "ssh_session"})
    return value


def _env_float(name: str, default: float, *, min_value: float, logger) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
        if value < min_value:
            raise ValueError
        return value
    except (TypeError, ValueError):
        logger.warning(
            "Invalid %s=%r; using default %s",
            name,
            raw,
            default,
            extra={"tool": "ssh_session"},
        )
        return default


def _env_int(name: str, default: int, *, min_value: int, logger) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
        if value < min_value:
            raise ValueError
        return value
    except (TypeError, ValueError):
        logger.warning(
            "Invalid %s=%r; using default %s",
            name,
            raw,
            default,
            extra={"tool": "ssh_session"},
        )
        return default


def _env_patterns(name: str, defaults: Tuple[str, ...]) -> Tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None:
        return defaults
    parts = [item.strip().upper() for item in raw.split(",")]
    cleaned = tuple(item for item in parts if item)
    return cleaned or defaults


def _redacted_key_count(env_map: Dict[str, str], patterns: Tuple[str, ...]) -> int:
    count = 0
    for key in env_map.keys():
        key_upper = key.upper()
        if any(pattern in key_upper for pattern in patterns):
            count += 1
    return count


@dataclass
class _SshSession:
    session_id: str
    target: SshTarget
    destination: str
    user: Optional[str]
    exec_mode: str
    idle_timeout_s: float
    max_lifetime_s: float
    opened_at: float
    last_used_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    state: str = "open"
    command_count: int = 0
    closed_at: Optional[float] = None
    close_reason: Optional[str] = None
    socket_path: Optional[str] = None
    shell_proc: Optional[subprocess.Popen] = None
    shell_buffer: bytes = b""

    @property
    def target_id(self) -> str:
        return self.target.target_id


class _SshSessionTransportError(RuntimeError):
    """Transport-level failure that should trigger reconnect/retry."""


class SshSessionManager:
    """Persistent unrestricted SSH session pool."""

    def __init__(
        self,
        *,
        targets_index: Mapping[str, SshTarget],
        ssh_binary: str,
        ssh_timeout: float,
        password_env_default: str,
        username_env_default: str,
        logger,
    ) -> None:
        self.targets_index = targets_index
        self.ssh_binary = ssh_binary
        self.ssh_timeout = ssh_timeout
        self.password_env_default = password_env_default
        self.username_env_default = username_env_default
        self.logger = logger
        self.enabled = _env_bool(_SESSION_ENABLED_ENV, True, logger)
        self.idle_timeout_default = _env_float(
            _SESSION_IDLE_TIMEOUT_ENV,
            _SESSION_IDLE_TIMEOUT_DEFAULT,
            min_value=1.0,
            logger=logger,
        )
        self.max_lifetime_default = _env_float(
            _SESSION_MAX_LIFETIME_ENV,
            _SESSION_MAX_LIFETIME_DEFAULT,
            min_value=1.0,
            logger=logger,
        )
        self.max_sessions_global = _env_int(
            _SESSION_MAX_GLOBAL_ENV,
            _SESSION_MAX_GLOBAL_DEFAULT,
            min_value=1,
            logger=logger,
        )
        self.max_sessions_per_target = _env_int(
            _SESSION_MAX_PER_TARGET_ENV,
            _SESSION_MAX_PER_TARGET_DEFAULT,
            min_value=1,
            logger=logger,
        )
        self.reconnect_attempts = _env_int(
            _SESSION_RECONNECT_ATTEMPTS_ENV,
            _SESSION_RECONNECT_ATTEMPTS_DEFAULT,
            min_value=0,
            logger=logger,
        )
        self.reconnect_backoff_s = _env_float(
            _SESSION_RECONNECT_BACKOFF_ENV,
            _SESSION_RECONNECT_BACKOFF_DEFAULT,
            min_value=0.0,
            logger=logger,
        )
        self.redact_patterns = _env_patterns(_SESSION_REDACT_ENV_KEYS_ENV, _REDACT_PATTERNS_DEFAULT)
        self._lock = threading.RLock()
        self._sessions: Dict[str, _SshSession] = {}
        self._socket_root = Path(tempfile.mkdtemp(prefix="onemcp-ssh-"))
        self._closed_at_exit = False
        atexit.register(self._cleanup_atexit)

    # --- Public MCP handlers ------------------------------------------- #

    def tool_ssh_session_open(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return _mcp_text(
                f"SSH session tools are disabled. Set {_SESSION_ENABLED_ENV}=1 to enable.",
                is_error=True,
            )

        target_id = args.get("target") or args.get("id") or args.get("host")
        exec_mode = (args.get("exec_mode") or "isolated").strip().lower() if isinstance(args.get("exec_mode"), str) else "isolated"
        metadata = args.get("metadata") or {}
        idle_timeout_raw = args.get("idle_timeout_s")
        max_lifetime_raw = args.get("max_lifetime_s")

        if not isinstance(target_id, str) or not target_id.strip():
            raise ValueError("target must be a non-empty string")
        if exec_mode not in {"isolated", "shell"}:
            raise ValueError("exec_mode must be 'isolated' or 'shell'")
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")

        idle_timeout_s = self.idle_timeout_default
        if idle_timeout_raw is not None:
            idle_timeout_s = _parse_positive_float(idle_timeout_raw, field_name="idle_timeout_s")
            if idle_timeout_s > self.idle_timeout_default:
                raise ValueError(
                    f"idle_timeout_s cannot exceed server limit {self.idle_timeout_default:g} seconds"
                )

        max_lifetime_s = self.max_lifetime_default
        if max_lifetime_raw is not None:
            max_lifetime_s = _parse_positive_float(max_lifetime_raw, field_name="max_lifetime_s")
            if max_lifetime_s > self.max_lifetime_default:
                raise ValueError(
                    f"max_lifetime_s cannot exceed server limit {self.max_lifetime_default:g} seconds"
                )

        target = self.targets_index.get(target_id.strip().lower())
        if not target:
            return _mcp_text(f"Unknown SSH target: {target_id}", is_error=True)

        session_id = uuid.uuid4().hex
        created_at = time.time()
        user, destination = self._resolve_destination(target)
        session = _SshSession(
            session_id=session_id,
            target=target,
            destination=destination,
            user=user,
            exec_mode=exec_mode,
            idle_timeout_s=idle_timeout_s,
            max_lifetime_s=max_lifetime_s,
            opened_at=created_at,
            last_used_at=created_at,
            metadata=metadata,
            socket_path=str(self._socket_root / f"{session_id}.sock") if exec_mode == "isolated" else None,
        )

        with self._lock:
            self._gc_locked(force=False)
            self._sessions[session_id] = session
            try:
                self._open_transport(session)
            except Exception as exc:  # pylint: disable=broad-except
                self._sessions.pop(session_id, None)
                return _mcp_text(f"Failed to open SSH session: {exc}", is_error=True)
            self._gc_locked(force=False)

        lines = [
            f"session_id: {session.session_id}",
            f"target: {session.target_id}",
            f"destination: {session.destination}",
            f"user: {session.user or '(default remote user)'}",
            f"exec_mode: {session.exec_mode}",
            f"opened_at: {_iso_ts(session.opened_at)}",
            f"idle_timeout_s: {session.idle_timeout_s:g}",
            f"max_lifetime_s: {session.max_lifetime_s:g}",
        ]
        return _mcp_text("\n".join(lines))

    def tool_ssh_session_exec(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return _mcp_text(
                f"SSH session tools are disabled. Set {_SESSION_ENABLED_ENV}=1 to enable.",
                is_error=True,
            )

        session_id = args.get("session_id")
        command = args.get("command")
        timeout = _parse_positive_float(args.get("timeout", self.ssh_timeout), field_name="timeout")
        cwd = args.get("cwd")
        env_map = _parse_env_map(args.get("env"))
        stream_requested = _parse_bool(args.get("stream"), False)

        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        if not isinstance(command, str) or not command.strip():
            raise ValueError("command must be a non-empty string")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError("cwd must be a string when provided")

        with self._lock:
            self._gc_locked(force=False)
            session = self._sessions.get(session_id.strip())
            if not session:
                return _mcp_text(f"Unknown SSH session: {session_id}", is_error=True)
            if session.state != "open":
                return _mcp_text(f"SSH session is not open: {session_id} (state={session.state})", is_error=True)

        start = time.time()
        attempts = 0
        reconnect_happened = False
        retry_note = ""
        stdout = ""
        stderr = ""
        exit_code = 255

        max_attempts = 1 + self.reconnect_attempts
        while attempts < max_attempts:
            attempts += 1
            try:
                if session.exec_mode == "isolated":
                    if cwd:
                        self.logger.info(
                            "ssh_session_exec ignored cwd for isolated session session_id=%s",
                            session.session_id,
                            extra={"tool": "ssh_session_exec"},
                        )
                    stdout, stderr, exit_code = self._exec_isolated_once(
                        session,
                        command=command.strip(),
                        timeout=timeout,
                        env_map=env_map,
                    )
                else:
                    stdout, stderr, exit_code = self._exec_shell_once(
                        session,
                        command=command.strip(),
                        timeout=timeout,
                        cwd=cwd.strip() if isinstance(cwd, str) else None,
                        env_map=env_map,
                    )
                break
            except _SshSessionTransportError as exc:
                if attempts >= max_attempts:
                    return _mcp_text(
                        f"SSH session transport failed after {attempts} attempt(s): {exc}",
                        is_error=True,
                    )
                reconnect_happened = True
                retry_note = (
                    f"transport dropped; waiting {self.reconnect_backoff_s:g}s and retrying once"
                    if self.reconnect_attempts == 1
                    else f"transport dropped; waiting {self.reconnect_backoff_s:g}s before retry"
                )
                self.logger.warning(
                    "ssh_session transport drop session_id=%s attempt=%s/%s reason=%s",
                    session.session_id,
                    attempts,
                    max_attempts,
                    exc,
                    extra={"tool": "ssh_session_exec"},
                )
                if self.reconnect_backoff_s > 0:
                    time.sleep(self.reconnect_backoff_s)
                try:
                    with self._lock:
                        if session.state != "open":
                            return _mcp_text(
                                f"SSH session closed while reconnecting: {session.session_id}",
                                is_error=True,
                            )
                        self._reconnect_transport(session)
                except Exception as reconnect_exc:  # pylint: disable=broad-except
                    return _mcp_text(f"Failed to reconnect SSH session: {reconnect_exc}", is_error=True)
            except subprocess.TimeoutExpired:
                with self._lock:
                    try:
                        self._reconnect_transport(session)
                    except Exception:  # pylint: disable=broad-except
                        pass
                return _mcp_text(
                    (
                        f"SSH command timed out after {timeout:.1f}s. "
                        "Session transport was reset to recover."
                    ),
                    is_error=True,
                )
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.exception("ssh_session_exec failed", extra={"tool": "ssh_session_exec"})
                return _mcp_text(f"SSH session exec failed: {exc}", is_error=True)

        end = time.time()
        with self._lock:
            if session.state == "open":
                session.last_used_at = end
                session.command_count += 1

        stdout = truncate_output(stdout or "", limit=120_000)
        stderr = truncate_output(stderr or "", limit=120_000)
        env_key_count = len(env_map)
        redacted_key_count = _redacted_key_count(env_map, self.redact_patterns)
        command_display = truncate_output(command.strip(), limit=4_000)
        bytes_out = _bytes_len(stdout)
        bytes_err = _bytes_len(stderr)
        total_bytes = bytes_out + bytes_err

        self.logger.info(
            "ssh_session_exec session_id=%s target=%s command=%s attempts=%s exit=%s env_key_count=%s redacted_env_keys=%s",
            session.session_id,
            session.target_id,
            _sanitize_log_command(command_display),
            attempts,
            exit_code,
            env_key_count,
            redacted_key_count,
            extra={"tool": "ssh_session_exec"},
        )

        lines = [
            f"session_id: {session.session_id}",
            f"target: {session.target_id} ({session.destination})",
            f"user: {session.user or '(default remote user)'}",
            f"exec_mode: {session.exec_mode}",
            f"command: {command_display}",
            f"attempts: {attempts}",
            f"reconnected: {str(reconnect_happened).lower()}",
            f"exit_code: {exit_code}",
            f"timeout_s: {timeout:g}",
            f"env_key_count: {env_key_count}",
            f"redacted_env_key_count: {redacted_key_count}",
            f"start: {_iso_ts(start)}",
            f"end: {_iso_ts(end)}",
            f"duration_ms: {int((end - start) * 1000)}",
            f"bytes: {total_bytes}",
            f"bytes_out: {bytes_out}",
            f"bytes_err: {bytes_err}",
        ]
        if retry_note:
            lines.append(f"retry_notice: {retry_note}")
        if stream_requested:
            lines.append("stream: requested, but v1 returns buffered output")

        lines.extend(["", "stdout:", stdout.strip() or "(empty)"])
        if stderr:
            lines.extend(["", "stderr:", stderr.strip()])
        return _mcp_text("\n".join(lines), is_error=exit_code != 0)

    def tool_ssh_session_list(self, args: Dict[str, Any]) -> Dict[str, Any]:
        include_closed = _parse_bool(args.get("include_closed"), False)
        target_filter = args.get("target")
        if target_filter is not None and not isinstance(target_filter, str):
            raise ValueError("target must be a string when provided")
        target_filter_norm = target_filter.strip().lower() if isinstance(target_filter, str) else None

        with self._lock:
            self._gc_locked(force=False)
            sessions = list(self._sessions.values())

        rows: List[_SshSession] = []
        for session in sessions:
            if target_filter_norm and session.target_id.lower() != target_filter_norm:
                continue
            if not include_closed and session.state != "open":
                continue
            rows.append(session)

        if not rows:
            return _mcp_text("No SSH sessions found.")

        rows.sort(key=lambda item: (item.opened_at, item.session_id))
        lines = [
            "session_id | target | mode | state | opened_at | last_used_at | closed_at | commands",
            "-- | -- | -- | -- | -- | -- | -- | --",
        ]
        for session in rows:
            lines.append(
                " | ".join(
                    [
                        session.session_id,
                        session.target_id,
                        session.exec_mode,
                        session.state,
                        _iso_ts(session.opened_at),
                        _iso_ts(session.last_used_at),
                        _iso_ts(session.closed_at),
                        str(session.command_count),
                    ]
                )
            )
        return _mcp_text("\n".join(lines))

    def tool_ssh_session_close(self, args: Dict[str, Any]) -> Dict[str, Any]:
        session_id = args.get("session_id")
        reason = args.get("reason")
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        if reason is not None and not isinstance(reason, str):
            raise ValueError("reason must be a string when provided")
        reason_text = _safe_session_reason(reason, "manual close")

        with self._lock:
            self._gc_locked(force=False)
            session = self._sessions.get(session_id.strip())
            if not session:
                return _mcp_text(f"Unknown SSH session: {session_id}", is_error=True)
            if session.state != "open":
                lines = [
                    f"session_id: {session.session_id}",
                    f"state: {session.state}",
                    f"closed_at: {_iso_ts(session.closed_at)}",
                    f"reason: {session.close_reason or '(unknown)'}",
                ]
                return _mcp_text("\n".join(lines))
            self._close_session_locked(session, reason_text)

        lines = [
            f"session_id: {session.session_id}",
            "state: closed",
            f"closed_at: {_iso_ts(session.closed_at)}",
            f"reason: {session.close_reason}",
        ]
        return _mcp_text("\n".join(lines))

    def tool_ssh_session_gc(self, args: Dict[str, Any]) -> Dict[str, Any]:
        force = _parse_bool(args.get("force"), False)
        with self._lock:
            stats = self._gc_locked(force=force)
        lines = [
            f"closed_count: {stats['closed_count']}",
            f"expired_count: {stats['expired_count']}",
            f"lru_count: {stats['lru_count']}",
            f"forced_count: {stats['forced_count']}",
            f"remaining_open: {stats['remaining_open']}",
        ]
        return _mcp_text("\n".join(lines))

    # --- Session lifecycle internals ----------------------------------- #

    def _cleanup_atexit(self) -> None:
        with self._lock:
            if self._closed_at_exit:
                return
            self._closed_at_exit = True
            try:
                self._gc_locked(force=True, reason="process exit")
            finally:
                shutil.rmtree(self._socket_root, ignore_errors=True)

    def _resolve_destination(self, target: SshTarget) -> Tuple[Optional[str], str]:
        env = os.environ
        user = target.user or env.get(self.username_env_default)
        destination = f"{user}@{target.host}" if user else target.host
        return user, destination

    def _session_env(self, target: SshTarget) -> Dict[str, str]:
        env = os.environ.copy()
        if not target.allow_agent:
            env.pop("SSH_AUTH_SOCK", None)
            env.pop("SSH_AGENT_PID", None)
        return env

    def _build_ssh_invocation(
        self,
        *,
        target: SshTarget,
        destination: str,
        timeout: float,
    ) -> Tuple[List[str], Dict[str, str], str]:
        env = self._session_env(target)
        password_env_name = target.password_env or self.password_env_default
        password = env.get(password_env_name) if password_env_name else None
        ssh_exe = shutil.which(self.ssh_binary)
        if not ssh_exe:
            raise RuntimeError(f"SSH binary '{self.ssh_binary}' not found in PATH.")

        if password:
            sshpass_exe = shutil.which("sshpass")
            if not sshpass_exe:
                raise RuntimeError(
                    f"Password provided via env {password_env_name} but sshpass is not installed."
                )
            env["SSHPASS"] = password
            cmd = [
                sshpass_exe,
                "-e",
                ssh_exe,
                "-o",
                "BatchMode=no",
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
            ]
        else:
            cmd = [
                ssh_exe,
                "-o",
                "BatchMode=yes",
                "-o",
                "PreferredAuthentications=publickey,keyboard-interactive",
            ]
        cmd.extend(["-o", f"ConnectTimeout={max(1, int(timeout))}", "-p", str(target.port)])
        return cmd, env, destination

    def _open_transport(self, session: _SshSession) -> None:
        if session.exec_mode == "isolated":
            self._open_isolated_transport(session)
        else:
            self._open_shell_transport(session)

    def _reconnect_transport(self, session: _SshSession) -> None:
        self._close_transport(session)
        self._open_transport(session)

    def _close_transport(self, session: _SshSession) -> None:
        if session.exec_mode == "isolated":
            self._close_isolated_transport(session)
        else:
            self._close_shell_transport(session)

    def _open_isolated_transport(self, session: _SshSession) -> None:
        if not session.socket_path:
            raise RuntimeError("isolated session missing control socket path")
        cmd, env, destination = self._build_ssh_invocation(
            target=session.target,
            destination=session.destination,
            timeout=self.ssh_timeout,
        )
        cmd.extend(
            [
                "-o",
                "ControlMaster=yes",
                "-o",
                "ControlPersist=no",
                "-o",
                f"ControlPath={session.socket_path}",
                "-N",
                "-f",
                destination,
            ]
        )
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(self.ssh_timeout, 1.0) + 5.0,
            env=env,
        )
        if proc.returncode != 0:
            stderr = truncate_output(proc.stderr or "", limit=8_000).strip()
            raise RuntimeError(f"failed to open isolated SSH transport: {stderr or 'unknown error'}")

    def _close_isolated_transport(self, session: _SshSession) -> None:
        socket_path = session.socket_path
        if socket_path:
            ssh_exe = shutil.which(self.ssh_binary)
            if ssh_exe:
                cmd = [
                    ssh_exe,
                    "-S",
                    socket_path,
                    "-O",
                    "exit",
                    "-p",
                    str(session.target.port),
                    session.destination,
                ]
                try:
                    subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=max(self.ssh_timeout, 1.0),
                        env=self._session_env(session.target),
                    )
                except Exception:  # pylint: disable=broad-except
                    pass
            try:
                os.unlink(socket_path)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _open_shell_transport(self, session: _SshSession) -> None:
        cmd, env, destination = self._build_ssh_invocation(
            target=session.target,
            destination=session.destination,
            timeout=self.ssh_timeout,
        )
        cmd.extend(["-T", destination, _SESSION_SHELL_REMOTE])
        proc = subprocess.Popen(  # pylint: disable=consider-using-with
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError("failed to initialize shell transport pipes")
        time.sleep(0.05)
        if proc.poll() is not None:
            out = ""
            try:
                out = truncate_output((proc.stdout.read() or b"").decode("utf-8", errors="replace"), limit=8_000)
            except Exception:  # pylint: disable=broad-except
                out = ""
            raise RuntimeError(f"failed to open shell SSH transport: {out.strip() or 'unknown error'}")
        session.shell_proc = proc
        session.shell_buffer = b""

    def _close_shell_transport(self, session: _SshSession) -> None:
        proc = session.shell_proc
        session.shell_proc = None
        session.shell_buffer = b""
        if not proc:
            return
        try:
            if proc.poll() is None and proc.stdin:
                proc.stdin.write(b"exit\n")
                proc.stdin.flush()
        except Exception:  # pylint: disable=broad-except
            pass
        try:
            proc.wait(timeout=1.0)
        except Exception:  # pylint: disable=broad-except
            try:
                proc.terminate()
            except Exception:  # pylint: disable=broad-except
                pass
            try:
                proc.wait(timeout=1.0)
            except Exception:  # pylint: disable=broad-except
                try:
                    proc.kill()
                except Exception:  # pylint: disable=broad-except
                    pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:  # pylint: disable=broad-except
                pass

    def _close_session_locked(self, session: _SshSession, reason: str) -> None:
        now = time.time()
        session.state = "closing"
        try:
            self._close_transport(session)
        finally:
            session.state = "closed"
            session.closed_at = now
            session.close_reason = reason

    def _open_sessions_locked(self) -> List[_SshSession]:
        return [session for session in self._sessions.values() if session.state == "open"]

    def _gc_locked(self, *, force: bool, reason: str = "gc") -> Dict[str, int]:
        now = time.time()
        stats = {
            "closed_count": 0,
            "expired_count": 0,
            "lru_count": 0,
            "forced_count": 0,
            "remaining_open": 0,
        }

        open_sessions = self._open_sessions_locked()
        if force:
            for session in open_sessions:
                self._close_session_locked(session, _safe_session_reason(reason, "gc force"))
                stats["closed_count"] += 1
                stats["forced_count"] += 1
            stats["remaining_open"] = 0
            return stats

        for session in list(open_sessions):
            idle_expired = (now - session.last_used_at) > session.idle_timeout_s
            life_expired = (now - session.opened_at) > session.max_lifetime_s
            if idle_expired or life_expired:
                close_reason = "idle timeout" if idle_expired else "max lifetime"
                self._close_session_locked(session, close_reason)
                stats["closed_count"] += 1
                stats["expired_count"] += 1

        self._enforce_lru_caps_locked(stats)
        stats["remaining_open"] = len(self._open_sessions_locked())
        return stats

    def _enforce_lru_caps_locked(self, stats: Dict[str, int]) -> None:
        while True:
            open_sessions = self._open_sessions_locked()
            if len(open_sessions) <= self.max_sessions_global:
                break
            victim = min(open_sessions, key=lambda item: (item.last_used_at, item.opened_at, item.session_id))
            self._close_session_locked(victim, "lru global cap")
            stats["closed_count"] += 1
            stats["lru_count"] += 1

        by_target: Dict[str, List[_SshSession]] = {}
        for session in self._open_sessions_locked():
            by_target.setdefault(session.target_id.lower(), []).append(session)
        for sessions in by_target.values():
            while len(sessions) > self.max_sessions_per_target:
                victim = min(sessions, key=lambda item: (item.last_used_at, item.opened_at, item.session_id))
                self._close_session_locked(victim, "lru per-target cap")
                stats["closed_count"] += 1
                stats["lru_count"] += 1
                sessions.remove(victim)

    # --- command execution internals ----------------------------------- #

    def _exec_isolated_once(
        self,
        session: _SshSession,
        *,
        command: str,
        timeout: float,
        env_map: Dict[str, str],
    ) -> Tuple[str, str, int]:
        if not session.socket_path:
            raise _SshSessionTransportError("isolated session has no control socket")

        cmd, env, destination = self._build_ssh_invocation(
            target=session.target,
            destination=session.destination,
            timeout=timeout,
        )
        remote_command = _env_prefixed_command(command, env_map)
        cmd.extend(
            [
                "-o",
                "ControlMaster=no",
                "-o",
                f"ControlPath={session.socket_path}",
                "-T",
                destination,
                remote_command,
            ]
        )

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        if proc.returncode == 255 and _looks_like_transport_drop(stderr):
            raise _SshSessionTransportError(stderr.strip() or "transport closed")
        return stdout, stderr, proc.returncode

    def _exec_shell_once(
        self,
        session: _SshSession,
        *,
        command: str,
        timeout: float,
        cwd: Optional[str],
        env_map: Dict[str, str],
    ) -> Tuple[str, str, int]:
        proc = session.shell_proc
        if not proc or proc.poll() is not None:
            raise _SshSessionTransportError("shell transport is not alive")
        if proc.stdin is None or proc.stdout is None:
            raise _SshSessionTransportError("shell transport pipes are unavailable")

        command_line = _env_prefixed_command(command, env_map)
        marker = f"{_SESSION_MARKER_PREFIX}{uuid.uuid4().hex}:"
        lines: List[str] = []
        if cwd:
            lines.append(f"cd {shlex.quote(cwd)}")
        # Prevent nested commands (notably nested ssh) from consuming the
        # persistent shell stdin and blocking marker-based completion parsing.
        lines.append(f"( {command_line} ) </dev/null")
        lines.append("__onemcp_ec=$?")
        lines.append(f"printf '{marker}%s\\n' \"$__onemcp_ec\"")
        payload = "\n".join(lines) + "\n"
        try:
            proc.stdin.write(payload.encode("utf-8"))
            proc.stdin.flush()
        except Exception as exc:  # pylint: disable=broad-except
            raise _SshSessionTransportError(f"failed to write command to shell transport: {exc}") from exc

        stdout, exit_code = self._read_shell_until_marker(session, marker=marker, timeout=timeout)
        return stdout, "", exit_code

    def _read_shell_until_marker(self, session: _SshSession, *, marker: str, timeout: float) -> Tuple[str, int]:
        proc = session.shell_proc
        if not proc or proc.stdout is None:
            raise _SshSessionTransportError("shell transport stdout unavailable")
        fd = proc.stdout.fileno()
        marker_bytes = marker.encode("utf-8", errors="replace")
        buffer = session.shell_buffer
        deadline = time.monotonic() + timeout

        while True:
            marker_pos = buffer.find(marker_bytes)
            if marker_pos >= 0:
                line_end = buffer.find(b"\n", marker_pos)
                if line_end >= 0:
                    exit_fragment = buffer[marker_pos + len(marker_bytes) : line_end]
                    exit_fragment = exit_fragment.replace(b"\r", b"").strip()
                    try:
                        exit_code = int(exit_fragment.decode("utf-8", errors="replace") or "1")
                    except ValueError:
                        exit_code = 1
                    command_output = buffer[:marker_pos]
                    session.shell_buffer = buffer[line_end + 1 :]
                    return command_output.decode("utf-8", errors="replace"), exit_code

            now = time.monotonic()
            if now >= deadline:
                raise subprocess.TimeoutExpired(cmd="ssh_session_exec(shell)", timeout=timeout)

            if proc.poll() is not None:
                raise _SshSessionTransportError("shell transport exited while awaiting command completion")

            wait_s = min(0.25, max(0.0, deadline - now))
            ready, _, _ = select.select([fd], [], [], wait_s)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 8192)
            except BlockingIOError:
                continue
            if not chunk:
                if proc.poll() is not None:
                    raise _SshSessionTransportError("shell transport closed stdout")
                continue
            buffer += chunk

