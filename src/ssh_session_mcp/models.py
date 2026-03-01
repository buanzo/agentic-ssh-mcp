"""Datamodels for SSH Session MCP."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class SshTarget:
    """SSH target metadata sourced from the target directory JSON."""

    target_id: str
    host: str
    port: int = 22
    user: str | None = None
    password_env: str | None = None
    description: str = ""
    allow_agent: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SshTarget":
        target_id = str(data.get("id") or data.get("name") or "").strip()
        if not target_id:
            raise ValueError("SSH target missing id")

        host = str(data.get("host") or data.get("hostname") or "").strip()
        if not host:
            raise ValueError(f"SSH target {target_id} missing host")

        try:
            port = int(data.get("port", 22))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid port for SSH target {target_id}") from exc

        if port <= 0 or port > 65535:
            raise ValueError(f"Port out of range for SSH target {target_id}")

        user = str(data.get("user") or "").strip() or None
        password_env = str(data.get("password_env") or "").strip() or None
        description = str(data.get("description") or data.get("comment") or "").strip()
        allow_agent = bool(data.get("allow_agent", True))
        return cls(
            target_id=target_id,
            host=host,
            port=port,
            user=user,
            password_env=password_env,
            description=description,
            allow_agent=allow_agent,
        )
