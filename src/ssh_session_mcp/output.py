"""Output truncation helpers for SSH Session MCP."""


def truncate_output(text: str, limit: int) -> str:
    """Trim output to a byte limit while keeping it decodable."""

    data = text.encode("utf-8", errors="replace")
    if len(data) <= limit:
        return text
    truncated = data[:limit]
    suffix = f"\n...[truncated {len(data) - limit} bytes]"
    return truncated.decode("utf-8", errors="replace") + suffix
