"""Shared BloodHound API and session-file helpers."""

import json
import os
import stat
import tempfile
from typing import Any

SESSION_PATH = os.path.join(tempfile.gettempdir(), "patchhound.session.json")
REDACTION_MASK = "████████"


def normalize_base_url(url: str) -> str:
    normalized = (url or "").strip()
    if not normalized:
        raise ValueError("BloodHound URL cannot be empty")
    return normalized if normalized.endswith("/") else f"{normalized}/"


def pretty_json(value: Any) -> str:
    """Return stable, human-readable JSON for verbose diagnostics."""
    return json.dumps(value, indent=2, ensure_ascii=False)


def extract_error_message(response) -> str:
    """Extract a useful API error without dumping an unbounded response."""
    try:
        body = response.json()
    except (TypeError, ValueError):
        body = None

    if isinstance(body, dict):
        errors = body.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                message = first.get("message")
            else:
                message = first
            if isinstance(message, str) and message.strip():
                return message.strip()

        for key in ("message", "error", "detail"):
            message = body.get(key)
            if isinstance(message, str) and message.strip():
                return message.strip()

    text = str(getattr(response, "text", "") or "").strip()
    if text:
        return text[:500]
    status = getattr(response, "status_code", None)
    return f"HTTP {status}" if status is not None else "Unknown API error"


def redact_token(token: str) -> str:
    return REDACTION_MASK if token else "<missing>"


def redact_secret(_secret: str) -> str:
    return REDACTION_MASK


def save_session(base_url: str, token: str, path: str = SESSION_PATH) -> None:
    payload = {"base_url": normalize_base_url(base_url), "session_token": token}
    directory = os.path.dirname(path) or "."
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=directory, delete=False
        ) as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
            temporary_path = handle.name
        os.replace(temporary_path, path)
        temporary_path = None
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def load_session(path: str = SESSION_PATH) -> tuple[str, str]:
    if not os.path.exists(path):
        raise RuntimeError("No session found — run `auth` first.")
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("Session file is invalid — re-run `auth`.") from exc

    if not isinstance(data, dict):
        raise RuntimeError("Session file is invalid — re-run `auth`.")

    base_url = data.get("base_url")
    token = data.get("session_token")
    if not isinstance(base_url, str) or not isinstance(token, str) or not token:
        raise RuntimeError("Session file missing base_url or session_token — re-run `auth`.")
    return normalize_base_url(base_url), token
