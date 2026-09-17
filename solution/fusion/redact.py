"""面向 Web、报告和下载工件的统一敏感数据脱敏。"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

SENSITIVE_KEY = re.compile(
    r"(?:secret|password|passwd|token|api[_-]?key|signing[_-]?key|webhook|dsn|database[_-]?url)",
    re.IGNORECASE,
)
IDENTITY_KEYS = {"id", "name", "key", "target", "rule", "title", "file", "path"}
VALUE_KEYS = {"value", "raw", "default", "literal", "content", "connection_string"}
ASSIGNMENT = re.compile(
    r"\b([A-Z][A-Z0-9_]{2,})\s*([:=])\s*([^\s,;\"'<>]+)"
)
URL_CREDENTIAL = re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)")
BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*")
MASKED = re.compile(r"^\*+$|\*{2,}")


def redact_document(value: Any, *contexts: Any) -> Any:
    """递归复制并脱敏；可传额外上下文发现跨工件重复出现的秘密。"""
    document = deepcopy(value)
    secrets: set[str] = set()
    _collect(document, secrets)
    for context in contexts:
        _collect(context, secrets)
    return _redact(document, secrets)


def redact_text(value: str, secrets: set[str] | None = None) -> str:
    text = ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]"
        if match.group(2) == "=" and SENSITIVE_KEY.search(match.group(1)) else match.group(0),
        value,
    )
    text = URL_CREDENTIAL.sub(r"\1[REDACTED]\3", text)
    text = BEARER.sub(r"\1[REDACTED]", text)
    for secret in sorted(secrets or (), key=len, reverse=True):
        if _wordlike(secret):
            pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(secret)}(?![A-Za-z0-9_-])")
            text = pattern.sub("[REDACTED]", text)
        else:
            text = text.replace(secret, "[REDACTED]")
    return text


def _collect(value: Any, secrets: set[str], sensitive_context: bool = False,
             key: str = "") -> None:
    if isinstance(value, dict):
        identity_sensitive = any(
            isinstance(value.get(identity), str) and SENSITIVE_KEY.search(value[identity])
            for identity in IDENTITY_KEYS
        )
        context = sensitive_context or identity_sensitive
        for item_key, item_value in value.items():
            key_sensitive = item_key not in IDENTITY_KEYS and _is_sensitive_field(str(item_key))
            collect_value = key_sensitive or (context and str(item_key).lower() in VALUE_KEYS)
            if collect_value and isinstance(item_value, str):
                _add_secret(item_value, secrets)
            _collect(item_value, secrets, context or key_sensitive, str(item_key))
        return
    if isinstance(value, list):
        for item in value:
            _collect(item, secrets, sensitive_context, key)
        return
    if isinstance(value, str):
        for match in ASSIGNMENT.finditer(value):
            if match.group(2) == "=" and SENSITIVE_KEY.search(match.group(1)):
                _add_secret(match.group(3), secrets)


def _redact(value: Any, secrets: set[str], sensitive_context: bool = False,
            key: str = "") -> Any:
    if isinstance(value, dict):
        identity_sensitive = any(
            isinstance(value.get(identity), str) and SENSITIVE_KEY.search(value[identity])
            for identity in IDENTITY_KEYS
        )
        context = sensitive_context or identity_sensitive
        return {
            item_key: _redact(
                item_value,
                secrets,
                context or (item_key not in IDENTITY_KEYS and _is_sensitive_field(str(item_key))),
                str(item_key),
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, secrets, sensitive_context, key) for item in value]
    if isinstance(value, str):
        if key not in IDENTITY_KEYS and (
            _is_sensitive_field(key) or (sensitive_context and key.lower() in VALUE_KEYS)
        ):
            return "[REDACTED]" if value else value
        return redact_text(value, secrets)
    return value


def _is_sensitive_field(key: str) -> bool:
    return not any(separator in key for separator in (":", "/", "\\")) and bool(SENSITIVE_KEY.search(key))


def _add_secret(value: str, secrets: set[str]) -> None:
    candidate = value.strip().strip("'\"")
    if len(candidate) < 4 or candidate == "[REDACTED]" or MASKED.search(candidate):
        return
    if candidate.lower() in {"true", "false", "none", "null", "password", "secret", "token"}:
        return
    secrets.add(candidate)


def _wordlike(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value))
