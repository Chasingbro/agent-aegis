"""严格读取 runner 产生的 last-good agent-scanner 工件。"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .peer_runner import (
    DEFAULT_PEER_ROOT,
    PeerScanError,
    current_peer_output,
    current_peer_pointer,
    read_peer_status,
    validate_artifacts,
)

PEER_FILES = ("assets.json", "graph.json", "risks.json", "summary.json", "bench.json")


@dataclass
class PeerLoadResult:
    status: str
    payload: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    error: str | None = None
    artifact_dir: str | None = None
    scan_status: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def configured_peer_out() -> tuple[Path | None, str]:
    explicit = os.environ.get("AGENT_SCANNER_OUT", "").strip()
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        return (candidate if candidate.is_dir() else None,
                "configured" if candidate.is_dir() else "configured_missing")
    current = current_peer_output(DEFAULT_PEER_ROOT)
    return current, "current" if current else "not_run"


def load_peer_result(out_dir: str | Path | None = None) -> PeerLoadResult:
    scan_status = read_peer_status(DEFAULT_PEER_ROOT)
    if out_dir is not None:
        root = Path(out_dir).expanduser().resolve()
        origin = "explicit"
    else:
        root, origin = configured_peer_out()
    if root is None:
        status = "not_configured" if origin == "configured_missing" else "not_run"
        return PeerLoadResult(status=status, reason=origin, scan_status=scan_status)
    if not root.is_dir():
        return PeerLoadResult(status="invalid", reason="artifact_dir_missing",
                              error=f"peer 工件目录不存在：{root}", scan_status=scan_status)

    documents = {}
    errors = []
    for name in PEER_FILES:
        try:
            value = json.loads((root / name).read_text(encoding="utf-8"))
        except FileNotFoundError:
            errors.append(f"缺少 {name}")
            continue
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{name} 无法解析：{exc}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{name} 顶层不是对象")
            continue
        documents[name] = value
    if errors:
        return PeerLoadResult(status="invalid", reason="invalid_artifacts",
                              error="；".join(errors), artifact_dir=str(root),
                              scan_status=scan_status)

    summary = documents["summary.json"].get("summary") or {}
    expected_target = summary.get("target", "")
    if out_dir is None and origin == "current":
        expected_target = current_peer_pointer(DEFAULT_PEER_ROOT).get("target", expected_target)
    try:
        validate_artifacts(root, Path(expected_target))
    except PeerScanError as exc:
        return PeerLoadResult(status="invalid", reason=exc.reason, error=str(exc),
                              artifact_dir=str(root), scan_status=scan_status)

    graph = documents["graph.json"]
    payload = {
        "meta": {
            "target": summary.get("target", ""),
            "started_at": summary.get("started_at", ""),
            "duration_ms": summary.get("duration_ms", 0),
            "file_count": summary.get("file_count", 0),
            "tool_version": summary.get("tool_version", ""),
            "artifact_dir": str(root),
        },
        "assets": documents["assets.json"].get("assets", []),
        "nodes": graph.get("nodes", []),
        "edges": graph.get("edges", []),
        "risks": documents["risks.json"].get("risks", []),
        "summary": summary,
        "bench": documents["bench.json"].get("bench") or {},
    }
    return PeerLoadResult(status="ready", payload=payload, artifact_dir=str(root),
                          scan_status=scan_status)


def load_peer_payload(out_dir: str | Path | None = None) -> dict[str, Any]:
    """兼容入口：始终附带 peer_scan 和 peer_load 状态。"""
    result = load_peer_result(out_dir)
    return {**result.payload, "peer_scan": result.scan_status,
            "peer_load": {key: value for key, value in result.to_dict().items()
                          if key not in {"payload", "scan_status"}}}
