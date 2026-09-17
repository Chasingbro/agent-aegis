"""两套扫描器的稳定 ID、类型和关系映射。"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

PEER_TYPE_MAP = {
    "agent": "AgentApplication",
    "framework": "FrameworkComponent",
    "model": "ModelEndpoint",
    "skill": "Skill",
    "script": "SkillScript",
    "mcp_server": "MCPServer",
    "mcp_tool": "Tool",
    "service": "Service",
    "endpoint": "Endpoint",
    "package": "Package",
    "config": "ConfigItem",
    "credential": "Credential",
    "unknown": "Unknown",
}

PEER_RELATION_MAP = {
    "provides": "exposes",
    "uses": "uses",
    "connects_to": "uses",
    "loads": "mounts",
    "contains": "has_script",
    "serves": "serves",
    "depends_on": "depends_on",
    "configured_by": "configured_by",
    "exposes": "exposes_endpoint",
}


def slug(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    return re.sub(r"[^a-z0-9.-]+", "-", normalized).strip("-") or "unnamed"


def normalize_path(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    return str(PurePosixPath(text)) if text else ""


def canonical_peer_id(asset: dict[str, Any]) -> str:
    atype = asset.get("type", "unknown")
    name = str(asset.get("name") or asset.get("id") or "unnamed")
    attrs = asset.get("attrs") or {}
    if atype == "mcp_server":
        return f"mcp:{slug(name)}"
    if atype == "mcp_tool":
        server = slug(attrs.get("server") or _tool_server(asset.get("id")))
        return f"tool:{server}.{slug(name).replace('-', '_')}"
    if atype == "skill":
        return f"skill:{slug(name)}"
    if atype == "script":
        path = normalize_path(asset.get("path") or name)
        return f"script:{path}" if path else f"script:{slug(name)}"
    if atype == "agent":
        return f"agent:{slug(name)}"
    if atype == "framework":
        return f"component:{slug(name)}"
    if atype == "model":
        return f"model:{slug(name)}"
    if atype == "service":
        return f"service:{slug(name)}"
    return f"{atype}:{slug(name)}"


def solution_identity_key(asset: dict[str, Any]) -> tuple[str, str]:
    """跨引擎合并辅助键；只在明确类型语义下按名称合并。"""
    return asset.get("type", "Unknown"), slug(asset.get("name"))


def peer_identity_key(asset: dict[str, Any]) -> tuple[str, str]:
    return PEER_TYPE_MAP.get(asset.get("type", "unknown"), "Unknown"), slug(asset.get("name"))


def service_alias_target(peer_asset: dict[str, Any], solution_assets: list[dict[str, Any]]) -> str | None:
    """把 compose 服务映射到 solution 中同名的服务角色节点。"""
    if peer_asset.get("type") != "service":
        return None
    want = slug(peer_asset.get("name"))
    matches = [asset["id"] for asset in solution_assets
               if slug(asset.get("name")) == want and asset.get("type") in {
                   "AgentApplication", "FrameworkComponent", "ModelEndpoint",
                   "DataStore", "ExternalEndpoint", "MCPServer",
               }]
    return matches[0] if len(matches) == 1 else None


def config_alias_target(peer_asset: dict[str, Any], solution_assets: list[dict[str, Any]]) -> str | None:
    if peer_asset.get("type") != "config":
        return None
    want_path = normalize_path(peer_asset.get("path"))
    matches = []
    for asset in solution_assets:
        if asset.get("type") != "ConfigItem":
            continue
        entries = (asset.get("declared") or {}).get("entries") or []
        if any(normalize_path(entry.get("file")) == want_path for entry in entries if isinstance(entry, dict)):
            matches.append(asset["id"])
    return matches[0] if len(matches) == 1 else None


def _tool_server(asset_id: Any) -> str:
    text = str(asset_id or "")
    parts = text.split(":")
    return parts[1] if len(parts) >= 3 else "unknown"
