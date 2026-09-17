"""融合图谱的内部数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CanonicalAsset:
    id: str
    type: str
    name: str
    path: str = ""
    confidence: float = 1.0
    declared: dict[str, Any] = field(default_factory=dict)
    observed: dict[str, Any] = field(default_factory=dict)
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    provenance: list[Any] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    native: dict[str, Any] = field(default_factory=dict)


@dataclass
class CanonicalEdge:
    id: str
    source: str
    target: str
    relation: str
    declared: bool = True
    observed: bool | None = None
    attrs: dict[str, Any] = field(default_factory=dict)
    provenance: list[Any] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class CanonicalRisk:
    id: str
    asset_id: str
    category: str
    severity: str
    title: str
    description: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    related_asset_ids: list[str] = field(default_factory=list)
    malicious_type: str | None = None
    confidence: float = 1.0
    source: str = "solution"
    source_kind: str = "static"
    rule: str = ""
    target: str = ""
    tag: str = ""
    native_ids: list[str] = field(default_factory=list)


@dataclass
class NormalizedResult:
    assets: list[CanonicalAsset] = field(default_factory=list)
    edges: list[CanonicalEdge] = field(default_factory=list)
    risks: list[CanonicalRisk] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    quality: dict[str, Any] = field(default_factory=dict)
