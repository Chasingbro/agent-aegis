"""AgentRiskBOM 兼容 schema（按 arXiv 2606.21877 字段组重建）+ 轻量校验。

字段组：agent identity / model & prompt metadata / tool descriptors + risk tiers /
autonomy level / memory & data sources / approval gates / credential scope /
audit signals / inter-agent communication / external BOM refs / governance weaknesses。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

BOM_FORMAT = "AgentRiskBOM"
SPEC_VERSION = "0.1-draft-compat"

REQUIRED_AGENT_FIELDS = [
    "identity", "model", "prompt", "autonomy", "tools", "credential_scope",
    "memory", "approval_gates", "audit_signals", "inter_agent",
    "external_bom_refs", "governance_weaknesses", "risk_assessment",
]


def sha256_short(text: str | None) -> str | None:
    if not text:
        return None
    return hashlib.sha256(text.encode()).hexdigest()[:16]


@dataclass
class ToolEntry:
    ref: str                    # 图节点 id
    server: str
    name: str
    tier: str                   # T1-T5
    tier_reason: str
    hidden: bool = False
    capabilities: dict = field(default_factory=dict)
    evidence: str = ""


@dataclass
class AgentBOM:
    identity: dict
    model: dict
    prompt: dict
    autonomy: dict
    tools: list[ToolEntry]
    credential_scope: dict
    memory: dict
    approval_gates: dict
    audit_signals: dict
    inter_agent: list
    external_bom_refs: dict
    governance_weaknesses: list
    risk_assessment: dict = field(default_factory=dict)

    def validate(self) -> list[str]:
        problems = []
        d = asdict(self)
        for f in REQUIRED_AGENT_FIELDS:
            if f not in d or d[f] in (None,):
                problems.append(f"missing field: {f}")
        if self.autonomy.get("level") not in {"A1", "A2", "A3", "A4"}:
            problems.append(f"bad autonomy level: {self.autonomy.get('level')}")
        for t in self.tools:
            if not str(t.tier).startswith("T") or not 1 <= int(t.tier[1]) <= 5:
                problems.append(f"bad tier: {t.tier} on {t.ref}")
        return problems


def wrap_bom(agents: list[dict]) -> dict:
    return {
        "bom_format": BOM_FORMAT,
        "spec_version": SPEC_VERSION,
        "source": {"tool": "solution/bom", "note": "auto-derived from static collection"},
        "agents": agents,
    }


def dump_bom(bom: dict, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bom, f, ensure_ascii=False, indent=2)


def load_bom(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
