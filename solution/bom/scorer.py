"""风险评分：AgentRiskBOM 论文式 6 输入规则分（0-100）+ 象限判定。

驱动因素：autonomy / max tool tier / data sensitivity / external exposure /
memory persistence / governance weakness。分数是规则加权和，输出可解释明细。
"""

from __future__ import annotations

from bom.tiers import tier_rank

AUTONOMY_W = {"A1": 0, "A2": 15, "A3": 25, "A4": 30}
TIER_W = {"T1": 0, "T2": 8, "T3": 12, "T4": 20, "T5": 30}
WEAKNESS_KIND_W = {
    "high_tier_without_approval": 6,
    "hidden_tool_mounted": 6,
    "permissive_tenant_semantics": 4,
    "weak_or_sensitive_config": 3,
    "collected_findings": 2,
}


def score_agent(agent_bom: dict) -> dict:
    tools = agent_bom.get("tools") or []
    max_tier = max((tier_rank(t["tier"]) for t in tools), default=1)

    # 1) autonomy
    autonomy = agent_bom["autonomy"]["level"]
    d_autonomy = AUTONOMY_W[autonomy]
    # 2) max tier
    d_tier = TIER_W[f"T{max_tier}"]
    # 3) data sensitivity：多租户客户库 / 敏感 env 引用
    data_refs = (agent_bom["memory"].get("sensitive_data_refs") or [])
    injection_surfaces = agent_bom["prompt"].get("injection_surfaces") or {}
    surfaces = len(injection_surfaces.get("skills_loaded_each_turn") or []) + \
        len(injection_surfaces.get("external_content_tools") or [])
    d_data = 15 if any("postgres" in str(r) for r in data_refs) else (8 if data_refs else 3)
    if surfaces:
        d_data = min(15, d_data + 3)  # 注入面放大敏感数据可达性
    # 4) external exposure：隐藏/外联工具与 T5
    has_t5 = any(t["tier"] == "T5" for t in tools)
    net_tools = [t for t in tools if (t.get("capabilities") or {}).get("net_out")]
    d_exposure = 15 if has_t5 else (10 if net_tools else 3)
    # 5) memory persistence
    d_memory = {"none-declared": 3, "session": 5, "durable": 10}.get(
        agent_bom["memory"].get("persistence", "none-declared"), 5)
    if agent_bom["memory"].get("rag_sources"):
        d_memory = min(12, d_memory + 3)
    # 6) governance weakness（按类型加权，cap 20）
    d_gov = min(20, sum(WEAKNESS_KIND_W.get(w["kind"], 2)
                        for w in agent_bom.get("governance_weaknesses") or []))

    drivers = {"autonomy": d_autonomy, "max_tool_tier": d_tier,
               "data_sensitivity": d_data, "external_exposure": d_exposure,
               "memory_persistence": d_memory, "governance_weakness": d_gov}
    total = sum(drivers.values())
    score = min(100, round(total / 102 * 100))  # 102 = 权重和上限

    quadrant = _quadrant(autonomy, max_tier)
    return {"score": score, "quadrant": quadrant, "drivers": drivers,
            "max_tool_tier": f"T{max_tier}", "driver_max": 102}


def _quadrant(autonomy: str, max_tier: int) -> str:
    a_high = autonomy in ("A3", "A4")
    t_high = max_tier >= 4
    if a_high and t_high:
        return "high"
    if a_high or t_high:
        return "elevated"
    if autonomy == "A2" or max_tier == 3:
        return "moderate"
    return "low"


def score_bom(bom: dict) -> dict:
    for agent in bom["agents"]:
        agent["risk_assessment"] = score_agent(agent)
    return bom
