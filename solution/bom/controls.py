"""控制映射：风险驱动/weakness kind -> 控制族建议（对齐论文 control mapper）。"""

from __future__ import annotations

CONTROL_FAMILIES = {
    "least-privilege": "最小权限：按身份 scope 收窄工具与数据访问",
    "tool-allowlist": "工具白名单：仅允许清单内工具可被调用",
    "human-approval": "人工审批门：高风险动作执行前需确认",
    "emergency-stop": "紧急停止：会话级 kill-switch",
    "tamper-evident-logging": "防篡改审计日志：完整攻击链可回放",
    "egress-allowlist": "出网白名单：目标级 egress 管控",
    "credential-hygiene": "凭据治理：密钥轮换、强随机、独立下发",
    "identity-propagation": "身份传播：下游可追溯真实用户（端到端身份）",
    "supply-chain-verification": "供应链验证：组件来源与完整性核验",
    "memory-scoping": "记忆隔离：按租户/会话隔离记忆与 RAG",
    "sandboxing": "沙箱执行：命令执行落在受限环境",
}

WEAKNESS_TO_CONTROLS = {
    "high_tier_without_approval": ["human-approval", "emergency-stop", "sandboxing"],
    "hidden_tool_mounted": ["tool-allowlist", "supply-chain-verification",
                            "tamper-evident-logging"],
    "permissive_tenant_semantics": ["least-privilege", "memory-scoping"],
    "weak_or_sensitive_config": ["credential-hygiene"],
    "collected_findings": ["tamper-evident-logging"],
    "confused_deputy": ["identity-propagation", "least-privilege"],
    "covert_egress": ["egress-allowlist"],
    "no_approval_gates": ["human-approval", "emergency-stop"],
    "weak_credential": ["credential-hygiene"],
    "missing_identity_propagation": ["identity-propagation"],
}

# 评分驱动 -> 控制族（驱动高分时触发）
DRIVER_TO_CONTROLS = {
    "autonomy": ["human-approval", "emergency-stop"],
    "max_tool_tier": ["least-privilege", "sandboxing", "tool-allowlist"],
    "data_sensitivity": ["memory-scoping", "least-privilege"],
    "external_exposure": ["egress-allowlist"],
    "memory_persistence": ["memory-scoping"],
    "governance_weakness": ["tamper-evident-logging"],
}


def map_controls(agent_bom: dict) -> list[dict]:
    """返回去重控制建议列表，每条含触发原因。"""
    triggered: dict[str, list[str]] = {}
    for w in agent_bom.get("governance_weaknesses") or []:
        for fam in WEAKNESS_TO_CONTROLS.get(w["kind"], []):
            triggered.setdefault(fam, []).append(f"weakness:{w['kind']}")
    assessment = agent_bom.get("risk_assessment") or {}
    drivers = assessment.get("drivers") or {}
    thresholds = {"autonomy": 15, "max_tool_tier": 8, "data_sensitivity": 8,
                  "external_exposure": 10, "memory_persistence": 5,
                  "governance_weakness": 6}
    for driver, value in drivers.items():
        if value >= thresholds.get(driver, 999):
            for fam in DRIVER_TO_CONTROLS.get(driver, []):
                triggered.setdefault(fam, []).append(f"driver:{driver}={value}")
    return [{"family": fam, "description": CONTROL_FAMILIES[fam],
             "triggered_by": reasons[:3]}
            for fam, reasons in sorted(triggered.items())]


def annotate_controls(bom: dict) -> dict:
    for agent in bom["agents"]:
        agent["risk_assessment"]["controls"] = map_controls(agent)
    return bom
