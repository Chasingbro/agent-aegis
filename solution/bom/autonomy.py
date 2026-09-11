"""自主等级推断：A1-A4（对齐 AgentRiskBOM 的 autonomy scale）。

A1 单轮建议  A2 固定管线/逐步审批  A3 有界自主循环（无人工审批）
A4 无界/持久调度
"""

from __future__ import annotations


def infer_autonomy(agent_decl: dict, approval_gates: int) -> tuple[str, dict, list[str]]:
    evidence = []
    max_steps = agent_decl.get("max_steps")
    is_flow = bool(agent_decl.get("nodes"))  # 编排 flow：节点序列固定
    if max_steps:
        evidence.append(f"Agent 循环上限 max_steps={max_steps}（环境变量默认）")
    if approval_gates == 0:
        evidence.append("未声明任何人工审批门（approval_gates=0）")

    if max_steps and int(max_steps) > 1 and approval_gates == 0:
        level = "A3"   # 有界自主循环
    elif is_flow and approval_gates == 0:
        level = "A2"   # 固定管线自动执行
    elif approval_gates > 0:
        level = "A2"
    else:
        level = "A1"

    signals = {"max_steps": max_steps, "approval_gates": approval_gates,
               "bounded": bool(max_steps), "flow": is_flow}
    return level, signals, evidence
