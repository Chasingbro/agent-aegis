"""BOM 差分推理：① 版本间 authority drift（复刻论文 diff detector）
② declared vs observed 接口（运行时监控的策略基线入口，本期仅留接口）。

变异测试：对 BOM 施加结构化变异，断言 diff 正确分类——
论文 33 变异实验的缩小版（10 个）。
"""

from __future__ import annotations

import copy
import json

# 变异 -> 期望分类
MUTATIONS = {
    "add_tool_t4":       "tool_added",
    "add_hidden_tool":   "tool_added+hidden",
    "remove_tool":       "tool_removed",
    "escalate_t1_to_t4": "tier_escalation",
    "escalate_t4_to_t5": "tier_escalation",
    "autonomy_a3_to_a4": "autonomy_change",
    "remove_approval":   "approval_gate_removed",
    "broaden_credential": "credential_broadened",
    "weaken_audit":      "audit_weakened",
    "extend_memory":     "memory_extended",
}


def _agent(bom: dict) -> dict:
    return bom["agents"][0]


def apply_mutation(bom: dict, name: str) -> tuple[dict, dict]:
    """返回 (baseline, current)：部分变异需要在基线上先构造前置状态。"""
    baseline = copy.deepcopy(bom)
    current = copy.deepcopy(bom)
    agent = current["agents"][0]
    base_agent = baseline["agents"][0]
    tools = agent["tools"]
    if name == "add_tool_t4":
        tools.append({"ref": "tool:new.exec_cmd", "server": "new", "name": "exec_cmd",
                      "tier": "T4", "tier_reason": "mutation", "hidden": False,
                      "capabilities": {"subprocess": True}, "evidence": "mutation"})
    elif name == "add_hidden_tool":
        tools.append({"ref": "tool:new.backdoor", "server": "new", "name": "backdoor",
                      "tier": "T5", "tier_reason": "mutation", "hidden": True,
                      "capabilities": {"subprocess": True}, "evidence": "mutation"})
    elif name == "remove_tool":
        tools[:] = [t for t in tools if t["name"] != "query"]
    elif name == "escalate_t1_to_t4":
        for t in tools:
            if t["name"] == "query":
                t["tier"] = "T4"
    elif name == "escalate_t4_to_t5":
        for t in tools:
            if t["name"] == "run":
                t["tier"], t["hidden"] = "T5", True
    elif name == "autonomy_a3_to_a4":
        agent["autonomy"]["level"] = "A4"
    elif name == "remove_approval":
        base_agent["approval_gates"].update({"count": 1, "policy": "per-action"})
    elif name == "broaden_credential":
        agent["credential_scope"]["service_account"] = {
            "token": "svc-mutated", "scope": "*:*:*"}
    elif name == "weaken_audit":
        base_agent["audit_signals"]["tamper_resistant"] = True
    elif name == "extend_memory":
        agent["memory"]["persistence"] = "durable"
        agent["memory"]["rag_sources"] = ["mcp:knowledge", "db:postgres-customer"]
    else:
        raise ValueError(f"unknown mutation: {name}")
    return baseline, current


def bom_diff(baseline: dict, current: dict) -> list[dict]:
    """结构化差分：返回分类后的变更列表。"""
    changes: list[dict] = []
    for a_old, a_new in zip(baseline["agents"], current["agents"]):
        aid = a_old["identity"]["id"]

        old_tools = {t["ref"]: t for t in a_old["tools"]}
        new_tools = {t["ref"]: t for t in a_new["tools"]}
        for ref, t in new_tools.items():
            if ref not in old_tools:
                kind = "tool_added+hidden" if t.get("hidden") else "tool_added"
                changes.append({"agent": aid, "kind": kind, "ref": ref,
                                "detail": f"新增工具 {t['name']} tier={t['tier']}"})
            else:
                o = old_tools[ref]
                if o["tier"] != t["tier"]:
                    up = int(t["tier"][1]) > int(o["tier"][1])
                    changes.append({"agent": aid, "kind": "tier_escalation" if up else "tier_downgrade",
                                    "ref": ref,
                                    "detail": f"{t['name']} {o['tier']} -> {t['tier']}"})
                if o.get("hidden") != t.get("hidden") and t.get("hidden"):
                    changes[-1]["detail"] += " 且转为隐藏" if changes else ""
        for ref, t in old_tools.items():
            if ref not in new_tools:
                changes.append({"agent": aid, "kind": "tool_removed", "ref": ref,
                                "detail": f"移除工具 {t['name']}"})

        if a_old["autonomy"]["level"] != a_new["autonomy"]["level"]:
            changes.append({"agent": aid, "kind": "autonomy_change",
                            "detail": f"autonomy {a_old['autonomy']['level']} -> "
                                      f"{a_new['autonomy']['level']}"})
        if a_old["approval_gates"]["count"] > a_new["approval_gates"]["count"]:
            changes.append({"agent": aid, "kind": "approval_gate_removed",
                            "detail": f"approval_gates {a_old['approval_gates']['count']} -> "
                                      f"{a_new['approval_gates']['count']}"})
        old_sa = json.dumps(a_old["credential_scope"].get("service_account"), sort_keys=True)
        new_sa = json.dumps(a_new["credential_scope"].get("service_account"), sort_keys=True)
        if old_sa != new_sa:
            changes.append({"agent": aid, "kind": "credential_broadened",
                            "detail": f"service_account {old_sa} -> {new_sa}"})
        if a_old["audit_signals"].get("tamper_resistant") and \
                not a_new["audit_signals"].get("tamper_resistant"):
            changes.append({"agent": aid, "kind": "audit_weakened",
                            "detail": "防篡改审计从有到无"})
        if a_old["memory"].get("persistence") != a_new["memory"].get("persistence") or \
                len(a_old["memory"].get("rag_sources", [])) < len(a_new["memory"].get("rag_sources", [])):
            changes.append({"agent": aid, "kind": "memory_extended",
                            "detail": f"memory {a_old['memory'].get('persistence')} -> "
                                      f"{a_new['memory'].get('persistence')}, rag "
                                      f"{a_new['memory'].get('rag_sources')}"})
    return changes


def declared_vs_observed(declared_bom: dict, runtime: dict) -> list[dict]:
    """声明包络 vs 运行时观测的差分（第二阶段检测的策略基线入口）。

    三类异常：
    ① tool_envelope：BOM 声明的隐藏工具在运行时 tools_list 缺席（隐藏确认）；
       或运行时广播了声明面之外的工具（未声明调用）；
    ② egress：c2-sink receipts 中出现声明业务出网之外的来源（隐蔽外传观测）；
    ③ auth：伪造 token 被接受（认证边界被绕过，弱密钥可伪造实证）。
    """
    anomalies: list[dict] = []
    mcp_rt = runtime.get("mcp_tools") or {}

    # ① 工具包络差分
    advertised: set[str] = set()
    for entry in mcp_rt.values():
        for t in entry.get("tools", []):
            advertised.add(t["name"])
    for agent in declared_bom.get("agents", []):
        for tool in agent.get("tools", []):
            name = tool["name"]
            if tool.get("hidden") and name not in advertised:
                anomalies.append({"kind": "hidden_tool_confirmed",
                                  "ref": tool["ref"], "agent": agent["identity"]["id"],
                                  "detail": f"{name} 声明隐藏且运行时不广播"})
    for name in sorted(advertised):
        known = {t["name"] for a in declared_bom.get("agents", [])
                 for t in a.get("tools", [])}
        if name not in known:
            anomalies.append({"kind": "undeclared_tool_call", "ref": name,
                              "detail": "运行时广播了 BOM 未声明的工具"})

    # ② 外传观测差分：声明业务出网 = threat-intel 检索；其余来源到 c2-sink 即隐蔽
    receipts = (runtime.get("http_fingerprint") or {}).get("c2_receipts") or {}
    for src, count in (receipts.get("by_src") or {}).items():
        if src not in ("threat-intel", "mock-internet", "opspilot-app"):
            anomalies.append({"kind": "covert_egress_observed", "src": src,
                              "count": count,
                              "leaked_keys": receipts.get("sensitive_keys_exfiltrated"),
                              "detail": f"{src} 向 c2-sink 投递 {count} 条"})

    # ③ 认证边界差分
    forge = (runtime.get("identity") or {}).get("forge") or {}
    if forge.get("accepted") and forge.get("control_wrong_secret_rejected"):
        anomalies.append({"kind": "auth_boundary_bypass",
                          "claims": forge.get("claims_forged"),
                          "detail": "伪造身份 token 被接受（弱密钥实证）"})
    return anomalies


def run_mutation_tests(bom: dict) -> list[tuple[str, bool, str]]:
    """返回 (mutation, pass, message) 列表。"""
    results = []
    for name, expected in MUTATIONS.items():
        baseline, current = apply_mutation(bom, name)
        changes = bom_diff(baseline, current)
        kinds = {c["kind"] for c in changes}
        ok = expected in kinds or expected.split("+")[0] in kinds
        results.append((name, ok, f"got={sorted(kinds)} expect={expected}"))
    return results


if __name__ == "__main__":
    import sys
    from pathlib import Path
    from bom.schema import load_bom
    bom_path = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parent.parent / "out" / "bom.json"
    results = run_mutation_tests(load_bom(bom_path))
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, msg in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<22} {msg}")
    print(f"变异差分测试: {passed}/{len(results)}")
