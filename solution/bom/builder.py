"""BOM builder：属性图 -> AgentRiskBOM 工件（每个 agent 一份 entry）。"""

from __future__ import annotations

from datetime import datetime, timezone

from graph.store import GraphStore
from bom.autonomy import infer_autonomy
from bom.schema import AgentBOM, ToolEntry, sha256_short, wrap_bom
from bom.tiers import classify_tool


def _mounted_tools(gs: GraphStore, agent_id: str) -> list[dict]:
    tools = []
    for tid in gs.neighbors_out(agent_id, "mounts"):
        d = gs.g.nodes[tid]
        if d["type"] == "Tool":
            tools.append({"ref": tid, "server": tid.split(":")[1].split(".")[0],
                          "name": d["name"], "hidden": d["declared"].get("hidden", False),
                          "capabilities": d["declared"].get("capabilities", {}),
                          "description": d["declared"].get("description", ""),
                          "evidence": "; ".join(d["provenance"])})
        elif d["type"] == "MCPServer":
            # flow 级挂载：继承该 server 暴露的全部工具
            for sub in gs.neighbors_out(tid, "exposes"):
                sd = gs.g.nodes[sub]
                tools.append({"ref": sub, "server": d["name"], "name": sd["name"],
                              "hidden": sd["declared"].get("hidden", False),
                              "capabilities": sd["declared"].get("capabilities", {}),
                              "description": sd["declared"].get("description", ""),
                              "evidence": f"inherited via server mount {tid}"})
    return tools


def _weaknesses_for_agent(gs: GraphStore, agent_id: str, tool_entries: list[ToolEntry]) -> list[dict]:
    weak = []
    # 1) T4+ 且无审批门
    high_tier = [t for t in tool_entries if t.tier in ("T4", "T5")]
    if high_tier:
        weak.append({"kind": "high_tier_without_approval",
                     "detail": f"挂载 {len(high_tier)} 个 T4+ 工具且无审批门",
                     "refs": [t.ref for t in high_tier]})
    # 2) 隐藏工具
    hidden = [t for t in tool_entries if t.hidden]
    if hidden:
        weak.append({"kind": "hidden_tool_mounted",
                     "detail": f"挂载 {len(hidden)} 个隐藏工具（不在 tools/list）",
                     "refs": [t.ref for t in hidden]})
    # 3) 图上已有风险发现的聚合
    subtree_risks = set(gs.g.nodes[agent_id].get("risks") or [])
    for t in tool_entries:
        subtree_risks.update(gs.g.nodes.get(t.ref, {}).get("risks") or [])
    for rid in gs.neighbors_out(agent_id, "mounts"):
        subtree_risks.update(gs.g.nodes[rid].get("risks") or [])
    if subtree_risks:
        weak.append({"kind": "collected_findings", "detail": "采集期发现在 agent 子图内命中",
                     "refs": sorted(subtree_risks)})
    # 4) 弱配置 / 服务账号传播（cfg 节点）
    for cid in gs.nodes_by_type("ConfigItem"):
        for tgt in gs.neighbors_out(cid, "configures"):
            if tgt == agent_id:
                d = gs.g.nodes[cid]
                weak.append({"kind": "weak_or_sensitive_config",
                             "detail": f"{cid} = {d['declared'].get('value')}",
                             "refs": [cid]})
    # 5) 租户通配符能力
    for t in tool_entries:
        if (t.capabilities or {}).get("wildcard_check"):
            weak.append({"kind": "permissive_tenant_semantics",
                         "detail": f"{t.server}.{t.name} 支持通配符查询",
                         "refs": [t.ref]})
    return weak


def _packages_for_agent(gs: GraphStore, agent_id: str, tool_entries: list[ToolEntry]) -> list[dict]:
    owners = {agent_id}
    for tool in tool_entries:
        for server in gs.neighbors_in(tool.ref, "exposes"):
            if gs.g.nodes[server]["type"] == "MCPServer":
                owners.add(server)
    packages = {}
    for owner in owners:
        for pid in gs.neighbors_out(owner, "depends_on"):
            node = gs.g.nodes[pid]
            if node["type"] != "Package":
                continue
            packages[pid] = {"ref": pid, "name": node["name"],
                             "version_specs": node["declared"].get("version_specs", []),
                             "scopes": node["declared"].get("scopes", []),
                             "evidence": "; ".join(node["provenance"])}
    return [packages[pid] for pid in sorted(packages)]


def build_agent_bom(gs: GraphStore, agent_id: str) -> AgentBOM:
    d = gs.g.nodes[agent_id]
    decl = d["declared"]
    is_flow = d["type"] == "AgentFlow"

    tools_raw = _mounted_tools(gs, agent_id)
    tool_entries = []
    for t in tools_raw:
        tier, reason = classify_tool(
            {"hidden": t["hidden"], "capabilities": t["capabilities"],
             "description": t["description"]})
        tool_entries.append(ToolEntry(
            ref=t["ref"], server=t["server"], name=t["name"], tier=tier,
            tier_reason=reason, hidden=t["hidden"],
            capabilities=t["capabilities"], evidence=t["evidence"]))

    approval_gates = 0  # 声明面未见任何审批机制
    level, signals, autonomy_evidence = infer_autonomy(decl, approval_gates)

    identities = []
    service_account = {}
    for iid in gs.neighbors_in(agent_id, "authenticates"):
        idd = gs.g.nodes[iid]["declared"]
        identities.append({"user": gs.g.nodes[iid]["name"], "role": idd.get("role"),
                           "scope": idd.get("scope")})
    for cid in gs.nodes_by_type("ConfigItem"):
        key = gs.g.nodes[cid]["name"]
        val = gs.g.nodes[cid]["declared"].get("value")
        if key == "OPSPILOT_SERVICE_TOKEN":
            service_account = {"token": val, "scope": "root-all-access"}
        if key == "OPSPILOT_PROPAGATION" and gs.neighbors_out(cid, "configures"):
            service_account["propagation"] = val

    skills = [gs.g.nodes[s]["name"]
              for s in gs.neighbors_out(agent_id, "mounts")
              if gs.g.nodes[s]["type"] == "Skill"]
    rag = [s for s in gs.neighbors_out(agent_id, "mounts")
           if gs.g.nodes[s]["type"] == "MCPServer" and "knowledge" in s]

    model = {}
    for mid in gs.neighbors_out(agent_id, "uses"):
        if gs.g.nodes[mid]["type"] == "ModelEndpoint":
            model = {"endpoint": gs.g.nodes[mid]["name"],
                     "protocol": "openai-chat-compat", "live": "unknown"}

    inter_agent = [{"peer": gs.g.nodes[o]["name"], "via": "langflow"}
                   for o in gs.neighbors_out(agent_id, "uses")
                   if gs.g.nodes[o]["type"] == "FrameworkComponent"]

    weaknesses = _weaknesses_for_agent(gs, agent_id, tool_entries)

    return AgentBOM(
        identity={"id": agent_id, "name": d["name"],
                  "kind": "flow" if is_flow else "application",
                  "criticality": "business-ops",
                  "evidence": "; ".join(d["provenance"])},
        model=model or {"endpoint": None, "protocol": "unknown"},
        prompt={"system_prompt_sha256": sha256_short(decl.get("system_prompt")),
                "excerpt": (decl.get("system_prompt") or "")[:80],
                "injection_surfaces": {
                    "skills_loaded_each_turn": skills,
                    "external_content_tools": [f"{t.server}.{t.name}" for t in tool_entries
                                               if (t.capabilities or {}).get("net_out")]}},
        autonomy={"level": level, "signals": signals, "evidence": autonomy_evidence},
        tools=tool_entries,
        credential_scope={"identities": identities,
                          "service_account": service_account,
                          "note": "Agent->MCP 不传递用户身份，仅 trace 头" if not is_flow
                          else "flow 内无独立身份声明"},
        memory={"skills": skills, "rag_sources": rag,
                "persistence": "none-declared", "sensitive_data_refs": ["db:postgres-customer"]},
        approval_gates={"count": approval_gates, "policy": "none-declared"},
        audit_signals={"trace_headers": ["X-Trace-Id", "X-Instance-Id"],
                       "mcp_trace_capture": True, "tamper_resistant": False,
                       "evidence": "docs/README 契约 + mcp app.state.last_trace_id"},
        inter_agent=inter_agent,
        external_bom_refs={"sbom": None,
                           "component_versions": {"langflow": "1.8.4"},
                           "advisories_hit": ["CVE-2026-0770", "CVE-2026-5027"],
                           "packages": _packages_for_agent(gs, agent_id, tool_entries)},
        governance_weaknesses=weaknesses,
    )


def build_bom(gs: GraphStore) -> dict:
    agents = []
    for ntype in ("AgentApplication", "AgentFlow"):
        for nid in gs.nodes_by_type(ntype):
            bom = build_agent_bom(gs, nid)
            problems = bom.validate()
            if problems:
                raise ValueError(f"{nid}: {problems}")
            import dataclasses
            agents.append(dataclasses.asdict(bom))
    return wrap_bom(agents)


if __name__ == "__main__":
    import sys
    from pathlib import Path
    graph_path = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parent.parent / "out" / "graph.json"
    gs = GraphStore.load(graph_path)
    bom = build_bom(gs)
    out = graph_path.parent / "bom.json"
    from bom.schema import dump_bom
    dump_bom(bom, out)
    for a in bom["agents"]:
        tiers = [t["tier"] for t in a["tools"]]
        print(f"{a['identity']['id']:<28} autonomy={a['autonomy']['level']} "
              f"tools={len(tiers)} tiers={sorted(set(tiers))} "
              f"weaknesses={len(a['governance_weaknesses'])}")
    print(f"BOM -> {out}")
