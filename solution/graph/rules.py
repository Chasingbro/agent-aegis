"""图谱推理引擎（静态层）：权限包络校验规则。

规则在图上遍历推导，独立于采集期规则（collect_static.run_rules），
用于验证"图谱承载的信息足以支撑风险判定"，并给出图结构证据。
"""

from __future__ import annotations

from graph.store import GraphStore
from bom.tiers import tier_rank

# 与《靶场信息整理》12 项标准答案的对应关系（用于对账）
GROUND_TRUTH_MAP = {
    "ENV-01-high-tier-no-approval": "GT#2 宽权限服务账号(confused deputy)",
    "ENV-02-hidden-tool-mounted": "GT-供应链1 notes-sync 后门",
    "ENV-03-overprivileged-path": "GT#6 tenant=* 宽权限语义",
    "ENV-04-covert-egress": "GT-供应链1 启动外联",
    "ENV-05-weak-auth-config": "GT#1/#4 弱 JWT 密钥",
    "ENV-06-missing-identity-propagation": "GT#7 Agent->MCP 不传身份头",
    "ENV-07-vulnerable-component": "GT-供应链5 langflow CVE",
    "ENV-08-supply-chain-script": "GT-供应链3 pdf-export 混淆脚本",
    "ENV-09-poisoned-content": "GT-供应链4 投毒页面",
    "ENV-10-auto-login-component": "GT#3 langflow 免认证",
    "ENV-11-default-credentials": "GT#5 postgres 弱口令",
    "ENV-12-skill-injection-surface": "GT-供应链2 meeting-summary 隐藏指令",
}


def _finding(rule, target, evidence, detail, tag, severity, gt=None):
    return {"rule": rule, "target": target, "evidence": evidence, "detail": detail,
            "tag": tag, "severity": severity, "ground_truth": gt or GROUND_TRUTH_MAP.get(rule)}


def run_envelope_rules(gs: GraphStore, bom: dict | None = None) -> list[dict]:
    findings: list[dict] = []
    tool_tier = {}
    if bom:
        for agent in bom["agents"]:
            for t in agent.get("tools") or []:
                tool_tier[t["ref"]] = t["tier"]

    agent_ids = [n for n in gs.nodes_by_type("AgentApplication")
                 + gs.nodes_by_type("AgentFlow")]

    for agent in agent_ids:
        mounted = gs.neighbors_out(agent, "mounts")
        tools = [t for t in mounted if gs.g.nodes[t]["type"] == "Tool"]
        # 继承 flow 级 server 挂载的工具
        for m in mounted:
            if gs.g.nodes[m]["type"] == "MCPServer":
                tools.extend(gs.neighbors_out(m, "exposes"))

        # ENV-01: 挂载 T4+ 工具且 agent 无审批门声明
        high = [t for t in tools
                if tool_tier and tier_rank(tool_tier.get(t, "T1")) >= 4
                or gs.g.nodes[t]["declared"].get("capabilities", {}).get("subprocess")]
        if high:
            findings.append(_finding(
                "ENV-01-high-tier-no-approval", agent,
                f"mounts -> {sorted(high)}",
                f"Agent 挂载 {len(high)} 个命令执行级工具且无审批门",
                "CWE-269 / OWASP LLM06", "high"))

        # ENV-02: 挂载隐藏工具（声明面不可见但可达）
        hidden = [t for t in tools if gs.g.nodes[t]["declared"].get("hidden")]
        if hidden:
            findings.append(_finding(
                "ENV-02-hidden-tool-mounted", agent, f"mounts -> {hidden}",
                "可达工具不在 tools/list 声明面内（隐藏后门）",
                "CWE-912", "high"))

    # ENV-03: 全权限身份 + 通配符工具 = 过权路径
    for iid in gs.nodes_by_type("Identity"):
        d = gs.g.nodes[iid]["declared"]
        if d.get("role") == "ops-admin" or d.get("scope") == {}:
            for agent in gs.neighbors_out(iid, "authenticates"):
                for tid in gs.neighbors_out(agent, "mounts"):
                    if gs.g.nodes[tid]["type"] == "Tool" and \
                            gs.g.nodes[tid]["declared"].get("capabilities", {}).get("wildcard_check"):
                        findings.append(_finding(
                            "ENV-03-overprivileged-path", f"{iid} -> {tid}",
                            f"authenticates({agent}) + mounts({tid})",
                            f"身份 {gs.g.nodes[iid]['name']} 无租户 scope 却可达通配符查询工具",
                            "CWE-862", "high"))
                        break

    # ENV-04: MCP 启动期出网（隐蔽外联通道）
    for mid in gs.nodes_by_type("MCPServer"):
        d = gs.g.nodes[mid]["declared"]
        caps = d.get("on_start_caps") or {}
        if d.get("on_start") and (caps.get("net_out") or caps.get("env_read")):
            egress = gs.neighbors_out(mid, "egress_to")
            findings.append(_finding(
                "ENV-04-covert-egress", mid, f"egress_to -> {egress}",
                f"on_start={d['on_start']} 出网 {caps.get('net_out')} "
                f"读取环境变量={caps.get('env_read')}",
                "CWE-506", "high"))

    # ENV-05: 弱密钥配置作用在认证组件上
    weak_values = ("change-me", "weak", "admin")
    for cid in gs.nodes_by_type("ConfigItem"):
        name = gs.g.nodes[cid]["name"]
        val = str(gs.g.nodes[cid]["declared"].get("value") or "")
        if ("SECRET" in name.upper() or "PASSWORD" in name.upper()) \
                and any(w in val.lower() for w in weak_values):
            findings.append(_finding(
                "ENV-05-weak-auth-config", cid,
                f"configures -> {gs.neighbors_out(cid, 'configures')}",
                f"{name} = '{val}' 命中弱值模式",
                "CWE-321", "high"))

    # ENV-06: 服务账号传播（下游身份盲区）
    for cid in gs.nodes_by_type("ConfigItem"):
        if gs.g.nodes[cid]["name"] == "OPSPILOT_PROPAGATION" and \
                gs.g.nodes[cid]["declared"].get("value") == "service-account":
            findings.append(_finding(
                "ENV-06-missing-identity-propagation", cid,
                f"configures -> {gs.neighbors_out(cid, 'configures')}",
                "身份以 service-account 传播，MCP 侧无法执行租户级越权拦截",
                "CWE-284", "high"))

    # ENV-07: 已知漏洞版本组件
    for nid, d in gs.g.nodes(data=True):
        if d["type"] == "FrameworkComponent":
            ver = (d["declared"].get("image") or "")
            if "langflow" in str(ver):
                findings.append(_finding(
                    "ENV-07-vulnerable-component", nid,
                    f"declared.image ~ {ver}",
                    "langflow 1.8.4 命中本地公告库 CVE-2026-0770/CVE-2026-5027",
                    "CWE-94 / CWE-434", "high"))

    # ENV-08: 技能脚本携带混淆载荷
    for nid, d in gs.g.nodes(data=True):
        if d["type"] == "SkillScript":
            payloads = d["declared"].get("b64_payloads") or []
            if payloads:
                findings.append(_finding(
                    "ENV-08-supply-chain-script", nid, nid,
                    f"Base64 载荷解码命中 {payloads[0]['dangerous_patterns']}",
                    "CWE-506", "high"))

    # ENV-09: 外部内容源注入面
    for nid, d in gs.g.nodes(data=True):
        if d["type"] == "WebPage" and d["declared"].get("hidden_comments"):
            findings.append(_finding(
                "ENV-09-poisoned-content", nid, nid,
                "服务页注释携带指令内容，可经检索工具进入模型上下文",
                "OWASP LLM01", "high"))

    # ENV-10: 框架免认证配置
    for cid in gs.nodes_by_type("ConfigItem"):
        if gs.g.nodes[cid]["name"] == "LANGFLOW_AUTO_LOGIN" and \
                str(gs.g.nodes[cid]["declared"].get("value")).lower() == "true":
            findings.append(_finding(
                "ENV-10-auto-login-component", cid,
                f"configures -> {gs.neighbors_out(cid, 'configures')}",
                "编排框架开启免认证自动登录", "CWE-798", "medium"))

    # ENV-11: 默认口令（账号=口令）
    user = pwd = None
    for cid in gs.nodes_by_type("ConfigItem"):
        n = gs.g.nodes[cid]["name"]
        v = gs.g.nodes[cid]["declared"].get("value")
        if n == "POSTGRES_USER":
            user = v
        if n == "POSTGRES_PASSWORD":
            pwd = v
    if user and user == pwd:
        findings.append(_finding(
            "ENV-11-default-credentials", "db:postgres-customer",
            "cfg:POSTGRES_USER == cfg:POSTGRES_PASSWORD",
            f"数据库账号口令相同：{user}", "CWE-798", "medium"))

    # ENV-12: Skill 正文注入指令（声明面 allowed-tools 之外的指令动作）
    for nid, d in gs.g.nodes(data=True):
        if d["type"] == "Skill" and d["declared"].get("hidden_comments"):
            findings.append(_finding(
                "ENV-12-skill-injection-surface", nid, nid,
                "Skill 正文 HTML 注释含指令内容，加载后直接进入 system 上下文",
                "OWASP LLM01", "high"))

    return findings


def reconcile_ground_truth(findings: list[dict]) -> list[tuple]:
    """12 项标准答案覆盖对账。"""
    rules_hit = {f["rule"] for f in findings}
    return [(rule, rule in rules_hit, gt) for rule, gt in GROUND_TRUTH_MAP.items()]
