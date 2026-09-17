"""属性图存储：scan.json -> NetworkX 图（声明面），作为 BOM/规则/前端的单一数据源。

节点: 15 类闭集（AgentApplication/AgentFlow/FrameworkComponent/ModelEndpoint/
      MCPServer/Tool/Skill/SkillScript/Identity/DataStore/NetworkSegment/
      ExternalEndpoint/WebPage/ConfigItem/Package）
边:   exposes/mounts/declares_allowed/has_script/attached_to/uses/authenticates/
      egress_to/serves/configures/depends_on
每个节点带 declared/observed 双 facet 与 provenance。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import networkx as nx

# 值得建 ConfigItem 节点的配置键标记（其余进服务节点属性）
CFG_KEY_MARKERS = ("SECRET", "PASSWORD", "TOKEN", "KEY", "WEBHOOK", "DSN", "USER",
                   "PROPAGATION", "AUTO_LOGIN", "C2_URL", "MOCK_INTERNET")

SEV_ORDER = {"high": 3, "medium": 2, "info": 1, None: 0}


def resolve_env_template(value: str) -> str:
    """${VAR:-default} -> default；其余原样返回。"""
    m = re.fullmatch(r"\$\{[^}:]+:-(.+)\}", str(value).strip())
    return m.group(1) if m else value


class GraphStore:
    def __init__(self):
        self.g = nx.DiGraph()

    # ---- 基础操作 ----
    def add_node(self, nid: str, ntype: str, name: str, **props):
        declared = props.pop("declared", {}) or {}
        observed = props.pop("observed", {}) or {}
        if nid in self.g:
            self.g.nodes[nid]["provenance"].extend(
                p for p in props.pop("provenance", []) if p not in self.g.nodes[nid]["provenance"])
            self.g.nodes[nid]["declared"].update(declared)
            self.g.nodes[nid]["observed"].update(observed)
            self.g.nodes[nid].update(props)
            return
        self.g.add_node(nid, type=ntype, name=name,
                        declared=declared, observed=observed,
                        provenance=props.pop("provenance", []),
                        severity=None, risks=[], **props)

    def add_edge(self, src: str, dst: str, etype: str, declared: bool = True, **props):
        if self.g.has_edge(src, dst) and self.g[src][dst].get("etype") == etype:
            return
        self.g.add_edge(src, dst, etype=etype, declared=declared, **props)

    def nodes_by_type(self, ntype: str) -> list[str]:
        return [n for n, d in self.g.nodes(data=True) if d.get("type") == ntype]

    def neighbors_out(self, nid: str, etype: str | None = None) -> list[str]:
        return [d for s, d, e in self.g.out_edges(nid, data=True)
                if etype is None or e.get("etype") == etype]

    def neighbors_in(self, nid: str, etype: str | None = None) -> list[str]:
        return [s for s, d, e in self.g.in_edges(nid, data=True)
                if etype is None or e.get("etype") == etype]

    def apply_risks(self, risks: list[dict]):
        """把采集期风险发现映射到节点：target 格式 tool:X.y / mcp:X / skill:X / cfg key。"""
        node_of = {nid.removeprefix("tool:"): nid
                   for nid, d in self.g.nodes(data=True) if d.get("type") == "Tool"}
        for r in risks:
            target = r["target"]
            nid = None
            if target.startswith("tool:"):
                nid = node_of.get(target.removeprefix("tool:")) or self._find_by_ref(target)
            else:
                nid = self._find_by_ref(target)
            if nid:
                d = self.g.nodes[nid]
                d["risks"].append(r["rule"])
                if SEV_ORDER[r["severity"]] > SEV_ORDER[d.get("severity")]:
                    d["severity"] = r["severity"]

    def _find_by_ref(self, target: str) -> str | None:
        prefix, _, value = target.partition(":")
        type_map = {"mcp": "MCPServer", "skill": "Skill", "agent": "AgentApplication",
                    "route": "AgentApplication", "cfg": "ConfigItem", "ext": "ExternalEndpoint"}
        want = type_map.get(prefix)
        for nid, d in self.g.nodes(data=True):
            if want and d.get("type") == want and (
                    nid.split(":", 1)[-1] == value or d.get("name") == value):
                return nid
        # 兜底：脚本/页面/配置键/镜像 等 target 用 id 后缀或名称匹配
        value = value or target
        candidates = [
            nid for nid in self.g.nodes
            if nid == target or nid.endswith(":" + value)
            or nid.split("/")[-1].split(":")[-1] == value.split("/")[-1] and value.split("/")[-1]
        ]
        if len(candidates) == 1:
            return candidates[0]
        name_hits = [nid for nid, d in self.g.nodes(data=True) if d.get("name") == value]
        if len(name_hits) == 1:
            return name_hits[0]
        return None

    # ---- 持久化 ----
    def save(self, path: Path):
        data = nx.node_link_data(self.g)
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=1),
                              encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "GraphStore":
        store = cls()
        store.g = nx.node_link_graph(json.loads(Path(path).read_text(encoding="utf-8")))
        return store


# ---------------------------------------------------------------- 构建函数

def build_graph(scan: dict) -> GraphStore:
    gs = GraphStore()
    gs.g.graph["source_root"] = scan.get("root")
    compose = scan["compose"]

    # 网络与服务
    for net in compose["networks"]:
        gs.add_node(f"net:{net}", "NetworkSegment", net)
    svc_node = {}
    for svc in compose["services"]:
        name = svc["name"]
        if svc["category"] == "mcp":
            continue  # MCP server 节点由 mcp_servers 通道建，避免重复
        ntype = {"datastore": "DataStore"}.get(
            svc["category"],
            "ModelEndpoint" if name == "llm-stub" else
            "FrameworkComponent" if name == "langflow" else
            "ExternalEndpoint" if svc["build"] and "attack" in str(svc["build"]) else
            "AgentApplication")
        nid = f"{ {'ModelEndpoint': 'model', 'FrameworkComponent': 'component', 'DataStore': 'db', 'ExternalEndpoint': 'ext', 'AgentApplication': 'agent'}.get(ntype, 'svc') }:{name}"
        svc_node[name] = nid
        gs.add_node(nid, ntype, name, declared={"image": svc["image"] or svc["build"],
                                                "ports": svc["ports"], "env": svc["env"]},
                    provenance=[compose["source"]])
        for net in svc["networks"]:
            gs.add_edge(nid, f"net:{net}", "attached_to")

    # MCP server 与工具
    for srv in scan["mcp_servers"]:
        sid = f"mcp:{srv['server']}"
        gs.add_node(sid, "MCPServer", srv["server"],
                    declared={"service": srv["service"], "on_start": srv["on_start"],
                              "on_start_caps": srv["on_start_caps"]},
                    provenance=[srv["source"]])
        if srv["service"]:
            for net in next((s["networks"] for s in compose["services"]
                             if s["name"] == srv["service"]), []):
                gs.add_edge(sid, f"net:{net}", "attached_to")
        for tool in srv["tools"]:
            tid = f"tool:{srv['server']}.{tool['name']}"
            gs.add_node(tid, "Tool", tool["name"],
                        declared={"description": tool["description"],
                                  "hidden": tool["hidden"],
                                  "handler": tool["handler"],
                                  "capabilities": tool["capabilities"]},
                        provenance=[srv["source"]])
            gs.add_edge(sid, tid, "exposes")
        # egress 边：环境变量中的出网目标
        for key in ("C2_URL", "MOCK_INTERNET"):
            url = (srv.get("declared_env") or {}).get(key) or _svc_env(
                compose, srv["service"], key)
            if url:
                host = url.split("//")[-1].split(":")[0]
                ext = svc_node.get(host) or f"ext:{host}"
                if ext not in gs.g:
                    gs.add_node(ext, "ExternalEndpoint", host,
                                declared={"url": url}, provenance=["env:" + key])
                gs.add_edge(sid, ext, "egress_to", url=url)

    # Python 依赖包：全部盘点；仅有确定 Compose owner 的 runtime 依赖建立 depends_on。
    for package in scan.get("packages", []):
        pid = f"package:{package['name']}"
        sources = [f"{entry['file']}:{entry['line']}" for entry in package.get("sources", [])]
        gs.add_node(pid, "Package", package["name"],
                    declared={"version_specs": package.get("version_specs", []),
                              "scopes": package.get("scopes", []),
                              "owners": package.get("owners", []),
                              "owner_entries": package.get("owner_entries", []),
                              "entries": package.get("sources", [])},
                    provenance=sources)
        runtime_owners = {entry["owner"] for entry in package.get("owner_entries", [])
                          if entry.get("scope") == "runtime"}
        for owner in runtime_owners:
            owner_id = svc_node.get(owner) or (
                f"mcp:{owner.removeprefix('mcp-')}" if owner.startswith("mcp-") else None)
            if owner_id and owner_id in gs.g:
                gs.add_edge(owner_id, pid, "depends_on",
                            purpose="python-runtime-dependency")

    # Agent 应用：路由挂载 / 技能 / 模型 / 身份
    app = scan["app"]
    agent = "agent:opspilot-app"
    gs.add_node(agent, "AgentApplication", "opspilot-app",
                declared={"max_steps": app.get("max_steps"),
                          "system_prompt": app.get("system_prompt"),
                          "routes": {k: list(v) for k, v in app["routes"].items()}},
                provenance=[app["source"]])
    for openai_name, (server, tool_name) in app["routes"].items():
        tid = f"tool:{server}.{tool_name}"
        if tid in gs.g:
            gs.add_edge(agent, tid, "mounts", route=openai_name)
    if "model:llm-stub" in gs.g:
        gs.add_edge(agent, "model:llm-stub", "uses", purpose="llm")
        gs.add_edge("component:langflow", "model:llm-stub", "uses", purpose="llm")
    gs.add_edge(agent, "component:langflow", "uses", purpose="orchestration")

    for ident in app["identities"]:
        iid = f"id:{ident['user']}"
        gs.add_node(iid, "Identity", ident["user"],
                    declared={"role": ident["role"], "team": ident["team"],
                              "scope": ident["scope"]},
                    provenance=[app["source"]])
        gs.add_edge(iid, agent, "authenticates")

    # Skills 与脚本
    for skill in scan["skills"]:
        skid = f"skill:{skill['name']}"
        gs.add_node(skid, "Skill", skill["name"],
                    declared={"description": skill["description"],
                              "allowed_tools": skill["allowed_tools"],
                              "hidden_comments": skill["hidden_comments"]},
                    provenance=[skill["source"]])
        gs.add_edge(agent, skid, "mounts")
        dangling = []
        for target in skill["allowed_tools"]:
            mid = f"mcp:{target}"
            if mid in gs.g:
                gs.add_edge(skid, mid, "declares_allowed")
            else:
                dangling.append(target)  # 悬空引用不静默丢弃，留给完整性校验器
        if dangling:
            gs.g.nodes[skid]["declared"]["dangling_allowed_tools"] = dangling
        for script in skill["scripts"]:
            scid = f"script:{script['path']}"
            gs.add_node(scid, "SkillScript", script["path"].split("/")[-1],
                        declared={"path": script["path"], "sha256": script["sha256"],
                                  "b64_payloads": script["b64_payloads"]},
                        provenance=[script["path"]])
            gs.add_edge(skid, scid, "has_script")

    # 编排 flow（第二个 agent）
    for flow in scan.get("flows", []):
        fid = f"flow:{flow['name']}"
        gs.add_node(fid, "AgentFlow", flow["name"],
                    declared={"description": flow["description"],
                              "nodes": flow["nodes"],
                              "model_base": flow["model_base"]},
                    provenance=[flow["source"]])
        gs.add_edge("component:langflow", fid, "exposes")
        for t in flow["mcp_tools"]:
            mid = f"mcp:{t}"
            if mid in gs.g:
                gs.add_edge(fid, mid, "mounts")

    # 外部内容源（投毒页）
    for page in scan.get("web_pages", []):
        pid = f"page:{page['path'].split('/')[-1]}"
        gs.add_node(pid, "WebPage", page["path"].split("/")[-1],
                    declared={"path": page["path"],
                              "hidden_comments": page["hidden_comments"]},
                    provenance=[page["path"]])
        if "ext:mock-internet" in gs.g:
            gs.add_edge("ext:mock-internet", pid, "serves")

    # ConfigItem（仅敏感/关键键）
    env_entries = list(scan["env_items"])
    for svc in compose["services"]:
        for k, v in svc["env"].items():
            env_entries.append({"key": k, "value": v,
                                "source": f"docker-compose.yml:{svc['name']}.{k}"})
    for e in env_entries:
        if not any(m in e["key"].upper() for m in CFG_KEY_MARKERS):
            continue
        cid = f"cfg:{e['key']}"
        target = _cfg_target(e["source"], svc_node)
        resolved = resolve_env_template(e["value"])
        if cid in gs.g:  # 多来源合并：保留全部来源，代表值优先取非模板明文
            node = gs.g.nodes[cid]
            node["declared"].setdefault("entries", []).append(
                {"source": e["source"], "raw": e["value"], "value": resolved})
            if e["source"] not in node["provenance"]:
                node["provenance"].append(e["source"])
            if "${" not in e["value"]:
                node["declared"]["value"] = resolved
        else:
            gs.add_node(cid, "ConfigItem", e["key"],
                        declared={"value": resolved,
                                  "entries": [{"source": e["source"],
                                               "raw": e["value"], "value": resolved}]},
                        provenance=[e["source"]])
        if target:
            gs.add_edge(cid, target, "configures")

    gs.apply_risks(scan.get("risks", []))
    return gs


def _svc_env(compose: dict, service: str | None, key: str) -> str | None:
    for svc in compose["services"]:
        if svc["name"] == service:
            return svc["env"].get(key)
    return None


def _cfg_target(source: str, svc_node: dict) -> str | None:
    """根据配置来源推断它配置的目标节点。"""
    if ".env.example" in source and "managed-host" not in source:
        return "agent:opspilot-app"
    if "managed-host" in source:
        return "mcp:shell-runner"
    if source.startswith("docker-compose.yml:"):
        svc = source.split(":", 1)[1].split(".")[0]
        return svc_node.get(svc) or (f"mcp:{svc.removeprefix('mcp-')}" if svc.startswith("mcp-")
                                     else None)
    if source.endswith("Dockerfile") or "/Dockerfile" in source:
        return "component:langflow" if "langflow" in source else None
    if "secrets.env" in source:
        return "agent:opspilot-app"
    return None


if __name__ == "__main__":
    import sys
    scan_path = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parent.parent / "out" / "scan.json"
    out_path = scan_path.parent / "graph.json"
    scan = json.loads(scan_path.read_text(encoding="utf-8"))
    store = build_graph(scan)
    store.save(out_path)
    types = {}
    for _, d in store.g.nodes(data=True):
        types[d["type"]] = types.get(d["type"], 0) + 1
    print(f"节点 {store.g.number_of_nodes()} / 边 {store.g.number_of_edges()}")
    for t, c in sorted(types.items(), key=lambda x: -x[1]):
        print(f"  {t:<18} {c}")
    risky = [(n, d['severity']) for n, d in store.g.nodes(data=True) if d.get('severity')]
    print(f"带风险标记节点 {len(risky)}: {risky}")
