"""R4: 观测结果入图 + 声明-观测差分。

① 汇聚 out/runtime/*.json；
② 观测写入选定节点的 observed facet（provenance=runtime:probe）；
③ bom.diff.declared_vs_observed 产出三类差分异常；
④ 生成运行时实证发现（runtime findings），升级对应静态发现的证据等级。
"""

from __future__ import annotations

import json
from pathlib import Path

from graph.store import GraphStore

RT_DIR = Path(__file__).resolve().parent.parent / "out" / "runtime"
RT_PROV = "runtime:probe"


def load_runtime() -> dict:
    bundle = {}
    for name in ("mcp_tools", "identity", "http_fingerprint"):
        path = RT_DIR / f"{name}.json"
        if path.exists():
            bundle[name] = json.loads(path.read_text(encoding="utf-8"))
    return bundle


def load_baseline_changes() -> list[dict]:
    """mcp_probe 的时序基线差（描述篡改/工具消失），rug pull 检测输入。"""
    path = RT_DIR / "baseline_changes.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def apply_observed(gs: GraphStore, rt: dict) -> dict:
    """观测面写入图节点。返回 {nodes_touched, hidden_tools_runtime} 统计。"""
    stats = {"nodes_touched": 0, "hidden_tools_runtime": []}

    for mcp_name, entry in (rt.get("mcp_tools") or {}).items():
        nid = f"mcp:{mcp_name}"
        if nid not in gs.g:
            continue
        observed = {"tools_list": [t["name"] for t in entry.get("tools", [])],
                    "probe_url": entry.get("url")}
        # 差集：代码注册（declared）有、运行时广播无 => 隐藏工具运行时实证
        declared_tools = {gs.g.nodes[t]["name"] for t in gs.neighbors_out(nid, "exposes")}
        hidden_runtime = sorted(declared_tools - set(observed["tools_list"]))
        if hidden_runtime:
            observed["hidden_confirmed"] = hidden_runtime
            stats["hidden_tools_runtime"].extend(hidden_runtime)
        gs.g.nodes[nid]["observed"].update(observed)
        gs.g.nodes[nid]["provenance"].append(RT_PROV)
        stats["nodes_touched"] += 1
        # 工具节点级：广播中的工具标 observed.advertised=True
        for tool_nid in gs.neighbors_out(nid, "exposes"):
            tname = gs.g.nodes[tool_nid]["name"]
            gs.g.nodes[tool_nid]["observed"]["advertised"] = tname in observed["tools_list"]

    ident = rt.get("identity") or {}
    for user, entry in (ident.get("logins") or {}).items():
        nid = f"id:{user}"
        if nid in gs.g:
            gs.g.nodes[nid]["observed"].update({
                "login_ok": entry.get("status") == 200,
                "claims_observed": entry.get("claims"),
                "weak_secret_validates": entry.get("verified_with_weak_secret")})
            gs.g.nodes[nid]["provenance"].append(RT_PROV)
            stats["nodes_touched"] += 1
    forge = ident.get("forge") or {}
    if "cfg:JWT_SECRET" in gs.g:
        gs.g.nodes["cfg:JWT_SECRET"]["observed"].update({
            "forge_accepted": forge.get("accepted"),
            "control_wrong_secret_rejected": forge.get("control_wrong_secret_rejected")})
        gs.g.nodes["cfg:JWT_SECRET"]["provenance"].append(RT_PROV)
        stats["nodes_touched"] += 1

    receipts = (rt.get("http_fingerprint") or {}).get("c2_receipts") or {}
    if "mcp:notes-sync" in gs.g and receipts:
        gs.g.nodes["mcp:notes-sync"]["observed"].update({
            "exfil_receipts": receipts.get("count"),
            "sensitive_keys_leaked": receipts.get("sensitive_keys_exfiltrated")})
        gs.g.nodes["mcp:notes-sync"]["provenance"].append(RT_PROV)
        stats["nodes_touched"] += 1
    if "ext:c2-sink" in gs.g:
        gs.g.nodes["ext:c2-sink"]["observed"]["receipts_count"] = receipts.get("count")
        gs.g.nodes["ext:c2-sink"]["provenance"].append(RT_PROV)
        stats["nodes_touched"] += 1

    page = (rt.get("http_fingerprint") or {}).get("poisoned_page") or {}
    for nid, d in gs.g.nodes(data=True):
        if d["type"] == "WebPage":
            d["observed"]["served_with_injection"] = page.get("injection_confirmed")
            d["observed"]["served_comments"] = page.get("comments")
            d["provenance"].append(RT_PROV)
            stats["nodes_touched"] += 1
    return stats


def runtime_findings(gs: GraphStore, rt: dict, anomalies: list[dict]) -> list[dict]:
    """把差分异常转成与采集期同构的 finding（source=runtime）。"""
    findings = []

    def f(rule, target, evidence, detail, tag, severity):
        findings.append({"rule": rule, "target": target, "evidence": evidence,
                         "detail": detail, "tag": tag, "severity": severity,
                         "source": "runtime"})

    for a in anomalies:
        if a["kind"] == "hidden_tool_confirmed":
            f("RT-hidden-tool-confirmed", a["ref"],
              "code registered + routed + absent from runtime tools/list",
              f"{a['ref']} 代码注册且被应用路由，但运行时 tools/list 不广播 —— "
              f"隐藏后门三通道闭环实证", "CWE-912", "high")
        elif a["kind"] == "undeclared_tool_call":
            f("RT-undeclared-tool", a["ref"], "runtime tools/list",
              f"运行时广播了声明面之外的工具 {a['ref']}", "CWE-1163", "medium")
        elif a["kind"] == "covert_egress_observed":
            f("RT-observed-exfil", a.get("src", "?"),
              f"c2-sink /receipts: 敏感键 {a.get('leaked_keys')}",
              f"启动外联在 c2-sink 留下外传记录（{a.get('count')} 条，含敏感环境变量）"
              f"—— 供应链后门运行时实证", "CWE-506", "high")
        elif a["kind"] == "auth_boundary_bypass":
            f("RT-jwt-forgeable", "cfg:JWT_SECRET",
              f"/me accepted forged {a.get('claims')} token; wrong-secret control rejected",
              "弱静态密钥可离线伪造任意身份 token（ops-admin 提权实测成功），"
              "阴性对照排除服务端不验签", "CWE-321", "high")
        elif a["kind"] == "description_mutated":
            f("RT-tool-description-mutated", a["key"],
              f"hash baseline: '{a.get('old_head', '')[:40]}' -> '{a.get('new_head', '')[:40]}'",
              "工具描述与上次探测的 hash 基线不一致——疑似授权后篡改（rug pull）；"
              "方法借鉴 mcp-scanner rug_pull_analyzer 的 hash 基线机制",
              "CWE-912", "high")
        elif a["kind"] == "tool_disappeared":
            f("RT-tool-disappeared", a["key"],
              "hash baseline: 广播于上次探测，本次缺席",
              "上次探测广播的工具本次消失（下架或转为隐藏）", "CWE-912", "medium")
    return findings


def run(graph_path: Path | None = None, bom_path: Path | None = None) -> dict:
    base = RT_DIR.parent
    graph_path = graph_path or base / "graph.enriched.json"
    bom_path = bom_path or base / "bom.json"
    gs = GraphStore.load(graph_path if graph_path.exists() else base / "graph.json")
    bom = json.loads(bom_path.read_text(encoding="utf-8"))
    rt = load_runtime()

    stats = apply_observed(gs, rt)
    from bom.diff import declared_vs_observed
    anomalies = declared_vs_observed(bom, rt)
    anomalies.extend(load_baseline_changes())  # rug pull 时序差并入异常流
    findings = runtime_findings(gs, rt, anomalies)
    anomalies_by_kind = {}
    for a in anomalies:
        anomalies_by_kind[a["kind"]] = anomalies_by_kind.get(a["kind"], 0) + 1

    gs.save(base / "graph.enriched.json")
    (RT_DIR / "runtime_findings.json").write_text(
        json.dumps({"anomalies": anomalies, "findings": findings,
                    "anomalies_by_kind": anomalies_by_kind},
                   ensure_ascii=False, indent=1), encoding="utf-8")
    return {"observed_stats": stats, "anomalies_by_kind": anomalies_by_kind,
            "findings": len(findings)}


if __name__ == "__main__":
    result = run()
    print(f"[observe] observed 节点 {result['observed_stats']['nodes_touched']} 个; "
          f"隐藏工具运行时实证 {result['observed_stats']['hidden_tools_runtime']}; "
          f"差分异常 {result['anomalies_by_kind']}; "
          f"运行时发现 {result['findings']} 条")
