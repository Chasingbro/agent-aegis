"""FastAPI 服务：/api/* 数据接口 + 前端静态页。用法: python -m server.app"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from graph.export import export_for_frontend
from graph.rules import run_envelope_rules
from graph.store import GraphStore

OUT = Path(__file__).resolve().parent.parent / "out"
WEB = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="AgentRange 资产风险图谱", version="0.1")


def _load(name):
    return json.loads((OUT / name).read_text(encoding="utf-8"))


def _graph():
    enriched = OUT / "graph.enriched.json"
    return GraphStore.load(enriched if enriched.exists() else OUT / "graph.json")


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


@app.get("/app.js")
def app_js():
    return FileResponse(WEB / "app.js")


@app.get("/vendor/cytoscape.min.js")
def cytoscape_js():
    return FileResponse(WEB / "vendor" / "cytoscape.min.js")


@app.get("/api/graph")
def api_graph():
    return export_for_frontend(_graph())


@app.get("/api/bom")
def api_bom():
    return _load("bom.json")


@app.get("/api/risks")
def api_risks():
    static_risks = _load("scan.json").get("risks", [])
    envelope = run_envelope_rules(_graph(), _load("bom.json"))
    rt_path = OUT / "runtime" / "runtime_findings.json"
    runtime = json.loads(rt_path.read_text(encoding="utf-8")).get("findings", []) \
        if rt_path.exists() else []
    val_path = OUT / "validator_findings.json"
    validator = json.loads(val_path.read_text(encoding="utf-8")).get("findings", []) \
        if val_path.exists() else []
    return {"static": static_risks, "envelope": envelope, "runtime": runtime,
            "validator": validator,
            "total": len(static_risks) + len(envelope) + len(runtime) + len(validator)}


@app.get("/api/summary")
def api_summary():
    scan = _load("scan.json")
    bom = _load("bom.json")
    gs = _graph()
    return {
        "services": len(scan["compose"]["services"]),
        "mcp_servers": len(scan["mcp_servers"]),
        "tools": sum(len(s["tools"]) for s in scan["mcp_servers"]),
        "hidden_tools": sum(1 for s in scan["mcp_servers"] for t in s["tools"]
                            if t["hidden"]),
        "skills": len(scan["skills"]),
        "identities": len(scan["app"]["identities"]),
        "graph_nodes": gs.g.number_of_nodes(),
        "graph_edges": gs.g.number_of_edges(),
        "agents": [{"id": a["identity"]["id"], "name": a["identity"]["name"],
                    "score": a["risk_assessment"]["score"],
                    "quadrant": a["risk_assessment"]["quadrant"],
                    "autonomy": a["autonomy"]["level"],
                    "max_tier": a["risk_assessment"]["max_tool_tier"]}
                   for a in bom["agents"]],
    }


# ---------------- 融合接口（版本 A / L3 REST 层） ----------------

@app.get("/api/baseline")
def api_baseline():
    """声明包络导出：队友监测系统可直接消费的判定基线。"""
    import api
    return api.policy_baseline()


@app.post("/api/judge")
def api_judge(events: list[dict]):
    """事件级判定入口：POST JSON 数组事件，返回逐事件判定。"""
    import api
    return api.judge_events(events)


@app.get("/api/artifacts")
def api_artifacts():
    """全部工件打包下载（zip）。"""
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(OUT.rglob("*.json")):
            zf.write(path, path.relative_to(OUT))
    buffer.seek(0)
    from fastapi.responses import StreamingResponse
    return StreamingResponse(
        buffer, media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=artifacts.zip"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
