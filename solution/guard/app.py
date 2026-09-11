"""guard 拦截代理（版本 B 核心）：MCP tools/call 逐事件判定 + 可选阻断 + 审计。

流量路径：
  runner -> [guard :8080 反代 opspilot-app]  # 提取 JWT -> trace↔actor 绑定
  opspilot-app -> [guard :8090 /mcp/{server}] -> 真实 MCP server
                                    |
                        api.judge_events（A 版同引擎，基线驱动）
模式：off（纯转发）/ observe（判定+记录）/ enforce（判定+阻断）
审计：/log/guard.jsonl（容器卷挂出）
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

GUARD_MODE = os.getenv("GUARD_MODE", "observe")
GUARD_NO_BASELINE = os.getenv("GUARD_NO_BASELINE") == "1"  # 对比实验：无资产基线
JWT_SECRET = os.getenv("GUARD_JWT_SECRET", "change-me-weak-secret")
BASELINE = json.loads(Path("/baseline/baseline.json").read_text(encoding="utf-8"))
if GUARD_NO_BASELINE:
    # 降级为纯内容规则检测器（无工具清单/隐藏工具/scope/通配符知识）
    BASELINE = {**BASELINE, "no_declaration_checks": True,
                "wildcard_capable_tools": [], "identity_scopes": [],
                "hidden_tools_forbidden": []}
AUDIT = Path("/log/guard.jsonl")
AUDIT.parent.mkdir(parents=True, exist_ok=True)

MCP_UPSTREAM = {  # URL slug -> 容器网络内真实地址
    "customer-db": "http://mcp-customer-db:8000/mcp",
    "shell-runner": "http://mcp-shell-runner:8000/mcp",
    "notes-sync": "http://mcp-notes-sync:8000/mcp",
    "threat-intel": "http://mcp-threat-intel:8000/mcp",
    "gitlab": "http://mcp-gitlab:8000/mcp",
    "monitoring": "http://mcp-monitoring:8000/mcp",
    "knowledge": "http://mcp-knowledge:8000/mcp",
    "sandbox-exec": "http://mcp-sandbox-exec:8000/mcp",
}
APP_UPSTREAM = "http://opspilot-app:8000"

app = FastAPI(title="asset-guard")
client = httpx.AsyncClient(timeout=9)   # 必须小于 app 侧 10s 读超时，慢上游快速失败
actor_by_trace: dict[str, str] = {}   # trace_id -> 用户名（编排层身份绑定）
CHAIN_STATE = {"tainted": set()}      # 跨事件持久的链路污点状态（judge_events）
stats = {"events": 0, "judged": 0, "blocked": 0, "alerted": 0,
         "forwarded_app": 0, "decision_ms_total": 0.0}


def _audit(record: dict):
    record["ts"] = time.time()
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _trace_of(headers) -> str:
    return headers.get("x-trace-id") or headers.get("x-instance-id") or "?"


# ---------------------------------------------------------------- MCP 面拦截

@app.post("/mcp/{server}")
async def mcp_proxy(server: str, request: Request):
    body = await request.json()
    headers = {k: v for k, v in request.headers.items()
               if k.lower() in ("content-type", "x-trace-id", "x-instance-id")}
    rid, method = body.get("id"), body.get("method")
    params = body.get("params") or {}

    if method == "tools/call" and GUARD_MODE != "off" and server in MCP_UPSTREAM:
        args = params.get("arguments") or {}
        event = {"trace_id": _trace_of(request.headers), "server": server,
                 "tool": params.get("name"), "args": args,
                 "cmd": args.get("cmd"), "actor_user": actor_by_trace.get(
                     _trace_of(request.headers))}
        t0 = time.perf_counter()
        from api import judge_events
        verdict = judge_events([event], BASELINE, state=CHAIN_STATE)["verdicts"][0]
        decision_ms = (time.perf_counter() - t0) * 1000
        stats.update(events=stats["events"] + 1, judged=stats["judged"] + 1,
                     decision_ms_total=stats["decision_ms_total"] + decision_ms)
        _audit({"kind": "tool_call", "mode": GUARD_MODE, "server": server,
                "tool": params.get("name"), "args": _clip(args),
                "trace": event["trace_id"], "actor": event["actor_user"],
                "score": verdict["score"], "signals": verdict["signals"],
                "action": verdict["action"], "decision_ms": round(decision_ms, 3)})
        if verdict["action"] == "block":
            if GUARD_MODE == "enforce":
                stats["blocked"] += 1
                _audit({"kind": "block", "trace": event["trace_id"],
                        "tool": f"{server}.{params.get('name')}",
                        "reason": verdict["signals"], "score": verdict["score"],
                        "mode": GUARD_MODE})
                return {"jsonrpc": "2.0", "id": rid, "error": {
                    "code": -32603,
                    "message": f"blocked by asset-guard: {verdict['signals']}"
                               f" (score={verdict['score']})"}}
        elif verdict["action"] == "alert":
            stats["alerted"] += 1

    # 转发上游（tools/list、initialize、放行的 tools/call）
    upstream = MCP_UPSTREAM.get(server)
    if not upstream:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": "unknown mcp server"}}
    try:
        resp = await client.post(upstream, json=body, headers=headers)
    except httpx.HTTPError as exc:
        _audit({"kind": "upstream_error", "server": server, "error": str(exc)[:200],
                "mode": GUARD_MODE})
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32603, "message": f"guard upstream error: {exc}"[:200]}}
    stats["events"] += 1
    return JSONResponse(resp.json(), status_code=resp.status_code)


# ---------------------------------------------------------------- 编排层反代（身份绑定）

@app.get("/status")
def status():
    decided = max(stats["judged"], 1)
    return {"mode": GUARD_MODE, **stats,
            "avg_decision_ms": round(stats["decision_ms_total"] / decided, 3),
            "actor_bindings": len(actor_by_trace)}


@app.api_route("/{path:path}",
                methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def app_proxy(path: str, request: Request):
    auth = request.headers.get("authorization", "")
    trace = _trace_of(request.headers)
    if auth.startswith("Bearer ") and path.rstrip("/") in ("run", "me", "login"):
        try:
            payload = jwt.decode(auth.removeprefix("Bearer "), JWT_SECRET,
                                 algorithms=["HS256"])
            if trace != "?":
                actor_by_trace[trace] = payload.get("sub")
        except jwt.PyJWTError:
            pass
    body = await request.body()
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length")}
    try:
        resp = await client.request(request.method, f"{APP_UPSTREAM}/{path}",
                                    content=body, headers=headers)
    except httpx.HTTPError as exc:
        return JSONResponse({"detail": f"guard upstream error: {exc}"[:200]},
                            status_code=502)
    stats["forwarded_app"] += 1
    return JSONResponse(resp.json() if resp.headers.get("content-type", "").startswith(
        "application/json") else resp.text, status_code=resp.status_code)


def _clip(args: dict, limit: int = 200) -> dict:
    return {k: (v[:limit] + "..." if isinstance(v, str) and len(v) > limit else v)
            for k, v in args.items()}
