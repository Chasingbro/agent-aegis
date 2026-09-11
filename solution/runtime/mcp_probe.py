"""R1: MCP tools/list 运行时探测 + 描述 hash 时序基线。

通路：宿主生成探测脚本 -> docker exec -i <opspilot-app> python - 从 stdin 注入执行
（opspilot-app 容器 env 内含全部 8 个 MCP URL，镜像自带 python）。
产出：
  out/runtime/mcp_tools.json      —— 每 server 运行时广播的工具清单；
  out/runtime/baseline_tools.json —— server:tool -> 描述 SHA-256 时序基线。
时序基线方法借鉴 eSentire-Labs/mcp-scanner 的 rug_pull_analyzer
（hash 不匹配即描述被篡改；我们只取其纯 hash 级，不引入其嵌入相似度部分）。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "out" / "runtime"
BASELINE = OUT / "baseline_tools.json"

# 容器内执行：只用标准库 urllib，按 env 中的 MCP_* URL 逐个 initialize + tools/list
INNER = r"""
import json, os, urllib.request

urls = {k.removeprefix("MCP_").lower().replace("_", "-"): v
        for k, v in os.environ.items() if k.startswith("MCP_")}

def rpc(url, method, params=None):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())

results = {}
for name, url in sorted(urls.items()):
    entry = {"url": url}
    try:
        init = rpc(url, "initialize", {"protocolVersion": "2025-06-18",
                                       "capabilities": {},
                                       "clientInfo": {"name": "probe", "version": "0"}})
        entry["serverInfo"] = (init.get("result") or {}).get("serverInfo")
        tl = rpc(url, "tools/list")
        tools = (tl.get("result") or {}).get("tools") or []
        entry["tools"] = [{"name": t.get("name"),
                           "description": (t.get("description") or "")[:200]}
                          for t in tools]
    except Exception as exc:
        entry["error"] = f"{type(exc).__name__}: {exc}"
    results[name] = entry
print("@@PROBE_RESULT@@")
print(json.dumps(results, ensure_ascii=False))
"""


def find_opspilot_container() -> str:
    """动态发现正在运行的 opspilot-app 容器（不依赖 compose 项目名）。"""
    out = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
        capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        name, _, status = line.partition("\t")
        if "opspilot-app" in name and status.startswith("Up"):
            return name.strip()
    raise RuntimeError("未找到运行中的 opspilot-app 容器（靶场是否已拉起？）")


def probe() -> dict:
    container = find_opspilot_container()
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "python", "-"],
        input=INNER, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"docker exec 失败: {proc.stderr[:500]}")
    marker = "@@PROBE_RESULT@@"
    if marker not in proc.stdout:
        raise RuntimeError(f"探测脚本无输出: {proc.stdout[:300]} {proc.stderr[:300]}")
    return json.loads(proc.stdout.split(marker, 1)[1].strip())


def check_baseline(results: dict) -> list[dict]:
    """与上次探测的描述 hash 对比；不匹配 => 疑似 rug pull（授权后描述篡改）。

    基线条目: {server:tool: {"hash", "description", "last_updated"}}，键形如
    mcp-scanner 的 tool_security_data.json，但只保留纯 hash 比对。
    """
    changes: list[dict] = []
    old = json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else {}
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    new = {}
    for server, entry in results.items():
        for tool in entry.get("tools", []):
            key = f"{server}:{tool['name']}"
            canonical = f"{tool['name']}\n{tool.get('description', '')}"
            digest = hashlib.sha256(canonical.encode()).hexdigest()
            new[key] = {"hash": digest,
                        "description": tool.get("description", ""),
                        "last_updated": now}
            prev = old.get(key)
            if prev and prev["hash"] != digest:
                changes.append({
                    "key": key, "kind": "description_mutated",
                    "old_head": prev["description"][:80],
                    "new_head": tool.get("description", "")[:80]})
    # 曾广播、本次消失的工具（下架/隐藏化）
    for key in old:
        if key not in new:
            changes.append({"key": key, "kind": "tool_disappeared",
                            "old_head": old[key]["description"][:80]})
    BASELINE.write_text(json.dumps(new, ensure_ascii=False, indent=1), encoding="utf-8")
    (OUT / "baseline_changes.json").write_text(
        json.dumps(changes, ensure_ascii=False, indent=1), encoding="utf-8")
    return changes


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    results = probe()
    changes = check_baseline(results)
    servers_ok = sum(1 for e in results.values() if "tools" in e)
    total_tools = sum(len(e.get("tools", [])) for e in results.values())
    path = OUT / "mcp_tools.json"
    path.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[mcp_probe] server {servers_ok}/{len(results)} 探测成功, "
          f"运行时广播工具 {total_tools} 个")
    for name, e in sorted(results.items()):
        if "error" in e:
            print(f"  {name:<14} ERROR {e['error']}")
        else:
            print(f"  {name:<14} {[t['name'] for t in e['tools']]}")
    if changes:
        print(f"  [baseline] 检测到 {len(changes)} 处时序变化（疑似 rug pull）:")
        for c in changes:
            print(f"    {c['key']}: {c['kind']}")
            if c["kind"] == "description_mutated":
                print(f"      旧: {c['old_head']}")
                print(f"      新: {c['new_head']}")
    else:
        print("  [baseline] 与上次探测一致，无描述篡改")
    print(f"-> {path}")
    return 0 if servers_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
