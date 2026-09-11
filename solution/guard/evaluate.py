"""B3 组合效果评测：全量 replay × {无基线, 有资产基线} 两相对比。

流程（每相）：
  1. 按 GUARD_NO_BASELINE 重建 guard（enforce 模式）
  2. 清空审计 → 后台 CPU 采样器 → 全量 replay（5200 事件过代理）
  3. 解析 guard.jsonl：按 trace 前缀取标签，算检出/阻断/误报/时延
产出：out/eval/eval_data.json + eval_report.md（两相对比表）
注意：C1-A/C1-B（24 条恶意）不经过 MCP 链路，guard 不可见，
     检出归属静态资产识别（known-vulnerable-version 已命中），报告中单列。
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

SOLUTION = Path(__file__).resolve().parent.parent
RANGE = SOLUTION.parent / "揭榜挑战赛赛题2靶场-AgentRange-player"
AUDIT = SOLUTION / "guard" / "audit" / "guard.jsonl"
EVAL = SOLUTION / "out" / "eval"
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml",
           "-f", "../solution/guard/guard-compose.yml",
           "-f", "../solution/runtime/hostport.override.yml"]

MALICIOUS = {"C1-A", "C1-B", "C2-A", "C2-B", "C2-C", "C2-D", "M-1"}
GUARD_VISIBLE_MAL = MALICIOUS - {"C1-A", "C1-B"}   # 仅 cat2 走 MCP 链


def _trace_scenario(trace: str) -> str:
    return re.sub(r"-\d+$", "", trace)


def _run_phase(no_baseline: bool) -> dict:
    label = "no_baseline" if no_baseline else "with_baseline"
    print(f"\n===== 相位: {label} =====")
    env = {**__import__("os").environ,
           "GUARD_MODE": "enforce",
           "GUARD_NO_BASELINE": "1" if no_baseline else "0"}
    subprocess.run(COMPOSE + ["up", "-d", "--build", "guard"], cwd=RANGE,
                   env=env, capture_output=True, text=True, check=True)
    time.sleep(6)
    AUDIT.unlink(missing_ok=True)

    cpu_samples: list[float] = []
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            try:
                out = subprocess.run(
                    ["docker", "stats", "--no-stream", "--format",
                     "{{.CPUPerc}}", "2-agentrange-player-guard-1"],
                    capture_output=True, text=True, timeout=10).stdout.strip()
                cpu_samples.append(float(out.rstrip("%")))
            except Exception:
                pass
            time.sleep(2)

    thread = threading.Thread(target=sampler); thread.start()
    t0 = time.time()
    proc = subprocess.run(
        [str(RANGE / ".venv/Scripts/python.exe"), "scenario-runner/runner.py"],
        cwd=RANGE, env={**env, "OPSPILOT_BASE": "http://localhost:18080"},
        capture_output=True, text=True)
    stop.set(); thread.join()
    wall_min = (time.time() - t0) / 60
    print(f"  replay exit={proc.returncode} 耗时 {wall_min:.1f} 分钟"
          f"（stderr 尾: {proc.stderr.strip()[-120:] or '无'}）")

    records = [json.loads(l) for l in AUDIT.read_text(encoding="utf-8").splitlines()]
    tool_calls = [r for r in records if r["kind"] == "tool_call"]
    by_trace = defaultdict(list)
    for r in tool_calls:
        by_trace[r["trace"]].append(r)

    detected, blocked, benign_flagged, benign_blocked = set(), set(), set(), set()
    decisions = [r["decision_ms"] for r in tool_calls if "decision_ms" in r]
    for trace, rs in by_trace.items():
        scen = _trace_scenario(trace)
        flagged = any(r["score"] > 0 for r in rs)
        blk = any(r["action"] == "block" for r in rs) or \
            any(r1["kind"] == "block" for r1 in records if r1.get("trace") == trace)
        if scen in MALICIOUS:
            flagged and detected.add(trace)
            blk and blocked.add(trace)
        else:
            flagged and benign_flagged.add(trace)
            blk and benign_blocked.add(trace)

    mal_visible = {t for t in by_trace if _trace_scenario(t) in GUARD_VISIBLE_MAL}
    benign_traces = {t for t in by_trace if _trace_scenario(t) not in MALICIOUS}
    result = {
        "label": label,
        "replay_minutes": round(wall_min, 1),
        "tool_calls": len(tool_calls),
        "traces_total": len(by_trace),
        "malicious_traces_visible": len(mal_visible),
        "malicious_detected": len(detected & mal_visible),
        "malicious_blocked": len(blocked & mal_visible),
        "detected_detail": sorted(detected),
        "benign_traces": len(benign_traces),
        "benign_flagged": len(benign_flagged),
        "benign_blocked": len(benign_blocked),
        "benign_flagged_detail": sorted(benign_flagged)[:20],
        "decision_ms_avg": round(sum(decisions) / max(len(decisions), 1), 3),
        "decision_ms_max": round(max(decisions), 3) if decisions else None,
        "cpu_pct_max": max(cpu_samples) if cpu_samples else None,
        "cpu_pct_avg": round(sum(cpu_samples) / max(len(cpu_samples), 1), 1)
        if cpu_samples else None,
    }
    print(f"  恶意(trace可见) {result['malicious_traces_visible']}: "
          f"检出 {result['malicious_detected']} 阻断 {result['malicious_blocked']}; "
          f"良性 {result['benign_traces']}: 误标 {result['benign_flagged']} "
          f"误断 {result['benign_blocked']}; "
          f"判定 avg {result['decision_ms_avg']}ms / max {result['decision_ms_max']}ms; "
          f"CPU max {result['cpu_pct_max']}% avg {result['cpu_pct_avg']}%")
    return result


def _report(results: list[dict]):
    EVAL.mkdir(parents=True, exist_ok=True)
    (EVAL / "eval_data.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    a, b = results  # a=无基线, b=有基线
    lines = [
        "# 组合效果评测报告（guard 实验版）",
        "",
        "全量语料 replay（seed=1337，5200 事件 / 80 恶意 / 5120 良性）过 MCP 拦截代理，",
        "对比「无声明类知识（关闭工具清单/隐藏工具/scope/通配符信号，保留内容规则）」",
        "与「加载完整声明包络基线」两相检测效果。",
        "",
        "| 指标 | 无基线 | 有资产基线 | 目标 |",
        "|---|---|---|---|",
        f"| cat2 恶意检出（guard 可见 {b['malicious_traces_visible']} 条） | "
        f"{a['malicious_detected']} | **{b['malicious_detected']}** | ≥95% |",
        f"| cat2 恶意阻断 | {a['malicious_blocked']} | **{b['malicious_blocked']}** | — |",
        f"| 良性误标 | {a['benign_flagged']} | {b['benign_flagged']} | <5% |",
        f"| 良性误阻断（业务中断） | {a['benign_blocked']} | {b['benign_blocked']} | 0 |",
        f"| 判定时延 avg/max (ms) | {a['decision_ms_avg']}/{a['decision_ms_max']} | "
        f"{b['decision_ms_avg']}/{b['decision_ms_max']} | <1000ms |",
        f"| guard CPU avg/max (%) | {a['cpu_pct_avg']}/{a['cpu_pct_max']} | "
        f"{b['cpu_pct_avg']}/{b['cpu_pct_max']} | <5% |",
        "",
        f"说明：",
        f"1. C1-A/C1-B（24 条恶意）直接打 Langflow 漏洞端点，不经 MCP 链路，guard 不可见；"
        f"其检出归属静态资产识别（known-vulnerable-version 规则命中 langflow 1.8.4 两个 CVE）。",
        f"2. 检出率口径：cat2 按 guard；全量 80 条恶意按『guard(cat2) ∪ 静态(C1)』合并计算。",
        f"3. 每相 replay 墙钟约 {a['replay_minutes']}/{b['replay_minutes']} 分钟。",
    ]
    (EVAL / "eval_report.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"\n-> {EVAL / 'eval_report.md'}")


if __name__ == "__main__":
    phases = []
    if "phase2" not in sys.argv:       # 默认两相；`phase2` 仅补跑有基线相
        phases.append(_run_phase(no_baseline=True))
    phases.append(_run_phase(no_baseline=False))
    _report(phases if len(phases) == 2 else
            [json.loads((EVAL / "eval_data.json").read_text(encoding="utf-8"))[0]]
            + phases)
