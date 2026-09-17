"""端到端 CLI：scan -> graph -> bom(build/score/controls) -> import -> verify -> serve

用法:
  python cli.py all [--root <靶场目录>]       # solution 全流程
  python cli.py peer-scan [--root <目标目录>] # 隔离运行队友扫描器
  python cli.py bench [--root <目标目录>]     # 对目标运行 oracle 评测
  python cli.py fused-bench [--root <目标目录>] # 独立输出的通用/融合评测
  python cli.py serve                         # 启动前端 (127.0.0.1:8080)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SOLUTION = Path(__file__).resolve().parent
OUT = SOLUTION / "out"
sys.path.insert(0, str(SOLUTION))
from range_root import RANGE  # noqa: E402


def run_step(name: str, fn):
    print(f"\n=== {name} ===")
    result = fn()
    print(f"    ok: {result}")
    return result


def cmd_scan(root: Path, output: Path | None = None, generic_only: bool = False):
    command = [sys.executable, str(SOLUTION / "collect_static.py"), str(root)]
    if output:
        command.extend(["--output", str(output)])
    if generic_only:
        command.append("--generic-only")
    proc = subprocess.run(command, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-2000:]); print(proc.stderr[-2000:])
        raise SystemExit("scan 失败")
    tail = [l for l in proc.stdout.splitlines() if "对账结果" in l or "FAIL" in l]
    return "; ".join(tail) or "scan 完成"


def cmd_graph(out: Path = OUT):
    sys.path.insert(0, str(SOLUTION))
    from graph.store import GraphStore, build_graph
    scan = json.loads((out / "scan.json").read_text(encoding="utf-8"))
    gs = build_graph(scan)
    gs.save(out / "graph.json")
    return f"{gs.g.number_of_nodes()} 节点 / {gs.g.number_of_edges()} 边"


def cmd_bom(out: Path = OUT):
    from bom.schema import load_bom, dump_bom
    from bom.builder import build_bom
    from bom.scorer import score_bom
    from bom.controls import annotate_controls
    from graph.store import GraphStore
    gs = GraphStore.load(out / "graph.json")
    bom = annotate_controls(score_bom(build_bom(gs)))
    dump_bom(bom, out / "bom.json")
    scores = [f"{a['identity']['id']}={a['risk_assessment']['score']}"
              f"({a['risk_assessment']['quadrant']})" for a in bom["agents"]]
    return "; ".join(scores)


def cmd_import(out: Path = OUT):
    from bom.schema import load_bom
    from bom.importer import import_bom, round_trip_check
    from graph.store import GraphStore
    gs = GraphStore.load(out / "graph.json")
    bom = load_bom(out / "bom.json")
    stats = import_bom(gs, bom)
    rt = round_trip_check(gs, bom)
    gs.save(out / "graph.enriched.json")
    if not rt["pass"]:
        raise SystemExit(f"round-trip 失败: {rt}")
    return f"import {stats}; round-trip pass"


def cmd_runtime() -> str:
    """三通道运行时探测 + 观测入图；靶场不可达时优雅跳过。"""
    import subprocess as sp
    for mod in ("runtime.mcp_probe", "runtime.identity_probe", "runtime.http_probe"):
        proc = sp.run([sys.executable, "-m", mod], capture_output=True, text=True)
        if proc.returncode != 0:
            return f"skipped（{mod} 不可达: {proc.stdout.strip()[:80] or proc.stderr.strip()[:80]}）"
    from runtime.observe import run as observe_run
    result = observe_run()
    return (f"observed 节点 {result['observed_stats']['nodes_touched']}, "
            f"差分 {result['anomalies_by_kind']}, "
            f"运行时发现 {result['findings']} 条")


def cmd_verify(out: Path = OUT):
    from bom.schema import load_bom
    from bom.diff import run_mutation_tests
    from graph.rules import run_envelope_rules, reconcile_ground_truth
    from graph.store import GraphStore
    from graph.validators import run_validators
    gs = GraphStore.load(out / "graph.enriched.json"
                         if (out / "graph.enriched.json").exists()
                         else out / "graph.json")
    bom = load_bom(out / "bom.json")
    findings = run_envelope_rules(gs, bom)
    checks = reconcile_ground_truth(findings)
    gt_pass = sum(1 for c in checks if c[1])
    muts = run_mutation_tests(bom)
    mut_pass = sum(1 for _, ok, _ in muts if ok)
    scan = json.loads((out / "scan.json").read_text(encoding="utf-8"))
    validation = run_validators(gs, scan)
    (out / "validator_findings.json").write_text(
        json.dumps(validation, ensure_ascii=False, indent=1), encoding="utf-8")
    results = {"包络校验标准答案": f"{gt_pass}/{len(checks)}",
               "变异差分": f"{mut_pass}/{len(muts)}",
               "完整性校验": f"{validation['total']} 项发现 {validation['by_rule'] or ''}"
                             if validation["total"] else "完整性校验: 全部通过"}
    if gt_pass < len(checks) or mut_pass < len(muts) or validation["total"]:
        results["失败明细"] = [c[0] for c in checks if not c[1]] + \
                              [m for m, ok, _ in muts if not ok] + \
                              [f"{f['rule']}:{f['target']}" for f in validation["findings"]]
    return results


def cmd_bench(root: Path, output: Path | None = None,
              generic_only: bool = False, oracle: Path | None = None) -> dict:
    from targets.bench import run
    target = root.name
    oracle = oracle or SOLUTION / "targets" / f"oracle-{target}.yaml"
    return run(target, root, oracle, output_dir=output, generic_only=generic_only)


def cmd_fused_bench(root: Path, output: Path | None = None,
                     generic_only: bool = False, oracle: Path | None = None) -> dict:
    """Run the native scanner benchmark and retain a fusion-bench artifact."""
    result = cmd_bench(root, output, generic_only, oracle)
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        (output / "fusion-bench.json").write_text(
            json.dumps({"schema": "fusion-bench-v1", "bench": result},
                       ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def cmd_peer_scan(root: Path, *, generic_only: bool = False,
                  timeout: float = 300.0) -> dict:
    """隔离执行队友 scanner；失败保留上一份 last-good 工件。"""
    from fusion.peer_runner import run_peer_scan
    result = run_peer_scan(root, generic_only=generic_only, timeout=timeout)
    payload = result.to_dict()
    if result.status != "ready":
        raise SystemExit(f"peer-scan 失败：{result.error}")
    return {"status": result.status, "job_id": result.job_id,
            "scanner_version": result.scanner_version,
            "duration_ms": result.duration_ms, "output": result.output}


# ---------------------------------------------------------------- 参数解析

def _flag(name: str) -> bool:
    return name in sys.argv


def _option_value(name: str, default=None):
    if name not in sys.argv:
        return default
    index = sys.argv.index(name)
    if index + 1 >= len(sys.argv):
        raise SystemExit(f"{name} 缺少参数值")
    return sys.argv[index + 1]


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd == "peer-scan":
        root = Path(_option_value("--root", str(RANGE)))
        try:
            timeout = float(_option_value("--timeout", "300"))
        except ValueError as exc:
            raise SystemExit("--timeout 必须是数字") from exc
        run_step("peer-scan", lambda: cmd_peer_scan(
            root, generic_only="--generic-only" in sys.argv, timeout=timeout))
    elif cmd in {"all", "scan", "graph", "bom", "import", "verify", "runtime", "bench", "fused-bench"}:
        root = Path(_option_value("--root", str(RANGE)))
        scan_output = Path(_option_value("--output", str(OUT)))
        generic_only = _flag("--generic-only")
        oracle_value = _option_value("--oracle")
        oracle = Path(oracle_value) if oracle_value else None
        steps = {"scan": lambda: cmd_scan(root, scan_output, generic_only),
                 "graph": lambda: cmd_graph(scan_output),
                 "bom": lambda: cmd_bom(scan_output),
                 "import": lambda: cmd_import(scan_output),
                 "verify": lambda: cmd_verify(scan_output),
                 "runtime": cmd_runtime,
                 "bench": lambda: cmd_bench(root, scan_output, generic_only, oracle),
                 "fused-bench": lambda: cmd_fused_bench(root, scan_output, generic_only, oracle)}
        if cmd == "all":
            for name in ("scan", "graph", "bom", "import", "runtime", "verify"):
                run_step(name, steps[name])
        else:
            result = run_step(cmd, steps[cmd])
            if cmd in {"bench", "fused-bench"}:
                if result.get("verdict") == "failed":
                    raise SystemExit(1)
                if result.get("verdict") != "passed":
                    raise SystemExit(2)
    elif cmd == "serve":
        print("启动 http://127.0.0.1:8080 ...")
        import uvicorn
        from server.app import app
        uvicorn.run(app, host="127.0.0.1", port=8080)
    else:
        print(__doc__)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
