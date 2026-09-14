"""端到端 CLI：scan -> graph -> bom(build/score/controls) -> import -> verify -> serve

用法:
  python cli.py all [--root <靶场目录>]   # 全流程
  python cli.py serve                      # 启动前端 (127.0.0.1:8080)
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


def cmd_scan(root: Path):
    proc = subprocess.run([sys.executable, str(SOLUTION / "collect_static.py"), str(root)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-2000:]); print(proc.stderr[-2000:])
        raise SystemExit("scan 失败")
    tail = [l for l in proc.stdout.splitlines() if "对账结果" in l or "FAIL" in l]
    return "; ".join(tail) or "scan 完成"


def cmd_graph():
    sys.path.insert(0, str(SOLUTION))
    from graph.store import GraphStore, build_graph
    scan = json.loads((OUT / "scan.json").read_text(encoding="utf-8"))
    gs = build_graph(scan)
    gs.save(OUT / "graph.json")
    return f"{gs.g.number_of_nodes()} 节点 / {gs.g.number_of_edges()} 边"


def cmd_bom():
    from bom.schema import load_bom, dump_bom
    from bom.builder import build_bom
    from bom.scorer import score_bom
    from bom.controls import annotate_controls
    from graph.store import GraphStore
    gs = GraphStore.load(OUT / "graph.json")
    bom = annotate_controls(score_bom(build_bom(gs)))
    dump_bom(bom, OUT / "bom.json")
    scores = [f"{a['identity']['id']}={a['risk_assessment']['score']}"
              f"({a['risk_assessment']['quadrant']})" for a in bom["agents"]]
    return "; ".join(scores)


def cmd_import():
    from bom.schema import load_bom
    from bom.importer import import_bom, round_trip_check
    from graph.store import GraphStore
    gs = GraphStore.load(OUT / "graph.json")
    bom = load_bom(OUT / "bom.json")
    stats = import_bom(gs, bom)
    rt = round_trip_check(gs, bom)
    gs.save(OUT / "graph.enriched.json")
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


def cmd_verify():
    from bom.schema import load_bom
    from bom.diff import run_mutation_tests
    from graph.rules import run_envelope_rules, reconcile_ground_truth
    from graph.store import GraphStore
    from graph.validators import run_validators
    gs = GraphStore.load(OUT / "graph.enriched.json"
                         if (OUT / "graph.enriched.json").exists()
                         else OUT / "graph.json")
    bom = load_bom(OUT / "bom.json")
    findings = run_envelope_rules(gs, bom)
    checks = reconcile_ground_truth(findings)
    gt_pass = sum(1 for c in checks if c[1])
    muts = run_mutation_tests(bom)
    mut_pass = sum(1 for _, ok, _ in muts if ok)
    scan = json.loads((OUT / "scan.json").read_text(encoding="utf-8"))
    validation = run_validators(gs, scan)
    (OUT / "validator_findings.json").write_text(
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


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd in {"all", "scan", "graph", "bom", "import", "verify", "runtime"}:
        root = RANGE
        if "--root" in sys.argv:
            root = Path(sys.argv[sys.argv.index("--root") + 1])
        steps = {"scan": lambda: cmd_scan(root), "graph": cmd_graph,
                 "bom": cmd_bom, "import": cmd_import, "verify": cmd_verify,
                 "runtime": cmd_runtime}
        if cmd == "all":
            for name in ("scan", "graph", "bom", "import", "runtime", "verify"):
                run_step(name, steps[name])
        else:
            run_step(cmd, steps[cmd])
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
