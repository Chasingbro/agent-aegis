#!/usr/bin/env python3
"""
score.py —— 资产识别评测脚本（P0.3）

用法:
    python score.py <system_output.json> [--gt ground_truth.yaml]

system_output.json 格式（采集器+规则引擎的最终输出契约）:
{
  "inventory": [ {"type": "MCPServer", "key": "mcp-notes-sync", "attrs": {...}}, ... ],
  "findings":  [ {"class": "malicious-component", "target": "mcp-notes-sync",
                  "rule_id": "hidden-tool", "evidence": "...", "severity": "high"}, ... ]
}

匹配规则:
  - 盘点: 按 (type, key) 精确匹配；services 以 type=DockerService 参与同一匹配
  - 风险: 按 (class, target) 匹配；target 兼容 "skill:xxx" 与 "xxx" 两种写法
  - 诱饵: 任何命中诱饵目标的 finding 计为误报并单独列出
  - 重复项: 先按匹配键去重再去匹配
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent


def load_ground_truth(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_output(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "inventory" not in data or "findings" not in data:
        sys.exit(f"[format] 输出必须包含 'inventory' 与 'findings' 两个数组字段: {path}")
    data["inventory"] = data.get("inventory") or []
    data["findings"] = data.get("findings") or []
    return data


def norm_target(t: str) -> str:
    """oracle 风险 target 兼容: 'skill:meeting-summary' / 'meeting-summary' 视为同键"""
    return t[6:] if t.startswith("skill:") else t


def dedupe(items: list[dict], keyfields: tuple[str, ...]) -> tuple[list[dict], int]:
    seen, out, dup = set(), [], 0
    for it in items:
        k = tuple(it.get(f) for f in keyfields)
        if k in seen:
            dup += 1
            continue
        seen.add(k)
        out.append(it)
    return out, dup


def score_inventory(gt: dict, out: dict) -> dict:
    vocab_types = set(gt["vocab"]["asset_types"])
    # assets 段按各自 type 计；services 段统一按 DockerService 计
    expected: dict[tuple[str, str], dict] = {}
    for a in gt["assets"]:
        expected[(a["type"], a["key"])] = a
    for s in gt["services"]:
        expected[("DockerService", s["key"])] = s

    got_list, dup = dedupe(out["inventory"], ("type", "key"))
    got: dict[tuple[str, str], dict] = {}
    invalid_type = []
    for it in got_list:
        if it.get("type") not in vocab_types:
            invalid_type.append(it)
            continue
        got[(it["type"], it["key"])] = it

    matched = set(got) & set(expected)
    fn = set(expected) - set(got)          # 漏报: 标准答案里有、系统没报
    fp = set(got) - set(expected)          # 误报: 系统多报的资产

    tp = len(matched)
    prec = tp / (tp + len(fp)) if tp + len(fp) else 0.0
    rec = tp / (tp + len(fn)) if tp + len(fn) else 0.0

    by_type: dict[str, dict] = {}
    for typ in vocab_types:
        exp_n = sum(1 for (t, _) in expected if t == typ)
        got_n = sum(1 for (t, _) in matched if t == typ)
        by_type[typ] = {"expected": exp_n, "found": got_n, "missing": exp_n - got_n}

    return {
        "tp": tp, "fp": len(fp), "fn": len(fn), "dup": dup,
        "precision": prec, "recall": rec, "miss_rate": 1 - rec,
        "fn_items": sorted(fn), "fp_items": sorted(fp),
        "invalid_type": invalid_type, "by_type": by_type,
    }


def score_risks(gt: dict, out: dict) -> dict:
    vocab_classes = set(gt["vocab"]["risk_classes"])
    exp: dict[tuple[str, str], dict] = {}
    for r in gt["risks"]:
        exp[(r["class"], norm_target(r["target"]))] = r
    decoy_targets = {norm_target(d["target"]) for d in gt["decoys"]}

    got_list, dup = dedupe(out["findings"], ("class", "target"))
    got, invalid_class, decoy_hits = {}, [], []
    for it in got_list:
        cls, tgt = it.get("class"), norm_target(str(it.get("target", "")))
        if cls not in vocab_classes:
            invalid_class.append(it)
            continue
        if tgt in decoy_targets:
            decoy_hits.append(it)
            continue
        got[(cls, tgt)] = it

    matched = set(got) & set(exp)
    fn = set(exp) - set(got)
    fp = set(got) - set(exp)

    tp = len(matched)
    prec = tp / (tp + len(fp) + len(decoy_hits)) if (tp + len(fp) + len(decoy_hits)) else 0.0
    rec = tp / (tp + len(fn)) if tp + len(fn) else 0.0

    return {
        "tp": tp, "fp": len(fp), "fn": len(fn), "dup": dup,
        "decoy_hits": decoy_hits, "precision": prec, "recall": rec, "miss_rate": 1 - rec,
        "fn_items": sorted((f"{c}/{t}" for c, t in fn)),
        "fp_items": sorted((f"{c}/{t}" for c, t in fp)),
        "invalid_class": invalid_class,
    }


def verdict(gt: dict, inv: dict, rsk: dict) -> list[tuple[str, bool, str]]:
    t = gt["targets"]
    return [
        ("盘点漏报率 < 5%", inv["miss_rate"] < t["inventory_miss_rate_max"],
         f"实际 {inv['miss_rate']:.1%}"),
        ("盘点准确率 ≥ 99%", inv["precision"] >= t["inventory_precision_min"],
         f"实际 {inv['precision']:.1%}"),
        ("风险准确率 ≥ 95%", rsk["precision"] >= t["risk_precision_min"],
         f"实际 {rsk['precision']:.1%}"),
        ("风险漏报率 < 5%", rsk["miss_rate"] < t["risk_miss_rate_max"],
         f"实际 {rsk['miss_rate']:.1%}"),
    ]


def main() -> None:
    ap = argparse.ArgumentParser(description="资产识别评测")
    ap.add_argument("output", help="系统输出 JSON 文件路径")
    ap.add_argument("--gt", default=str(HERE / "ground_truth.yaml"), help="标准答案 YAML")
    ap.add_argument("--quiet", action="store_true", help="只打印汇总行")
    args = ap.parse_args()

    gt = load_ground_truth(Path(args.gt))
    out = load_output(Path(args.output))
    inv, rsk = score_inventory(gt, out), score_risks(gt, out)

    if not args.quiet:
        print("=" * 64)
        print("资产盘点 —— 按类型")
        print(f"{'类型':<22}{'标准':>4}{'发现':>4}{'漏':>4}")
        for typ, s in inv["by_type"].items():
            if s["expected"]:
                print(f"{typ:<22}{s['expected']:>4}{s['found']:>4}{s['missing']:>4}")
        print("-" * 64)
        print(f"TP={inv['tp']}  FP={inv['fp']}  FN={inv['fn']}  重复={inv['dup']}")
        print(f"准确率(precision)={inv['precision']:.1%}  漏报率={inv['miss_rate']:.1%}")
        if inv["invalid_type"]:
            print(f"[format] 非法资产类型 {len(inv['invalid_type'])} 项(已忽略): "
                  + ", ".join(str(i.get('type')) for i in inv["invalid_type"][:5]))
        if inv["fn_items"]:
            print("漏报项: " + ", ".join(f"{t}/{k}" for t, k in inv["fn_items"]))
        if inv["fp_items"]:
            print("多报项: " + ", ".join(f"{t}/{k}" for t, k in inv["fp_items"]))

        print("=" * 64)
        print("风险识别")
        print(f"TP={rsk['tp']}  FP={rsk['fp']}  FN={rsk['fn']}  重复={rsk['dup']}")
        print(f"准确率(precision)={rsk['precision']:.1%}  漏报率={rsk['miss_rate']:.1%}")
        if rsk["decoy_hits"]:
            print(f"!! 诱饵误报 {len(rsk['decoy_hits'])} 项: "
                  + ", ".join(f"{d['class']}@{d['target']}" for d in rsk["decoy_hits"]))
        if rsk["fn_items"]:
            print("漏报项: " + ", ".join(rsk["fn_items"]))
        if rsk["fp_items"]:
            print("多报项: " + ", ".join(rsk["fp_items"]))
        if rsk["invalid_class"]:
            print(f"[format] 非法风险类别 {len(rsk['invalid_class'])} 项(已忽略)")

    print("=" * 64)
    all_pass = True
    for name, ok, actual in verdict(gt, inv, rsk):
        mark = "PASS" if ok else "FAIL"
        all_pass &= ok
        print(f"[{mark}] {name}  ({actual})")
    print("总体: " + ("达标 ✅" if all_pass else "未达标 ❌"))
    sys.exit(0)


if __name__ == "__main__":
    main()
