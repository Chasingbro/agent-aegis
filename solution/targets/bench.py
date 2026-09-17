"""统一目标评测：独立扫描工件、严格匹配和诚实指标。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

SOLUTION = Path(__file__).resolve().parents[1]
ROOT = SOLUTION.parent
DEFAULT_OUT = SOLUTION / "out" / "bench"

CATEGORY_ALIASES = {
    "service": {"service", "component", "agent", "framework", "model", "datastore", "mcp"},
    "network-control": {"network-control", "network"},
    "plugin": {"plugin"},
    "datastore": {"datastore", "service"},
    "tool": {"tool", "mcp_tool"},
    "mcp": {"mcp", "mcp_server"},
    "mcp_server": {"mcp", "mcp_server"},
    "framework": {"framework", "component"},
    "model": {"model", "model_endpoint"},
    "skill": {"skill"},
    "agent": {"agent", "application"},
}


def normalize_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    return "-".join(text.replace("_", "-").replace(".", "-").split())


def normalize_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").lower().split(":", 1)[0]


def _load_yaml(path: Path) -> dict:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return value if isinstance(value, dict) else {}


def _load_oracle(path: Path) -> dict:
    raw = _load_yaml(path)
    # agent-asset-lab style: kind/id/source/expected
    if raw.get("assets") and any("kind" in item for item in raw["assets"] if isinstance(item, dict)):
        assets = [{"id": item.get("id", ""), "type": item.get("kind", ""),
                   "name": _id_name(item.get("id", "")),
                   "evidence": item.get("source", ""),
                   "expected": item.get("expected", True)}
                  for item in raw.get("assets", []) if isinstance(item, dict)]
        risks = [{"id": item.get("id", ""), "category": _risk_category(item.get("id", "")),
                  "evidence": item.get("evidence", ""), "expected": item.get("expected", True)}
                 for item in raw.get("risks", []) if isinstance(item, dict)]
        negatives = [{"id": item.get("id", ""), "expected_risk": item.get("expected_risk", True)}
                     for item in raw.get("benign", []) if isinstance(item, dict)]
        return {"target": raw.get("target", ""), "assets": assets, "risks": risks,
                "negative_samples": negatives, "thresholds": raw.get("thresholds", {})}
    # agent-scanner style: type/name/evidence and negative_samples
    assets = [{**item, "expected": item.get("expected", True)}
              for item in raw.get("assets", []) if isinstance(item, dict)]
    risks = [{**item, "expected": item.get("expected", True)}
             for item in raw.get("risks", []) if isinstance(item, dict)]
    negative = raw.get("negative_samples", {}) or {}
    negatives = [{"name": name, "forbidden_categories": negative.get("forbidden_categories", [])}
                 for name in negative.get("assets", [])]
    return {"target": raw.get("target", ""), "assets": assets, "risks": risks,
            "negative_samples": negatives, "thresholds": raw.get("thresholds", {})}


def _id_name(value: Any) -> str:
    text = str(value or "")
    return text.split(".")[-1].replace("-", " ")


def _risk_category(value: Any) -> str:
    text = str(value or "")
    return "malicious_mcp" if ".mcp." in text else "malicious_skill" if ".skill." in text else "finding"


def _detected_assets(scan: dict) -> list[dict]:
    result: list[dict] = []
    app = scan.get("app") or {}
    for agent in scan.get("agents", []):
        result.append({"type": "agent", "name": agent.get("name", ""), "path": agent.get("path", "")})
    for service in (scan.get("compose") or {}).get("services", []):
        if service.get("name") in {"asset-agent", "opspilot-app"}:
            result.append({"type": "agent", "name": service.get("name", ""), "path": "docker-compose.yml"})
    if app.get("source"):
        result.append({"type": "agent", "name": Path(app["source"]).stem,
                       "path": app["source"]})
    for service in (scan.get("compose") or {}).get("services", []):
        result.append({"type": service.get("category", "service"), "name": service.get("name", ""),
                       "path": "docker-compose.yml"})
    for server in scan.get("mcp_servers", []):
        result.append({"type": "mcp_server", "name": server.get("server", ""),
                       "path": server.get("source", "")})
        for tool in server.get("tools", []):
            result.append({"type": "mcp_tool", "name": tool.get("name", ""),
                           "path": server.get("source", ""), "server": server.get("server", "")})
    for skill in scan.get("skills", []):
        result.append({"type": "skill", "name": skill.get("name", ""), "path": skill.get("source", "")})
    for package in scan.get("packages", []):
        result.append({"type": "package", "name": package.get("name", ""),
                       "path": (package.get("sources") or [{}])[0].get("file", "")})
    for plugin in scan.get("plugins", []):
        result.append({"type": "plugin", "name": plugin.get("name", ""), "path": plugin.get("source", "")})
    for model in scan.get("models", []):
        result.append({"type": "model", "name": model.get("name", ""), "path": model.get("source", "")})
    for model in scan.get("model_files", []):
        result.append({"type": "model", "name": model.get("name", ""), "path": model.get("path", "")})
    for agent in scan.get("agents", []):
        result.append({"type": "agent", "name": agent.get("name", ""), "path": agent.get("path", "")})
    for flow in scan.get("flows", []):
        result.append({"type": "flow", "name": flow.get("name", ""), "path": flow.get("source", "")})
    networks = (scan.get("compose") or {}).get("networks", [])
    for network in networks:
        result.append({"type": "network", "name": network, "path": "docker-compose.yml"})
    return result


def _asset_match(expected: dict, detected: list[dict]) -> dict | None:
    expected_type = str(expected.get("type", ""))
    expected_name = normalize_name(expected.get("name", ""))
    allowed = CATEGORY_ALIASES.get(expected_type, {expected_type})
    candidates = [item for item in detected
                  if item.get("type") in allowed and normalize_name(item.get("name")) == expected_name]
    if candidates:
        return candidates[0]
    evidence = normalize_path(expected.get("evidence", ""))
    if evidence:
        candidates = [item for item in detected if item.get("type") in allowed and
                      evidence in normalize_path(item.get("path", ""))]
        if candidates:
            return candidates[0]
    return None


def _risk_match(expected: dict, risks: list[dict], detected: list[dict]) -> list[dict]:
    expected_category = str(expected.get("category", ""))
    if expected_category == "finding":
        expected_category = ""
    expected_types = set(expected.get("malicious_type_in", []) or [])
    names = {normalize_name(expected_name) for expected_name in expected.get("asset_any_of", []) or []}
    evidence = normalize_path(expected.get("evidence", ""))
    hits = []
    for risk in risks:
        category = str(risk.get("category", ""))
        if expected_category and category and category != expected_category:
            continue
        if expected_types and risk.get("malicious_type") not in expected_types:
            continue
        target = normalize_name(risk.get("target", ""))
        detail = normalize_path(risk.get("evidence", ""))
        name_match = not names or any(name in target for name in names)
        evidence_match = not evidence or evidence in detail or evidence in normalize_path(risk.get("detail", ""))
        if names and evidence and not (name_match or evidence_match):
            continue
        if names and not evidence and not name_match:
            continue
        if evidence and not names and not evidence_match:
            continue
        hits.append(risk)
    return hits


def run(target: str, root: Path, oracle_path: Path, *, output_dir: Path | None = None,
        generic_only: bool = False) -> dict:
    root = Path(root).expanduser().resolve()
    oracle_path = Path(oracle_path).expanduser().resolve()
    if not root.is_dir() or not oracle_path.is_file():
        return {"status": "not_measured", "target": target,
                "reason": "target/oracle missing", "available": False}
    out = Path(output_dir).expanduser().resolve() if output_dir else None
    temporary = False
    if out is None:
        out = Path(tempfile.mkdtemp(prefix="solution-bench-"))
        temporary = True
    out.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(SOLUTION / "collect_static.py"), str(root), "--output", str(out)]
    if generic_only:
        command.append("--generic-only")
    try:
        proc = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", shell=False, timeout=300)
    except subprocess.TimeoutExpired:
        return {"status": "not_measured", "target": target, "reason": "scanner timeout",
                "available": False}
    scan_path = out / "scan.json"
    if proc.returncode not in (0, 1) or not scan_path.is_file():
        return {"status": "not_measured", "target": target,
                "reason": (proc.stderr or proc.stdout)[-500:], "available": False}
    try:
        scan = json.loads(scan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "not_measured", "target": target, "reason": "invalid scan JSON",
                "available": False}
    if Path(scan.get("root", "")).resolve() != root:
        return {"status": "not_measured", "target": target,
                "reason": "scanner output target mismatch", "available": False}

    oracle = _load_oracle(oracle_path)
    expected_assets = [item for item in oracle["assets"] if item.get("expected", True)]
    expected_risks = [item for item in oracle["risks"] if item.get("expected", True)]
    detected_assets = _detected_assets(scan)
    asset_rows = []
    matched_asset_ids = set()
    for item in expected_assets:
        match = _asset_match(item, detected_assets)
        if match:
            matched_asset_ids.add(id(match))
        asset_rows.append({"expected": item, "detected": bool(match), "match": match or {}})
    derived_types = {"mcp_tool", "mcp_server", "package", "skill", "script", "config", "endpoint", "service",
                     "unknown", "component", "mcp", "flow", "network", "plugin", "agent", "model"}
    unexpected = [item for item in detected_assets if id(item) not in matched_asset_ids
                  and item.get("type") not in derived_types]
    risk_rows = []
    matched_risks = set()
    for item in expected_risks:
        hits = _risk_match(item, scan.get("risks", []), detected_assets)
        matched_risks.update(id(hit) for hit in hits)
        risk_rows.append({"expected": item, "detected": bool(hits), "matches": hits})
    extra = [risk for risk in scan.get("risks", []) if id(risk) not in matched_risks]
    false_positives = []
    for negative in oracle.get("negative_samples", []):
        name = normalize_name(negative.get("name") or negative.get("id", "").split(".")[-1])
        asset = next((item for item in detected_assets if normalize_name(item.get("name")) == name), None)
        if not asset:
            false_positives.append({"negative": negative, "reason": "negative asset not detected"})
            continue
        forbidden = set(negative.get("forbidden_categories") or {"malicious_skill", "malicious_mcp"})
        related = [risk for risk in scan.get("risks", [])
                   if name in normalize_name(risk.get("target")) and risk.get("category") in forbidden]
        false_positives.extend({"negative": negative, "risk": risk} for risk in related)

    asset_tp = sum(row["detected"] for row in asset_rows)
    risk_tp = sum(row["detected"] for row in risk_rows)
    asset_accuracy = _rate(asset_tp, asset_tp + len(unexpected))
    risk_accuracy = _rate(risk_tp, risk_tp + len(false_positives))
    checks = [
        _check("asset_miss_rate", _rate(len(expected_assets) - asset_tp, len(expected_assets)),
               oracle.get("thresholds", {}).get("asset_miss_rate_max", 0.05), "max"),
        _check("asset_accuracy", asset_accuracy,
               oracle.get("thresholds", {}).get("asset_accuracy_min", 0.99), "min"),
        _check("risk_accuracy", risk_accuracy,
               oracle.get("thresholds", {}).get("risk_accuracy_min", 0.95), "min"),
        _check("risk_miss_rate", _rate(len(expected_risks) - risk_tp, len(expected_risks)),
               oracle.get("thresholds", {}).get("risk_miss_rate_max", 0.05), "max"),
    ]
    statuses = {check["status"] for check in checks}
    verdict = "failed" if "failed" in statuses else "not_measured" if "not_measured" in statuses else "passed"
    result = {
        "available": True, "applicable": True,
        "status": "measured", "verdict": verdict, "passed": verdict == "passed",
        "target": target, "generic_only": generic_only, "output": str(out),
        "assets": {"expected": len(expected_assets), "matched": asset_tp,
                   "missing": [row["expected"] for row in asset_rows if not row["detected"]],
                   "unexpected": unexpected, "rows": asset_rows,
                   "recall": _rate(asset_tp, len(expected_assets)), "accuracy": asset_accuracy},
        "risks": {"expected": len(expected_risks), "matched": risk_tp,
                  "missing": [row["expected"] for row in risk_rows if not row["detected"]],
                  "false_positives": false_positives, "extra": extra, "rows": risk_rows,
                  "recall": _rate(risk_tp, len(expected_risks)), "accuracy": risk_accuracy},
        "checks": checks, "scanner_exit": proc.returncode,
    }
    if temporary:
        result["output_retained"] = False
    return result


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator <= 0 else round(numerator / denominator, 4)


def _check(name: str, value: float | None, threshold: float, mode: str) -> dict:
    if value is None:
        return {"name": name, "value": None, "threshold": threshold, "mode": mode,
                "passed": None, "status": "not_measured"}
    passed = value <= threshold if mode == "max" else value >= threshold
    return {"name": name, "value": value, "threshold": threshold, "mode": mode,
            "passed": passed, "status": "passed" if passed else "failed"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="目标级静态识别评测")
    parser.add_argument("target", help="目标注册名")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--generic-only", action="store_true")
    args = parser.parse_args(argv)
    result = run(args.target, args.root, args.oracle, output_dir=args.output,
                 generic_only=args.generic_only)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("verdict") == "passed" else 1 if result.get("verdict") == "failed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
