import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOLUTION = ROOT / "solution"
sys.path.insert(0, str(SOLUTION))


def test_holdout_collectors_cover_generic_layout():
    from collect_static import (collect_compose, collect_flows, collect_mcp_code,
                                collect_models, collect_plugins, collect_skills)
    target = ROOT / "test-ranges" / "agent-asset-lab"
    compose = collect_compose(target)
    servers = collect_mcp_code(target, compose)
    assert len(compose["services"]) == 12
    assert len(compose["networks"]) == 2
    assert len(servers) == 6
    assert any(tool["hidden"] for server in servers for tool in server["tools"])
    assert {skill["name"] for skill in collect_skills(target)} == {"meeting-digest", "release-notes"}
    assert collect_plugins(target)[0]["name"] == "export-plugin"
    assert collect_models(target, compose)[0]["name"] == "sim-model-v1"
    assert collect_flows(target)[0]["name"] == "support-flow"


def test_holdout_bench_is_measured():
    from targets.bench import run
    target = ROOT / "test-ranges" / "agent-asset-lab"
    oracle = SOLUTION / "targets" / "oracle-agent-asset-lab.yaml"
    result = run("agent-asset-lab", target, oracle)
    assert result["status"] == "measured"
    assert result["verdict"] in {"passed", "failed"}
    assert result["assets"]["recall"] == 1.0
    assert result["risks"]["recall"] == 1.0


def test_missing_target_is_not_measured(tmp_path):
    from targets.bench import run
    result = run("missing", tmp_path / "missing", tmp_path / "oracle.yaml")
    assert result["status"] == "not_measured"
