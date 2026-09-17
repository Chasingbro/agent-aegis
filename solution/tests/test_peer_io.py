"""P1 严格 peer 工件读取状态回归。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SOLUTION = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOLUTION))


def _valid_files(root: Path, target: Path) -> None:
    asset = {"id": "agent:test", "type": "agent", "name": "test"}
    root.mkdir(parents=True)
    (root / "assets.json").write_text(json.dumps({"assets": [asset]}), encoding="utf-8")
    (root / "graph.json").write_text(json.dumps({"nodes": [asset], "edges": []}), encoding="utf-8")
    (root / "risks.json").write_text(json.dumps({"risks": []}), encoding="utf-8")
    (root / "summary.json").write_text(json.dumps({"summary": {
        "target": str(target), "tool_version": "0.2.0"
    }}), encoding="utf-8")
    (root / "bench.json").write_text(json.dumps({"bench": {
        "available": False, "reason": "no baseline"
    }}), encoding="utf-8")


def test_loader_distinguishes_ready_and_invalid(tmp_path):
    from fusion.peer_io import load_peer_result

    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "peer"
    _valid_files(out, target)
    ready = load_peer_result(out)
    assert ready.status == "ready"
    assert len(ready.payload["assets"]) == 1

    (out / "risks.json").write_text("not json", encoding="utf-8")
    invalid = load_peer_result(out)
    assert invalid.status == "invalid"
    assert invalid.reason == "invalid_artifacts"
    assert not invalid.payload


def test_current_pointer_target_detects_tampered_summary(tmp_path, monkeypatch):
    from fusion import peer_io, peer_runner

    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "peer-root"
    job = root / "jobs" / "good"
    _valid_files(job, target)
    root.mkdir(parents=True, exist_ok=True)
    (root / "current.json").write_text(json.dumps({
        "job_id": "good", "path": str(job), "target": str(target)
    }), encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    summary = json.loads((job / "summary.json").read_text(encoding="utf-8"))
    summary["summary"]["target"] = str(other)
    (job / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    monkeypatch.setattr(peer_runner, "DEFAULT_PEER_ROOT", root)
    monkeypatch.setattr(peer_io, "DEFAULT_PEER_ROOT", root)

    result = peer_io.load_peer_result()
    assert result.status == "invalid"
    assert result.reason == "invalid_artifacts"
    assert "summary.target" in result.error


def test_loader_reports_missing_explicit_directory(tmp_path):
    from fusion.peer_io import load_peer_result

    result = load_peer_result(tmp_path / "missing")
    assert result.status == "invalid"
    assert result.reason == "artifact_dir_missing"
