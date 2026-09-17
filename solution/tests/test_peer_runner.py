"""P0：队友扫描器隔离 runner、路径约束与 last-good 回归。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SOLUTION = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOLUTION))

from fusion import peer_runner


def _write_artifacts(output: Path, target: Path, *, bench_available: bool = True) -> None:
    assets = [{"id": "agent:test", "type": "agent", "name": "test", "path": "agent.py"}]
    output.mkdir(parents=True, exist_ok=True)
    (output / "assets.json").write_text(json.dumps({"assets": assets}), encoding="utf-8")
    (output / "graph.json").write_text(json.dumps({"nodes": assets, "edges": []}), encoding="utf-8")
    (output / "risks.json").write_text(json.dumps({"risks": []}), encoding="utf-8")
    (output / "summary.json").write_text(json.dumps({"summary": {
        "target": str(target), "tool_version": "0.2.0"
    }}), encoding="utf-8")
    bench = {"available": True, "status": "passed", "checks": []} if bench_available else {
        "available": False, "reason": "no matching baseline"
    }
    (output / "bench.json").write_text(json.dumps({"bench": bench}), encoding="utf-8")


@pytest.fixture
def runner_paths(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    target = workspace / "target"
    scanner = workspace / "reference" / "agent-scanner" / "agent-scanner"
    peer_root = workspace / "solution" / "out" / "peer"
    python = workspace / "python.exe"
    target.mkdir(parents=True)
    scanner.mkdir(parents=True)
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(peer_runner, "WORKSPACE_ROOT", workspace.resolve())
    monkeypatch.setattr(peer_runner, "SCANNER_ROOT", scanner.resolve())
    monkeypatch.setattr(peer_runner, "DEFAULT_PEER_ROOT", peer_root.resolve())
    return target, scanner, peer_root, python


def test_success_uses_isolated_job_and_switches_current(runner_paths, monkeypatch):
    target, scanner, peer_root, python = runner_paths
    captured = {}

    def fake_run(command, **kwargs):
        captured.update(command=command, kwargs=kwargs)
        output = Path(command[command.index("--output") + 1])
        _write_artifacts(output, target)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(peer_runner.subprocess, "run", fake_run)
    result = peer_runner.run_peer_scan(
        target, peer_root=peer_root, scanner_root=scanner,
        python_executable=python, generic_only=True,
    )

    assert result.status == "ready"
    assert result.job_id and Path(result.output).parent.name == "jobs"
    assert captured["command"][-1] == "--generic-only"
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["cwd"] == scanner.resolve()
    current = json.loads((peer_root / "current.json").read_text(encoding="utf-8"))
    assert current["job_id"] == result.job_id
    assert peer_runner.current_peer_output(peer_root) == Path(result.output).resolve()


def test_unknown_target_bench_is_valid(runner_paths, monkeypatch):
    target, scanner, peer_root, python = runner_paths

    def fake_run(command, **kwargs):
        _write_artifacts(Path(command[command.index("--output") + 1]), target,
                         bench_available=False)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(peer_runner.subprocess, "run", fake_run)
    result = peer_runner.run_peer_scan(target, peer_root=peer_root,
                                       scanner_root=scanner, python_executable=python)
    assert result.status == "ready"


def test_timeout_keeps_last_good_pointer(runner_paths, monkeypatch):
    target, scanner, peer_root, python = runner_paths
    old_job = peer_root / "jobs" / "old"
    _write_artifacts(old_job, target)
    peer_root.mkdir(parents=True, exist_ok=True)
    pointer = {"job_id": "old", "path": str(old_job), "target": str(target)}
    (peer_root / "current.json").write_text(json.dumps(pointer), encoding="utf-8")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(peer_runner.subprocess, "run", timeout)
    result = peer_runner.run_peer_scan(target, peer_root=peer_root,
                                       scanner_root=scanner, python_executable=python,
                                       timeout=1)
    assert result.status == "failed" and result.reason == "timeout"
    assert result.last_good == "old"
    assert json.loads((peer_root / "current.json").read_text())["job_id"] == "old"


def test_nonzero_and_bad_artifacts_do_not_switch_current(runner_paths, monkeypatch):
    target, scanner, peer_root, python = runner_paths

    monkeypatch.setattr(peer_runner.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=2, stdout="", stderr="missing dependency"))
    failed = peer_runner.run_peer_scan(target, peer_root=peer_root,
                                       scanner_root=scanner, python_executable=python)
    assert failed.reason == "scanner_failed"
    assert not (peer_root / "current.json").exists()

    monkeypatch.setattr(peer_runner.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout="", stderr=""))
    invalid = peer_runner.run_peer_scan(target, peer_root=peer_root,
                                        scanner_root=scanner, python_executable=python)
    assert invalid.reason == "invalid_artifacts"
    assert not (peer_root / "current.json").exists()


def test_path_validation_rejects_outside_target_and_output_inside_target(runner_paths):
    target, scanner, peer_root, python = runner_paths
    outside = target.parents[1] / "outside"
    outside.mkdir()
    with pytest.raises(peer_runner.PeerScanError, match="工作区"):
        peer_runner.validate_paths(target=outside, peer_root=peer_root,
                                   scanner_root=scanner, python_executable=python)

    peer_runner.DEFAULT_PEER_ROOT = target / "out" / "peer"
    with pytest.raises(peer_runner.PeerScanError, match="扫描目标内"):
        peer_runner.validate_paths(target=target, peer_root=target / "out" / "peer",
                                   scanner_root=scanner, python_executable=python)


def test_existing_lock_does_not_overwrite_running_status(runner_paths):
    target, scanner, peer_root, python = runner_paths
    peer_root.mkdir(parents=True)
    (peer_root / ".scan.lock").write_text("busy", encoding="utf-8")
    running = {"status": "running", "job_id": "other"}
    (peer_root / "status.json").write_text(json.dumps(running), encoding="utf-8")

    result = peer_runner.run_peer_scan(target, peer_root=peer_root,
                                       scanner_root=scanner, python_executable=python)
    assert result.reason == "scan_in_progress"
    assert json.loads((peer_root / "status.json").read_text()) == running
