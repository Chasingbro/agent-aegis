import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "solution" / "cli.py"


def test_fused_bench_keeps_target_outputs_isolated(tmp_path):
    sim_out = tmp_path / "sim"
    lab_out = tmp_path / "lab"
    sim = subprocess.run(
        [sys.executable, str(CLI), "fused-bench", "--root",
         str(ROOT / "reference" / "agent-scanner" / "simulated-target"),
         "--oracle", str(ROOT / "reference" / "agent-scanner" / "agent-scanner" / "bench" / "simulated-target.yaml"),
         "--output", str(sim_out), "--generic-only"],
        cwd=str(ROOT), capture_output=True, text=True)
    lab = subprocess.run(
        [sys.executable, str(CLI), "fused-bench", "--root",
         str(ROOT / "test-ranges" / "agent-asset-lab"),
         "--oracle", str(ROOT / "solution" / "targets" / "oracle-agent-asset-lab.yaml"),
         "--output", str(lab_out), "--generic-only"],
        cwd=str(ROOT), capture_output=True, text=True)
    assert sim.returncode == 0, sim.stderr
    assert lab.returncode == 0, lab.stderr
    sim_doc = json.loads((sim_out / "fusion-bench.json").read_text(encoding="utf-8"))
    lab_doc = json.loads((lab_out / "fusion-bench.json").read_text(encoding="utf-8"))
    assert sim_doc["bench"]["target"] == "simulated-target"
    assert lab_doc["bench"]["target"] == "agent-asset-lab"
    assert sim_doc["bench"]["output"] != lab_doc["bench"]["output"]
    assert (sim_out / "scan.json").exists()
    assert (lab_out / "scan.json").exists()


def test_cli_bench_missing_oracle_returns_not_measured(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(CLI), "bench", "--root", str(ROOT / "test-ranges" / "agent-asset-lab"),
         "--oracle", str(tmp_path / "missing.yaml"), "--output", str(tmp_path / "out")],
        cwd=str(ROOT), capture_output=True, text=True)
    assert proc.returncode == 2
