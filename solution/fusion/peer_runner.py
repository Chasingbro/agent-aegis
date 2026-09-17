"""队友 agent-scanner 的隔离执行与 last-good 工件管理。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SOLUTION_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = SOLUTION_ROOT.parent.resolve()
SCANNER_ROOT = WORKSPACE_ROOT / "reference" / "agent-scanner" / "agent-scanner"
DEFAULT_PEER_ROOT = SOLUTION_ROOT / "out" / "peer"
REQUIRED_ARTIFACTS = (
    "assets.json",
    "graph.json",
    "risks.json",
    "summary.json",
    "bench.json",
)


@dataclass
class PeerScanResult:
    status: str
    job_id: str | None
    target: str
    output: str | None
    started_at: str
    finished_at: str
    duration_ms: float
    generic_only: bool
    scanner_version: str | None = None
    reason: str | None = None
    error: str | None = None
    last_good: str | None = None
    returncode: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PeerScanError(RuntimeError):
    """可归类并展示给 CLI/前端的扫描失败。"""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def run_peer_scan(
    target: str | Path,
    *,
    peer_root: str | Path = DEFAULT_PEER_ROOT,
    scanner_root: str | Path = SCANNER_ROOT,
    python_executable: str | Path | None = None,
    generic_only: bool = False,
    timeout: float = 300.0,
) -> PeerScanResult:
    """在独立 job 目录运行扫描；仅校验成功后原子更新 current.json。"""
    started = _now()
    started_clock = time.monotonic()
    root = Path(peer_root).expanduser().absolute()
    current_before = _read_current(root)
    job_id: str | None = None
    job_dir: Path | None = None

    try:
        resolved_target, resolved_scanner, resolved_python, resolved_root = validate_paths(
            target=target,
            peer_root=root,
            scanner_root=scanner_root,
            python_executable=python_executable,
        )
        if timeout <= 0:
            raise PeerScanError("invalid_timeout", "扫描超时必须大于 0 秒")

        resolved_root.mkdir(parents=True, exist_ok=True)
        with _PeerLock(resolved_root / ".scan.lock"):
            job_id = _job_id()
            job_dir = resolved_root / "jobs" / job_id
            job_dir.mkdir(parents=True, exist_ok=False)
            running = PeerScanResult(
                status="running", job_id=job_id, target=str(resolved_target),
                output=str(job_dir), started_at=started, finished_at="", duration_ms=0,
                generic_only=generic_only, last_good=_current_job(current_before),
            )
            _write_json_atomic(resolved_root / "status.json", running.to_dict())

            command = [
                str(resolved_python), "-m", "agent_scanner", "scan",
                "--target", str(resolved_target), "--output", str(job_dir),
            ]
            if generic_only:
                command.append("--generic-only")
            try:
                process = subprocess.run(
                    command,
                    cwd=resolved_scanner,
                    env=_scanner_environment(resolved_scanner),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    shell=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise PeerScanError("timeout", f"agent-scanner 超过 {timeout:g} 秒未完成") from exc
            except OSError as exc:
                raise PeerScanError("scanner_start_failed", f"无法启动 agent-scanner：{exc}") from exc

            if process.returncode != 0:
                detail = (process.stderr or process.stdout or "无诊断输出").strip()[-1000:]
                raise PeerScanError(
                    "scanner_failed",
                    f"agent-scanner 退出码 {process.returncode}：{detail}",
                )

            metadata = validate_artifacts(job_dir, resolved_target)
            pointer = {
                "job_id": job_id,
                "path": str(job_dir),
                "target": str(resolved_target),
                "scanner_version": metadata["scanner_version"],
                "generic_only": generic_only,
                "updated_at": _now(),
            }
            _write_json_atomic(resolved_root / "current.json", pointer)
            result = PeerScanResult(
                status="ready", job_id=job_id, target=str(resolved_target),
                output=str(job_dir), started_at=started, finished_at=_now(),
                duration_ms=_elapsed_ms(started_clock), generic_only=generic_only,
                scanner_version=metadata["scanner_version"], last_good=job_id,
                returncode=process.returncode,
            )
            _write_json_atomic(resolved_root / "status.json", result.to_dict())
            return result
    except PeerScanError as exc:
        result = PeerScanResult(
            status="invalid" if exc.reason.startswith("invalid_") else "failed",
            job_id=job_id, target=str(target), output=str(job_dir) if job_dir else None,
            started_at=started, finished_at=_now(), duration_ms=_elapsed_ms(started_clock),
            generic_only=generic_only, reason=exc.reason, error=str(exc),
            last_good=_current_job(current_before),
        )
        if exc.reason != "scan_in_progress":
            _best_effort_status(root, result)
        return result


def validate_paths(
    *,
    target: str | Path,
    peer_root: str | Path,
    scanner_root: str | Path,
    python_executable: str | Path | None,
) -> tuple[Path, Path, Path, Path]:
    """约束扫描目标和输出都在预期边界内，拒绝符号链接入口。"""
    raw_target = Path(target).expanduser().absolute()
    if not raw_target.exists():
        raise PeerScanError("invalid_target", f"目标目录不存在：{raw_target}")
    if not raw_target.is_dir():
        raise PeerScanError("invalid_target", f"目标路径不是目录：{raw_target}")
    _reject_symlink(raw_target, "目标目录")
    resolved_target = raw_target.resolve()
    if not _is_within(resolved_target, WORKSPACE_ROOT):
        raise PeerScanError("invalid_target", f"目标目录必须位于工作区内：{WORKSPACE_ROOT}")

    raw_scanner = Path(scanner_root).expanduser().absolute()
    expected_scanner = SCANNER_ROOT.absolute()
    if raw_scanner != expected_scanner:
        raise PeerScanError("invalid_scanner_root", f"扫描器目录必须固定为：{expected_scanner}")
    if not raw_scanner.is_dir():
        raise PeerScanError("invalid_scanner_root", f"扫描器目录不存在：{raw_scanner}")
    _reject_symlink(raw_scanner, "扫描器目录")
    resolved_scanner = raw_scanner.resolve()

    raw_root = Path(peer_root).expanduser().absolute()
    _reject_existing_symlink_components(raw_root, "输出目录")
    resolved_root = raw_root.resolve(strict=False)
    allowed_output = DEFAULT_PEER_ROOT.resolve(strict=False)
    if not _is_within(resolved_root, allowed_output):
        raise PeerScanError("invalid_output", f"输出目录必须位于：{allowed_output}")
    if resolved_root == resolved_target or _is_within(resolved_root, resolved_target):
        raise PeerScanError("invalid_output", "输出目录不能等于或位于扫描目标内")

    configured_python = python_executable or os.environ.get("AGENT_SCANNER_PYTHON") or sys.executable
    raw_python = Path(configured_python).expanduser().absolute()
    if not raw_python.exists() or not raw_python.is_file():
        raise PeerScanError("invalid_python", f"Python 解释器不存在：{raw_python}")
    _reject_symlink(raw_python, "Python 解释器")
    return resolved_target, resolved_scanner, raw_python.resolve(), resolved_root


def validate_artifacts(job_dir: Path, target: Path) -> dict[str, Any]:
    """严格校验五个核心 JSON 及其引用完整性。"""
    documents: dict[str, dict[str, Any]] = {}
    for name in REQUIRED_ARTIFACTS:
        path = job_dir / name
        if not path.is_file():
            raise PeerScanError("invalid_artifacts", f"缺少核心工件：{name}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PeerScanError("invalid_artifacts", f"工件无法解析：{name}") from exc
        if not isinstance(value, dict):
            raise PeerScanError("invalid_artifacts", f"工件顶层必须是对象：{name}")
        documents[name] = value

    assets = documents["assets.json"].get("assets")
    edges = documents["graph.json"].get("edges")
    risks = documents["risks.json"].get("risks")
    summary = documents["summary.json"].get("summary")
    bench = documents["bench.json"].get("bench")
    if not isinstance(assets, list) or not isinstance(edges, list) or not isinstance(risks, list):
        raise PeerScanError("invalid_artifacts", "assets/edges/risks 必须是数组")
    if not isinstance(summary, dict) or not isinstance(bench, dict):
        raise PeerScanError("invalid_artifacts", "summary/bench 必须是对象")

    asset_ids = set()
    for asset in assets:
        if not isinstance(asset, dict) or not all(asset.get(key) for key in ("id", "type", "name")):
            raise PeerScanError("invalid_artifacts", "资产缺少 id/type/name")
        asset_ids.add(asset["id"])
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("src") not in asset_ids or edge.get("dst") not in asset_ids:
            raise PeerScanError("invalid_artifacts", f"关系边引用未知资产：{edge}")
    for risk in risks:
        if not isinstance(risk, dict) or risk.get("asset_id") not in asset_ids:
            raise PeerScanError("invalid_artifacts", f"风险引用未知资产：{risk}")
        if any(asset_id not in asset_ids for asset_id in risk.get("related_asset_ids", [])):
            raise PeerScanError("invalid_artifacts", f"风险关联未知资产：{risk.get('id', '')}")

    reported_target = summary.get("target")
    try:
        target_matches = bool(reported_target) and Path(reported_target).resolve() == target.resolve()
    except (OSError, TypeError):
        target_matches = False
    if not target_matches:
        raise PeerScanError("invalid_artifacts", "summary.target 与请求目标不一致")
    scanner_version = summary.get("tool_version")
    if not scanner_version:
        raise PeerScanError("invalid_artifacts", "summary.tool_version 缺失")
    if "available" not in bench:
        raise PeerScanError("invalid_artifacts", "bench 缺少 available 契约")
    if bench.get("available"):
        if bench.get("status") not in {"passed", "failed", "not_measured"}:
            raise PeerScanError("invalid_artifacts", "bench.status 非法")
        if not isinstance(bench.get("checks"), list):
            raise PeerScanError("invalid_artifacts", "bench.checks 必须是数组")
    elif not bench.get("reason"):
        raise PeerScanError("invalid_artifacts", "不可用 bench 必须包含 reason")
    return {"scanner_version": str(scanner_version), "asset_count": len(assets),
            "edge_count": len(edges), "risk_count": len(risks)}


def read_peer_status(peer_root: str | Path = DEFAULT_PEER_ROOT) -> dict[str, Any]:
    root = Path(peer_root)
    status = _read_json(root / "status.json")
    if status:
        return status
    current = _read_current(root)
    return {"status": "ready", **current} if current else {"status": "not_run"}


def current_peer_pointer(peer_root: str | Path = DEFAULT_PEER_ROOT) -> dict[str, Any]:
    """返回通过目录边界检查的 current 指针；损坏或越界时返回空对象。"""
    root = Path(peer_root)
    pointer = _read_current(root)
    path = pointer.get("path") if pointer else None
    target = pointer.get("target") if pointer else None
    if not path or not target:
        return {}
    candidate = Path(path).resolve()
    allowed = root.resolve(strict=False)
    if not candidate.is_dir() or not _is_within(candidate, allowed):
        return {}
    return {**pointer, "path": str(candidate)}


def current_peer_output(peer_root: str | Path = DEFAULT_PEER_ROOT) -> Path | None:
    pointer = current_peer_pointer(peer_root)
    return Path(pointer["path"]) if pointer else None


def _scanner_environment(scanner_root: Path) -> dict[str, str]:
    allowed = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP", "HOME", "USERPROFILE")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update({"PYTHONPATH": str(scanner_root), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"})
    return env


def _reject_symlink(path: Path, label: str) -> None:
    if path.is_symlink():
        raise PeerScanError(f"invalid_{'target' if label == '目标目录' else 'path'}", f"{label}不能是符号链接：{path}")


def _reject_existing_symlink_components(path: Path, label: str) -> None:
    cursor = path
    while not cursor.exists() and cursor.parent != cursor:
        cursor = cursor.parent
    if cursor.is_symlink():
        raise PeerScanError("invalid_output", f"{label}的已有父目录不能是符号链接：{cursor}")


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_current(root: Path) -> dict[str, Any]:
    return _read_json(root / "current.json")


def _current_job(pointer: dict[str, Any]) -> str | None:
    return pointer.get("job_id") if pointer else None


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def _best_effort_status(root: Path, result: PeerScanResult) -> None:
    try:
        if _is_within(root.resolve(strict=False), DEFAULT_PEER_ROOT.resolve(strict=False)):
            _write_json_atomic(root / "status.json", result.to_dict())
    except OSError:
        pass


def _job_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _elapsed_ms(started: float) -> float:
    return round((time.monotonic() - started) * 1000, 3)


class _PeerLock:
    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None

    def __enter__(self):
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise PeerScanError("scan_in_progress", "已有队友扫描任务正在运行") from exc
        os.write(self.fd, f"pid={os.getpid()} started={_now()}\n".encode("utf-8"))
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            os.close(self.fd)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
