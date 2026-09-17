"""从 requirements 与 Dockerfile pip install 声明采集 Python 依赖资产。"""

from __future__ import annotations

import re
import shlex
from pathlib import Path, PurePath
from typing import Iterable

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_REQUIREMENT_FILE = re.compile(r"^(?:requirements(?:-[\w.-]+)?\.txt|requirements/[\w./-]+\.txt)$", re.I)
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "site-packages",
              ".pytest_cache", ".mypy_cache", ".tox", "dist", "build", "out"}
_OPTIONS_WITH_VALUE = {
    "--index-url", "--extra-index-url", "--find-links", "--trusted-host", "--proxy",
    "--cert", "--client-cert", "--src", "--target", "--platform", "--python-version",
    "--implementation", "--abi", "--root", "--prefix", "-c", "--constraint",
}


def collect_packages(root: Path, compose: dict | None = None) -> list[dict]:
    """返回稳定 package 记录；同名包聚合所有声明来源。"""
    root = Path(root)
    records: dict[str, dict] = {}
    requirement_files = sorted(path for path in root.rglob("*.txt")
                               if _is_requirement_file(path, root) and not _skipped(path, root))
    visited: set[Path] = set()
    for path in requirement_files:
        _parse_requirements(path, root, records, visited)
    for dockerfile in sorted(path for path in root.rglob("Dockerfile")
                             if not _skipped(path, root)):
        for command, line in _docker_run_commands(dockerfile):
            for tokens in _pip_install_segments(command):
                _consume_tokens(tokens, dockerfile, line, root, records, visited)
    _annotate_packages(records, root, compose or {})
    return [records[name] for name in sorted(records)]


def _is_requirement_file(path: Path, root: Path) -> bool:
    relative = path.relative_to(root).as_posix()
    return bool(_REQUIREMENT_FILE.match(relative) or path.name.lower().startswith("requirements"))


def _parse_requirements(path: Path, root: Path, records: dict, visited: set[Path]) -> None:
    path = path.resolve()
    if path in visited or not path.is_file():
        return
    visited.add(path)
    for lineno, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        line = line.split(";", 1)[0].strip()
        if not line:
            continue
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            tokens = line.split()
        _consume_tokens(tokens, path, lineno, root, records, visited)


def _consume_tokens(tokens: list[str], source: Path, lineno: int, root: Path,
                    records: dict, visited: set[Path]) -> None:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"-r", "--requirement"} and index + 1 < len(tokens):
            included = (source.parent / tokens[index + 1]).resolve()
            if _inside(included, root.resolve()):
                _parse_requirements(included, root, records, visited)
            index += 2
            continue
        if token.startswith(("-r", "--requirement=")):
            value = token[2:] if token.startswith("-r") else token.split("=", 1)[1]
            included = (source.parent / value).resolve()
            if _inside(included, root.resolve()):
                _parse_requirements(included, root, records, visited)
            index += 1
            continue
        if token in {"-e", "--editable"}:
            index += 2
            continue
        if token in _OPTIONS_WITH_VALUE:
            index += 2
            continue
        if any(token.startswith(option + "=") for option in _OPTIONS_WITH_VALUE):
            index += 1
            continue
        if token.startswith("-") or token in {"pip", "install", "python", "python3", "-m"}:
            index += 1
            continue
        if index + 2 < len(tokens) and tokens[index + 1] == "@" and "://" in tokens[index + 2]:
            parsed = _parse_requirement(f"{token} @ {tokens[index + 2]}")
            index += 3
        else:
            parsed = _parse_requirement(token)
            index += 1
        if parsed:
            name, specifier = parsed
            key = _normalize_name(name)
            entry = records.setdefault(key, {
                "name": key, "version_spec": specifier, "sources": [],
            })
            if not entry["version_spec"] and specifier:
                entry["version_spec"] = specifier
            evidence = {"file": _relative(source, root), "line": lineno,
                        "snippet": token[:240], "kind": "package-declaration",
                        "scope": _scope_for(source, root), "version_spec": specifier}
            if evidence not in entry["sources"]:
                entry["sources"].append(evidence)
            continue
        if parsed is None:
            continue
        index += 1


def _parse_requirement(token: str) -> tuple[str, str] | None:
    token = token.strip().rstrip("\\")
    if not token or token.startswith((".", "/", "git+", "http://", "https://")):
        return None
    marker_free = token.split(";", 1)[0].strip()
    direct = marker_free.split("@", 1)
    if len(direct) == 2 and "://" in direct[1]:
        name = direct[0].strip()
        return (name, "@ " + direct[1].strip()) if _PACKAGE_NAME.fullmatch(name) else None
    match = _PACKAGE_NAME.match(marker_free)
    if not match:
        return None
    name = match.group(0)
    remainder = marker_free[match.end():]
    if remainder.startswith("["):
        close = remainder.find("]")
        remainder = remainder[close + 1:] if close >= 0 else ""
    return name, remainder.strip()


def _docker_run_commands(path: Path) -> Iterable[tuple[str, int]]:
    logical = ""
    start = 0
    for lineno, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        stripped = raw.strip()
        if not logical:
            if not stripped.upper().startswith("RUN "):
                continue
            logical, start = stripped[4:], lineno
        else:
            logical += " " + stripped
        if logical.endswith("\\"):
            logical = logical[:-1].rstrip()
            continue
        yield logical, start
        logical = ""
    if logical:
        yield logical, start


def _pip_install_segments(command: str) -> Iterable[list[str]]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    for index, token in enumerate(tokens):
        is_pip = token in {"pip", "pip3"}
        is_module = token in {"python", "python3"} and tokens[index + 1:index + 3] == ["-m", "pip"]
        start = index + 1 if is_pip else index + 3 if is_module else None
        if start is None or start >= len(tokens) or tokens[start] != "install":
            continue
        end = len(tokens)
        for marker in ("&&", ";", "||"):
            if marker in tokens[start + 1:]:
                end = min(end, tokens.index(marker, start + 1))
        yield tokens[start + 1:end]


def _annotate_packages(records: dict[str, dict], root: Path, compose: dict) -> None:
    services = compose.get("services", []) if isinstance(compose, dict) else []
    for package in records.values():
        owner_entries = []
        for source in package["sources"]:
            source_path = source["file"]
            for service in services:
                dockerfile = _service_dockerfile(service)
                owner_match = source_path == dockerfile
                if not owner_match and dockerfile:
                    docker_parent = PurePath(dockerfile).parent.as_posix()
                    owner_match = docker_parent not in {"", "."} and source_path.startswith(docker_parent + "/")
                if not owner_match:
                    continue
                entry = {"owner": service["name"], "scope": source["scope"],
                         "source": source_path}
                if entry not in owner_entries:
                    owner_entries.append(entry)
        package["owner_entries"] = owner_entries
        package["owners"] = sorted({entry["owner"] for entry in owner_entries})
        package["scopes"] = sorted({source["scope"] for source in package["sources"]})
        package["version_specs"] = sorted({source.get("version_spec", "")
                                             for source in package["sources"]} - {""})


def _service_dockerfile(service: dict) -> str:
    context = str(service.get("build_context") or service.get("build") or ".").replace("\\", "/")
    dockerfile = str(service.get("dockerfile") or "Dockerfile").replace("\\", "/")
    if context in {"", "."}:
        return PurePath(dockerfile).as_posix()
    return (PurePath(context) / dockerfile).as_posix()


def _scope_for(path: Path, root: Path) -> str:
    relative = _relative(path, root).lower()
    if relative.startswith("attack/"):
        return "attack"
    if any(marker in relative for marker in ("requirements-dev", "requirements-test", "/tests/")):
        return "dev"
    return "runtime"


def _strip_comment(line: str) -> str:
    return re.split(r"\s+#", line, maxsplit=1)[0]


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _skipped(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in _SKIP_DIRS for part in parts)
