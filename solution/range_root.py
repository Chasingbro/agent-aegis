"""靶场根目录的唯一解析入口。

目录名历史上是「揭榜挑战赛赛题2靶场-AgentRange-player」，2026-09-14 缩短为
`AgentRange-player`（与官方包名、队友 scanner 的约定一致）。两者都兼容，
避免队友手上未改名的检出直接失效。

优先级：环境变量 AGENT_RANGE_ROOT > AgentRange-player > 旧长名。

用法：
    from range_root import RANGE            # 默认取本仓库旁的靶场
    from range_root import resolve
    resolve(some_dir)                       # 指定起点目录下的靶场
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CANDIDATE_NAMES = ("AgentRange-player", "揭榜挑战赛赛题2靶场-AgentRange-player")


def resolve(base: Path | None = None) -> Path:
    """返回靶场根目录；base 为候选目录的父目录（默认仓库根）。"""
    env = os.environ.get("AGENT_RANGE_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    parent = Path(base).resolve() if base else REPO_ROOT
    for name in CANDIDATE_NAMES:
        candidate = parent / name
        if candidate.is_dir():
            return candidate
    return parent / CANDIDATE_NAMES[0]


RANGE = resolve()
