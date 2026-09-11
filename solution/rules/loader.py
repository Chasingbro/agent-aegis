"""规则库加载器：solution/rules/rules.yaml -> 各检测模块共用的常量。

部分模式族改编自 eSentire-Labs/mcp-scanner 的 .nov 规则
（已归档仓库，方法借鉴非代码复制），详见 rules.yaml 头部标注。
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

RULES_PATH = Path(__file__).resolve().parent / "rules.yaml"


@lru_cache(maxsize=1)
def load() -> dict:
    return yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))


def injection_patterns() -> list[str]:
    return load()["injection_patterns"]


def variable_poisoning_patterns() -> list[str]:
    return load()["variable_poisoning_patterns"]


def ansi_invisible_patterns() -> list[str]:
    return load()["ansi_invisible_patterns"]


def weak_value_patterns() -> list[str]:
    return load()["weak_value_patterns"]


def dangerous_decoded_patterns() -> list[str]:
    return load()["dangerous_decoded_patterns"]


def popular_mcp_servers() -> list[str]:
    return load()["popular_mcp_servers"]


def name_similarity_threshold() -> float:
    return float(load()["name_similarity_threshold"])


def advisories() -> dict:
    return load().get("advisories", {})
