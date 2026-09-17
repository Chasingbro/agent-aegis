"""分层规则加载器。

无参 legacy accessor 继续读取 rules.yaml；新扫描链使用 load_rules() 选择
通用规则和目标 profile，避免不同 target 在同一进程中串用规则。
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

RULES_PATH = Path(__file__).resolve().parent / "rules.yaml"
GENERIC_DIR = Path(__file__).resolve().parent / "generic"
PROFILE_DIR = Path(__file__).resolve().parent / "profile"

_TARGET_ALIASES = {
    "agent-range": "agent-range",
    "agentrange-player": "agent-range",
    "揭榜挑战赛赛题2靶场-agentrange-player": "agent-range",
}


@lru_cache(maxsize=16)
def _load_legacy() -> dict:
    value = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8")) or {}
    return value if isinstance(value, dict) else {}


@lru_cache(maxsize=16)
def _load_generic_cached() -> dict:
    merged: dict[str, Any] = {}
    for path in sorted(GENERIC_DIR.glob("*.yaml")):
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if isinstance(value, dict):
            merged = _merge(merged, value)
    return merged


@lru_cache(maxsize=32)
def _load_rules_cached(target_key: str, use_profile: bool) -> dict:
    merged = deepcopy(_load_generic_cached())
    if use_profile and target_key:
        profile = PROFILE_DIR / f"{target_key}.yaml"
        if profile.is_file():
            value = yaml.safe_load(profile.read_text(encoding="utf-8")) or {}
            if isinstance(value, dict):
                merged = _merge(merged, value)
    return merged


def normalize_target(target: str | Path | None) -> str:
    if not target:
        return ""
    name = Path(str(target).replace("\\", "/")).name.strip().lower()
    return _TARGET_ALIASES.get(name, name.replace("_", "-").replace(" ", "-"))


def load() -> dict:
    """Legacy rules.yaml snapshot; compatible with existing direct callers."""
    return deepcopy(_load_legacy())


def load_generic() -> dict:
    return deepcopy(_load_generic_cached())


def load_profile(target: str | Path | None) -> dict | None:
    key = normalize_target(target)
    path = PROFILE_DIR / f"{key}.yaml" if key else None
    if not path or not path.is_file():
        return None
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return deepcopy(value) if isinstance(value, dict) else None


def load_rules(target: str | Path | None = None, *, use_profile: bool = True) -> dict:
    return deepcopy(_load_rules_cached(normalize_target(target), use_profile))


def _rules_or_legacy(target=None, use_profile=True):
    if target is None:
        return load()
    return load_rules(target, use_profile=use_profile)


def injection_patterns(target=None, *, use_profile=True) -> list[str]:
    return list(_rules_or_legacy(target, use_profile).get("injection_patterns", []))


def variable_poisoning_patterns(target=None, *, use_profile=True) -> list[str]:
    return list(_rules_or_legacy(target, use_profile).get("variable_poisoning_patterns", []))


def ansi_invisible_patterns(target=None, *, use_profile=True) -> list[str]:
    return list(_rules_or_legacy(target, use_profile).get("ansi_invisible_patterns", []))


def weak_value_patterns(target=None, *, use_profile=True) -> list[str]:
    return list(_rules_or_legacy(target, use_profile).get("weak_value_patterns", []))


def dangerous_decoded_patterns(target=None, *, use_profile=True) -> list[str]:
    return list(_rules_or_legacy(target, use_profile).get("dangerous_decoded_patterns", []))


def popular_mcp_servers(target=None, *, use_profile=True) -> list[str]:
    return list(_rules_or_legacy(target, use_profile).get("popular_mcp_servers", []))


def name_similarity_threshold(target=None, *, use_profile=True) -> float:
    return float(_rules_or_legacy(target, use_profile).get("name_similarity_threshold", 0.9))


def advisories(target=None, *, use_profile=True) -> dict:
    return deepcopy(_rules_or_legacy(target, use_profile).get("advisories", {}))


def _merge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(left)
    for key, value in right.items():
        if key not in result:
            result[key] = deepcopy(value)
        elif isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge(result[key], value)
        elif isinstance(result[key], list) and isinstance(value, list):
            result[key] = _merge_lists(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _merge_lists(left: list[Any], right: list[Any]) -> list[Any]:
    result = deepcopy(left)
    keyed: dict[tuple[str, Any], int] = {}
    for index, item in enumerate(result):
        marker = _list_key(item)
        if marker is not None:
            keyed[marker] = index
    for item in right:
        marker = _list_key(item)
        if marker is not None and marker in keyed:
            result[keyed[marker]] = deepcopy(item)
        elif item not in result:
            if marker is not None:
                keyed[marker] = len(result)
            result.append(deepcopy(item))
    return result


def _list_key(value: Any) -> tuple[str, Any] | None:
    if isinstance(value, dict):
        for field in ("id", "name"):
            if field in value:
                return field, value[field]
    return None


# Keep the cache-clear affordance expected by existing tests.
load.cache_clear = _load_legacy.cache_clear  # type: ignore[attr-defined]
