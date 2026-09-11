"""工具风险分级：capabilities / hidden / 声明约束 -> T1-T5。

T1 只读查询  T2 受限执行/外部检索  T3 任意文件读取
T4 任意命令执行  T5 隐藏后门（不在 tools/list 但可调用）
"""

from __future__ import annotations

TIERS = ("T1", "T2", "T3", "T4", "T5")
TIER_NAMES = {"T1": "只读查询", "T2": "受限执行/外部检索", "T3": "任意文件读取",
              "T4": "任意命令执行", "T5": "隐藏后门"}


def tier_rank(tier: str) -> int:
    return int(tier[1]) if tier in TIERS else 0


def classify_tool(tool_decl: dict) -> tuple[str, str]:
    caps = tool_decl.get("capabilities") or {}
    desc = (tool_decl.get("description") or "").lower()
    if tool_decl.get("hidden"):
        return "T5", "代码注册 hidden=True，不出现在 tools/list"
    if caps.get("subprocess"):
        return "T4", "handler 直接 subprocess 执行任意命令"
    if "白名单" in desc or "allowlist" in desc:
        return "T2", "受限执行：仅白名单命令（声明约束）"
    if caps.get("file_read"):
        return "T3", "任意路径文件读取"
    if caps.get("net_out"):
        return "T2", "触发外部网络检索"
    return "T1", "无副作用只读查询"


def classify_all(tools: list[dict]) -> list[dict]:
    out = []
    for t in tools:
        tier, reason = classify_tool(t)
        out.append({**t, "tier": tier, "tier_reason": reason})
    return out
