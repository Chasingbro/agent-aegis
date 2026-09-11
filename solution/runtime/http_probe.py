"""R3: 组件指纹 + 取证点探测。

重点：c2-sink /receipts —— notes-sync 启动外联的运行时直接证据
（容器启动即 POST 筛选出的敏感环境变量）；投毒页内容与静态扫描比对。

产出：out/runtime/http_fingerprint.json
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "out" / "runtime"

SENSITIVE_MARKERS = ("SECRET", "TOKEN", "KEY", "PASSWORD", "WEBHOOK", "DSN")
INJECTION_HINT = re.compile(r"ignore (all )?previous|read\s+/app|exfiltrate|debug_exec",
                            re.IGNORECASE)


def _get(url: str, timeout: int = 5) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:300]
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def _pick(base_paths: list[tuple[str, str]]) -> dict[str, str]:
    """按 (名字, url) 顺序探测，取第一个可达的（WinNAT 端口规避后宿主端口可能漂移）。"""
    chosen = {}
    for name, url in base_paths:
        if name in chosen:
            continue
        code, _ = _get(url)
        if 200 <= code < 500:  # 4xx 也证明端口活着（如 GET /collect 得 405）
            chosen[name] = url
    return chosen


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    result = {"services": {}, "c2_receipts": {}, "poisoned_page": {}}

    # 组件存活指纹（主端口被 WinNAT 排除段占用时回退 override 映射端口）
    endpoints = _pick([
        ("opspilot-app", "http://127.0.0.1:8100/health"),
        ("opspilot-app", "http://127.0.0.1:18100/health"),
        ("langflow", "http://127.0.0.1:7860/health"),
        ("llm-stub", "http://127.0.0.1:8000/health"),
        ("mock-internet", "http://127.0.0.1:9000/advisory/CVE-2025-0001"),
        ("mock-internet", "http://127.0.0.1:29000/advisory/CVE-2025-0001"),
        ("c2-sink", "http://127.0.0.1:9100/collect"),
        ("c2-sink", "http://127.0.0.1:29100/collect"),
    ])
    for name, url in endpoints.items():
        code, body = _get(url)
        result["services"][name] = {"endpoint": url, "status": code,
                                    "body_head": body[:120]}
    alive = sum(1 for s in result["services"].values() if 200 <= s["status"] < 500)

    # c2-sink 取证：receipts 聚合（端口自适应）
    c2_base = endpoints.get("c2-sink", "http://127.0.0.1:9100").removesuffix("/collect")
    code, body = _get(c2_base + "/receipts")
    if code == 200:
        doc = json.loads(body)
        items = doc.get("items", [])
        by_src = Counter(i.get("src", "?") for i in items)
        leaked_keys: set[str] = set()
        for i in items:
            for k in (i.get("exfil") or {}):
                if any(m in str(k).upper() for m in SENSITIVE_MARKERS):
                    leaked_keys.add(str(k))
        result["c2_receipts"] = {
            "endpoint": "http://127.0.0.1:9100/receipts", "status": code,
            "count": doc.get("count", len(items)), "by_src": dict(by_src),
            "sensitive_keys_exfiltrated": sorted(leaked_keys),
            "startup_beacon_present": "notes-sync" in by_src,
        }

    # 投毒页内容一致性（端口自适应）
    page_base = endpoints.get("mock-internet",
                              "http://127.0.0.1:9000").removesuffix(
        "/advisory/CVE-2025-0001")
    code, body = _get(page_base.rstrip("/") + "/advisory/CVE-2026-0001")
    comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
    injected = [c.strip()[:160] for c in comments if INJECTION_HINT.search(c)]
    result["poisoned_page"] = {
        "url": "http://127.0.0.1:9000/advisory/CVE-2026-0001", "status": code,
        "comments": injected,
        "injection_confirmed": bool(injected),
    }

    path = OUT / "http_fingerprint.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    receipts = result["c2_receipts"]
    print(f"[http_probe] 组件存活 {alive}/5; "
          f"c2 receipts={receipts.get('count', 0)} by_src={receipts.get('by_src')}; "
          f"外传敏感键={receipts.get('sensitive_keys_exfiltrated')}; "
          f"投毒页注入={'确认' if result['poisoned_page']['injection_confirmed'] else '未检出'}")
    print(f"-> {path}")
    ok = (alive >= 4 and receipts.get("startup_beacon_present")
          and result["poisoned_page"]["injection_confirmed"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
