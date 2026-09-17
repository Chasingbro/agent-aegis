"""静态资产采集器 v0 —— 不依赖靶场运行，仅解析源码与配置。

采集通道（对应《资产识别实施计划》P1 静态部分）:
  1. docker-compose.yml   -> 服务 / 网络 / 镜像版本 / 环境变量配置
  2. mcp/*/server.py      -> AST 扫描 Tool 注册（含 hidden）、on_start、危险能力
  3. skills/              -> frontmatter、正文隐藏注释、脚本 Base64 载荷
  4. opspilot-app/api     -> USERS 身份表、OPENAI_TOOL_ROUTES 工具路由
  5. .env* / managed-host -> 配置项与弱配置
  6. langflow/Dockerfile  -> 组件版本 <-> 本地公告库 CVE 匹配

输出: solution/out/scan.json + 控制台摘要与对账结果
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path

import yaml

# 外置规则库（部分模式族改编自 eSentire-Labs/mcp-scanner 的 .nov 规则，见 rules.yaml 标注）
sys.path.insert(0, str(Path(__file__).resolve().parent))
from range_root import RANGE
from rules import loader
from collectors import collect_packages

# ---------------------------------------------------------------- 小工具

def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def find_files(root: Path, pattern: str) -> list[Path]:
    return [p for p in root.rglob(pattern)
            if ".venv" not in p.parts and "__pycache__" not in p.parts]


def _skipped_path(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in {".git", ".venv", "venv", "node_modules", "out"}
               for part in parts)


def finding(rule: str, target: str, evidence: str, detail: str, tag: str, severity: str):
    return {"rule": rule, "target": target, "evidence": evidence,
            "detail": detail, "tag": tag, "severity": severity}


def looks_injected(text: str, rules: dict | None = None) -> list[str]:
    """注入结构 + 变量投毒模式；规则可按目标显式传入。"""
    rules = rules or loader.load()
    hits = []
    for p in rules.get("injection_patterns", []):
        if re.search(p, text, re.IGNORECASE | re.DOTALL):
            hits.append(p)
    for p in rules.get("variable_poisoning_patterns", []):
        if re.search(p, text, re.IGNORECASE):
            hits.append(p)
    return hits


def has_ansi_invisible(text: str, rules: dict | None = None) -> str | None:
    """ANSI 隐形文本检测（白底白字转义序列）。"""
    rules = rules or loader.load()
    for p in rules.get("ansi_invisible_patterns", []):
        if re.search(p, text):
            return p
    return None


def is_weak_value(value: str, rules: dict | None = None) -> str | None:
    rules = rules or loader.load()
    for pat in rules.get("weak_value_patterns", []):
        if re.search(pat, value, re.IGNORECASE):
            return pat
    return None


# 借鉴 mcp-scanner cross_origin_analyzer 的三步 token 归一化：
# 括号剥离 -> 下划线转连字符 -> 标点移除，使 brave_search 与 brave-search 等价
def normalize_token(token: str) -> str:
    token = re.sub(r"^\((.*)\)$", r"\1", token)
    token = token.replace("_", "-")
    return re.sub(r"[^\w\-]", "", token)


def find_cross_origin_refs(text: str, server_names: set[str],
                           self_name: str, rules: dict | None = None) -> list[dict]:
    """描述/正文中引用其他 MCP server 名（跨源引用是描述投毒的强线索）。"""
    rules = rules or loader.load()
    refs = []
    flagged = {normalize_token(s) for s in server_names
               if normalize_token(s) and normalize_token(s) != normalize_token(self_name)}
    flagged |= set(rules.get("popular_mcp_servers", []))
    flagged.discard(normalize_token(self_name))
    seen = set()
    for raw in text.lower().split():
        norm = normalize_token(raw)
        if not norm or norm in seen or norm not in flagged:
            continue
        seen.add(norm)
        m = re.search(r"\b" + re.escape(raw.strip("(),.")) + r"\b", text, re.IGNORECASE)
        start = max(0, (m.start() if m else 0) - 20)
        refs.append({"token": norm, "context": text[start:start + 60].strip()})
    return refs


def name_similarity_hits(name: str, known: list[str],
                         threshold: float | None = None, rules: dict | None = None) -> list[tuple[str, float]]:
    """名称相似度混淆（typosquatting）检测。"""
    rules = rules or loader.load()
    threshold = threshold or float(rules.get("name_similarity_threshold", 0.9))
    hits = []
    for k in known:
        if k == name:
            continue
        score = SequenceMatcher(None, name.lower(), k.lower()).ratio()
        if score >= threshold:
            hits.append((k, round(score, 3)))
    return hits


SENSITIVE_KEY_MARKERS = ("SECRET", "TOKEN", "KEY", "PASSWORD", "WEBHOOK", "DSN")


# ---------------------------------------------------------------- 通道 1: compose

def collect_compose(root: Path) -> dict:
    compose = root / "docker-compose.yml"
    doc = yaml.safe_load(compose.read_text(encoding="utf-8"))
    services, urls = [], []

    for name, cfg in (doc.get("services") or {}).items():
        env = dict(cfg.get("environment") or {})
        env_file = cfg.get("env_file") or []
        flat = {}
        for k, v in env.items():
            flat[k] = str(v)
        for key, val in flat.items():
            for m in re.finditer(r"https?://([\w.-]+)(:\d+)?", str(val)):
                urls.append({"url": m.group(0), "host": m.group(1),
                             "referenced_by": f"compose:{name}.{key}"})
        build_cfg = cfg.get("build")
        build_context = build_cfg.get("context") if isinstance(build_cfg, dict) else build_cfg
        dockerfile = build_cfg.get("dockerfile", "Dockerfile") if isinstance(build_cfg, dict) else "Dockerfile"
        svc = {
            "name": name,
            "image": cfg.get("image"),
            "build": build_context,
            "build_context": build_context,
            "dockerfile": dockerfile,
            "networks": cfg.get("networks") or [],
            "ports": cfg.get("ports") or [],
            "env": flat,
            "env_file": env_file,
            "mcp_module": None,
            "category": "component",
        }
        # SERVER: <module>.server 是 MCP server 的声明特征
        server_mod = flat.get("SERVER") or ""
        if server_mod.endswith(".server"):
            svc["mcp_module"] = server_mod.removesuffix(".server").replace(".", "/")
            svc["category"] = "mcp"
        elif (cfg.get("image") or "").startswith("postgres"):
            svc["category"] = "datastore"
        elif "mcp" in str(build_context or "").lower():
            svc["category"] = "mcp"
        services.append(svc)

    return {"services": services,
            "networks": list((doc.get("networks") or {}).keys()),
            "urls": urls,
            "source": rel(compose, root)}


# ---------------------------------------------------------------- 通道 2: MCP 源码 AST

class McpModuleScan:
    """对单个 server.py 做 AST 扫描，产出工具注册表与函数能力分析。"""

    def __init__(self, path: Path, root: Path):
        self.path = path
        self.root = root
        self.tree = ast.parse(path.read_text(encoding="utf-8"))
        self.strings = {}          # 变量名 -> 字符串常量（描述等）
        self.functions = {}        # 函数名 -> FunctionDef
        self.fastmcp_aliases: set[str] = set()
        self.fastmcp_instances: dict[str, str | None] = {}
        self._collect_toplevel()
        self.tools: list[dict] = []
        self.server_name = None
        self.on_start = None
        self._collect_registrations()

    def _collect_toplevel(self):
        for node in self.tree.body:
            if isinstance(node, ast.ImportFrom) and node.module in {"mcp.server.fastmcp", "fastmcp"}:
                for alias in node.names:
                    if alias.name == "FastMCP":
                        self.fastmcp_aliases.add(alias.asname or alias.name)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                for t in targets:
                    if isinstance(t, ast.Name) and isinstance(value, ast.Constant) \
                            and isinstance(value.value, str):
                        self.strings[t.id] = value.value
                    if isinstance(t, ast.Name) and isinstance(value, ast.Call) \
                            and isinstance(value.func, ast.Name) \
                            and value.func.id in self.fastmcp_aliases:
                        name = self._const_str(value.args[0]) if value.args else None
                        for keyword in value.keywords:
                            if keyword.arg == "name":
                                name = self._const_str(keyword.value)
                        self.fastmcp_instances[t.id] = name
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node

    def _const_str(self, node) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.strings.get(node.id)
        if isinstance(node, ast.BinOp):  # "a" + "b" 拼接
            left, right = self._const_str(node.left), self._const_str(node.right)
            return (left or "") + (right or "") if left or right else None
        return None

    def _collect_registrations(self):
        if len(self.fastmcp_instances) == 1:
            self.server_name = next(iter(self.fastmcp_instances.values()))
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            fname = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else "")
            if fname == "Tool":
                self.tools.append(self._parse_tool(node))
            elif fname == "create_server":
                self.server_name = (self._const_str(node.args[0])
                                    if node.args else None)
                for kw in node.keywords:
                    if kw.arg == "name":
                        self.server_name = self._const_str(kw.value)
                    if kw.arg == "on_start" and isinstance(kw.value, ast.Name):
                        self.on_start = kw.value.id
        if len(self.fastmcp_instances) == 1:
            instance = next(iter(self.fastmcp_instances))
            for function in self.functions.values():
                tool = self._parse_fastmcp_tool(function, instance)
                if tool:
                    self.tools.append(tool)
        unique = {}
        for tool in self.tools:
            key = (tool.get("name"), tool.get("handler"))
            unique.setdefault(key, tool)
        self.tools = list(unique.values())

    def _parse_fastmcp_tool(self, function, instance: str) -> dict | None:
        for decorator in function.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            expression = call.func if call else decorator
            if not isinstance(expression, ast.Attribute) or expression.attr != "tool" \
                    or not isinstance(expression.value, ast.Name) \
                    or expression.value.id != instance:
                continue
            name = function.name
            description = ast.get_docstring(function) or ""
            if call:
                for keyword in call.keywords:
                    if keyword.arg == "name":
                        name = self._const_str(keyword.value) or name
                    elif keyword.arg == "description":
                        description = self._const_str(keyword.value) or description
            return {"name": name, "description": description, "hidden": False,
                    "handler": function.name, "line": function.lineno,
                    "registration": "fastmcp-decorator",
                    "capabilities": self.analyze_function(function.name)}
        return None

    def _parse_tool(self, call: ast.Call) -> dict:
        pos = {"name": 0, "description": 1, "handler": 3}
        tool = {"name": None, "description": "", "hidden": False, "handler": None}
        for idx, arg in enumerate(call.args):
            if idx == pos["name"]:
                tool["name"] = self._const_str(arg)
            elif idx == pos["description"]:
                tool["description"] = self._const_str(arg) or ""
            elif idx == pos["handler"] and isinstance(arg, ast.Name):
                tool["handler"] = arg.id
            elif idx == 2 and isinstance(arg, ast.Name):
                # Support compact Tool(name, description, handler) registries.
                tool["handler"] = arg.id
        for kw in call.keywords:
            if kw.arg == "name":
                tool["name"] = self._const_str(kw.value)
            elif kw.arg == "description":
                tool["description"] = self._const_str(kw.value) or ""
            elif kw.arg == "hidden" and isinstance(kw.value, ast.Constant):
                tool["hidden"] = bool(kw.value.value)
            elif kw.arg == "handler" and isinstance(kw.value, ast.Name):
                tool["handler"] = kw.value.id
        tool["capabilities"] = self.analyze_function(tool["handler"])
        return tool

    def _const_endpoint(self, node) -> str:
        if isinstance(node, (ast.Tuple, ast.List)):
            values = []
            for element in node.elts:
                if isinstance(element, ast.Constant):
                    values.append(str(element.value))
            return ":".join(values) if values else "socket.connect"
        return self._const_str(node) or "socket.connect"

    def analyze_function(self, fn_name: str | None) -> dict:
        caps = {"subprocess": False, "net_out": [], "env_read": False,
                "sensitive_markers": [], "wildcard_check": False, "file_read": False,
                "network_send": False}
        if not fn_name or fn_name not in self.functions:
            return caps
        for node in ast.walk(self.functions[fn_name]):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    recv = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
                    attr = node.func.attr
                    if attr in {"run", "system", "popen", "Popen"} and recv in {"subprocess", "os"}:
                        caps["subprocess"] = True
                    if attr in {"post", "get"} and recv in {"httpx", "requests"}:
                        caps["net_out"].append(self._const_str(node.args[0]) or f"{recv}.{attr}")
                    if attr == "connect":
                        endpoint = self._const_endpoint(node.args[0]) if node.args else "socket.connect"
                        caps["net_out"].append(endpoint)
                    if attr in {"send", "sendall", "sendto"}:
                        caps["network_send"] = True
                    if attr == "getenv" and recv == "os":
                        caps["env_read"] = True
                    if attr == "open":
                        caps["file_read"] = True
                elif isinstance(node.func, ast.Name) and node.func.id == "open":
                    caps["file_read"] = True
            if isinstance(node, ast.Attribute) and node.attr == "environ":
                caps["env_read"] = True
            if isinstance(node, ast.Constant):
                v = node.value
                if isinstance(v, str):
                    if re.search(r"https?://", v):
                        caps["net_out"].append(v)
                    if any(m in v.upper() for m in SENSITIVE_KEY_MARKERS):
                        caps["sensitive_markers"].append(v[:40])
            if isinstance(node, ast.Compare):
                for comp in node.comparators:
                    if isinstance(comp, ast.Constant) and comp.value == "*":
                        caps["wildcard_check"] = True
        caps["net_out"] = sorted(set(caps["net_out"]))
        caps["sensitive_markers"] = sorted(set(caps["sensitive_markers"]))[:5]
        return caps


def collect_mcp_configs(root: Path) -> list[dict]:
    """发现标准 MCP 客户端配置；只记录声明，不执行 command/args。"""
    records = {}
    names = {".mcp.json", "mcp.json", "claude_desktop_config.json", "claude_config.json"}
    for path in sorted(root.rglob("*.json")):
        if path.name.lower() not in names or _skipped_path(path, root):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        servers = document.get("mcpServers") if isinstance(document, dict) else None
        if not isinstance(servers, dict):
            continue
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            entry = records.setdefault(str(name), {"server": str(name), "service": None,
                "module": None, "on_start": None, "on_start_caps": {
                    "subprocess": False, "net_out": [], "env_read": False,
                    "sensitive_markers": [], "wildcard_check": False,
                    "file_read": False, "network_send": False}, "tools": [],
                "source": rel(path, root), "config_sources": []})
            evidence = {"file": rel(path, root), "spec": spec}
            if evidence not in entry["config_sources"]:
                entry["config_sources"].append(evidence)
            entry["config"] = spec
            entry["transport"] = "http" if spec.get("url") or spec.get("endpoint") else "stdio"
    return list(records.values())


def collect_mcp_code(root: Path, compose: dict, rules: dict | None = None) -> list[dict]:
    rules = rules or loader.load()
    servers = []
    module_to_service = {s["mcp_module"]: s["name"] for s in compose["services"]
                         if s["mcp_module"]}
    for service in compose["services"]:
        context = service.get("build")
        if context:
            module_to_service.setdefault(str(context).replace("\\", "/"), service["name"])
    # Accept both the official mcp/* layout and independent service directories.
    candidates = {rel(p.parent, root) for p in find_files(root, "server.py")}
    for service in compose["services"]:
        context = service.get("build")
        if context:
            context_path = root / context
            if (context_path / "server.py").exists():
                candidates.add(rel(context_path, root))
    for config in collect_mcp_configs(root):
        if not any(server["server"] == config["server"] for server in servers):
            servers.append(config)
    for module in sorted(candidates):
        path = root / module / "server.py"
        if not path.exists():
            continue
        scan = McpModuleScan(path, root)
        # Do not classify every generic FastAPI app as an MCP server.
        if not scan.tools and not scan.server_name and not scan.on_start:
            continue
        # compose 的 SERVER=customer_db.server 推出短模块名，文件系统扫描得到
        # mcp/customer_db 全路径 —— 两种形态都尝试绑定 compose 服务
        short = module.split("/")[-1]
        record = {
            "server": scan.server_name or short,
            "service": module_to_service.get(module) or module_to_service.get(short),
            "module": module,
            "on_start": scan.on_start,
            "on_start_caps": scan.analyze_function(scan.on_start),
            "tools": scan.tools,
            "source": rel(path, root),
        }
        existing = next((item for item in servers if item["server"] == record["server"]), None)
        if existing:
            existing.update(record)
            existing["config_sources"] = existing.get("config_sources", [])
            existing["config_sources"].extend(record.get("config_sources", []))
        else:
            servers.append(record)
    return servers


# ---------------------------------------------------------------- 通道 3: skills

def collect_skills(root: Path, rules: dict | None = None) -> list[dict]:
    rules = rules or loader.load()
    skills = []
    skills_dir = root / "skills"
    candidates = sorted(skills_dir.rglob("SKILL.md")) if skills_dir.exists() else []
    # Generic targets may keep extensions under a differently named directory.
    if not candidates:
        candidates = sorted(p for p in root.rglob("*.md")
                            if any(part in {"extensions", "plugins", "skills"}
                                   for part in p.parts))
    for skill_md in candidates:
        text = skill_md.read_text(encoding="utf-8")
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
        metadata_error = None
        try:
            meta = yaml.safe_load(m.group(1)) if m else {}
            meta = meta if isinstance(meta, dict) else {}
        except yaml.YAMLError as exc:
            meta = {}
            metadata_error = str(exc).splitlines()[0][:200]
        body = m.group(2) if m else text
        skill = {
            "name": meta.get("name", skill_md.parent.name),
            "description": meta.get("description", ""),
            "allowed_tools": meta.get("allowed-tools", []),
            "hidden_comments": re.findall(r"<!--(.*?)-->", body, re.DOTALL),
            "scripts": [],
            "source": rel(skill_md, root),
            "metadata_error": metadata_error,
        }
        for script in sorted(skill_md.parent.rglob("*.py")):
            code = script.read_text(encoding="utf-8")
            entry = {"path": rel(script, root),
                     "sha256": hashlib.sha256(code.encode()).hexdigest()[:12]}
            entry["b64_payloads"] = analyze_script_payloads(code, rules)
            skill["scripts"].append(entry)
        skills.append(skill)
    return skills


def collect_plugins(root: Path, rules: dict | None = None) -> list[dict]:
    rules = rules or loader.load()
    plugins = []
    for path in sorted(root.rglob("*.py")):
        if "plugins" not in path.parts or _skipped_path(path, root):
            continue
        code = path.read_text(encoding="utf-8", errors="replace")
        plugins.append({
            "name": path.stem.replace("_", "-"),
            "source": rel(path, root),
            "sha256": hashlib.sha256(code.encode()).hexdigest()[:12],
            "b64_payloads": analyze_script_payloads(code, rules),
        })
    return plugins


def analyze_script_payloads(code: str, rules: dict | None = None) -> list[dict]:
    rules = rules or loader.load()
    payloads = []
    for m in re.finditer(r"[A-Za-z0-9+/]{32,}={0,2}", code):
        try:
            decoded = base64.b64decode(m.group()).decode("utf-8", "replace")
        except Exception:
            continue
        hits = [p for p in rules.get("dangerous_decoded_patterns", [])
                if re.search(p, decoded)]
        if hits:
            payloads.append({"blob": m.group()[:24] + "...",
                             "decoded": decoded.strip()[:160],
                             "dangerous_patterns": hits})
    return payloads


def collect_web_pages(root: Path) -> list[dict]:
    """静态 HTML 内容源（外部情报页/投毒页），与 Skill 正文共用注入检测规则。"""
    pages = []
    search_root = root / "attack" if (root / "attack").exists() else root
    for html_file in sorted(search_root.rglob("*.html")):
        text = html_file.read_text(encoding="utf-8")
        pages.append({"path": rel(html_file, root),
                      "hidden_comments": re.findall(r"<!--(.*?)-->", text, re.DOTALL)})
    return pages


# ---------------------------------------------------------------- 通道 4: app 源码

def collect_app(root: Path) -> dict:
    app_path = root / "opspilot-app" / "api" / "app.py"
    if not app_path.exists():
        # Use the first Compose build context with a FastAPI app as a generic fallback.
        compose_path = root / "docker-compose.yml"
        contexts = []
        if compose_path.exists():
            doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
            for cfg in (doc.get("services") or {}).values():
                build = cfg.get("build")
                if isinstance(build, dict):
                    build = build.get("context")
                if build:
                    contexts.append(root / build / "app.py")
        app_path = next((p for p in contexts if p.exists()), root / "app.py")
    if not app_path.exists():
        return {"identities": [], "routes": {}, "system_prompt": None,
                "max_steps": None, "source": None}
    source = app_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    identities, routes = [], {}
    system_prompt, max_steps = None, None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            key = node.targets[0].id if isinstance(node.targets[0], ast.Name) else ""
            if key == "USERS":
                for v in node.value.values:
                    if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) \
                            and v.func.id == "Identity":
                        args = [a.value for a in v.args if isinstance(a, ast.Constant)]
                        scope = ast.literal_eval(v.args[3]) if len(v.args) > 3 \
                            and isinstance(v.args[3], (ast.Dict, ast.List)) else {}
                        identities.append({"user": args[0], "role": args[1],
                                           "team": args[2], "scope": scope})
            if key == "OPENAI_TOOL_ROUTES":
                for k, v in zip(node.value.keys, node.value.values):
                    if isinstance(k, ast.Constant) and isinstance(v, ast.Tuple):
                        routes[k.value] = tuple(
                            e.value for e in v.elts if isinstance(e, ast.Constant))
            if key == "SYSTEM_PROMPT":
                system_prompt = node.value.value if isinstance(node.value, ast.Constant) else None
        # max_steps 这类运行上限从 getenv 默认值里取（如 OPSPILOT_MAX_AGENT_STEPS=8）
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            inner = call.args[0] if isinstance(call.func, ast.Name) and call.func.id == "int" \
                and call.args else None
            target = inner if isinstance(inner, ast.Call) else call
            if isinstance(target, ast.Call) and isinstance(target.func, ast.Attribute) \
                    and target.func.attr == "getenv":
                env_name = target.args[0].value if target.args and \
                    isinstance(target.args[0], ast.Constant) else ""
                if "MAX" in env_name and "STEP" in env_name:
                    default = target.args[1] if len(target.args) > 1 else next(
                        (d.value for d in target.keywords
                         if d.arg == "default"), None)
                    if isinstance(default, ast.Constant):
                        max_steps = default.value
    return {"identities": identities, "routes": routes,
            "system_prompt": system_prompt, "max_steps": max_steps,
            "source": rel(app_path, root)}


# ---------------------------------------------------------------- 通道 7: 编排 flow 资产

def collect_agents(root: Path, compose: dict | None = None) -> list[dict]:
    """发现常见 Agent 入口文件，使用框架/运行循环的结构信号而非项目名。"""
    agents = []
    for path in sorted(root.rglob("*.py")):
        if _skipped_path(path, root):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if not ("create_react_agent" in text or "AgentExecutor" in text or
                ("ChatOpenAI" in text and "agent" in path.stem.lower()) or
                ("FastAPI" in text and "agent" in text.lower() and path.name == "app.py")):
            continue
        agents.append({"name": path.stem, "path": rel(path, root), "frameworks":
                       [name for name in ("langchain", "langgraph") if name.lower() in text.lower()]})
    return agents


def collect_model_files(root: Path) -> list[dict]:
    models = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _skipped_path(path, root):
            continue
        if path.suffix.lower() in {".gguf", ".ggml", ".safetensors", ".bin"}:
            models.append({"name": path.stem, "path": rel(path, root), "format": path.suffix.lower()[1:]})
    return models


def collect_models(root: Path, compose: dict) -> list[dict]:

    models = []
    seen = set()
    for service in compose["services"]:
        context = service.get("build")
        app_path = root / context / "app.py" if context else None
        if not app_path or not app_path.exists():
            continue
        text = app_path.read_text(encoding="utf-8", errors="replace")
        if "/v1/chat/completions" not in text:
            continue
        names = re.findall(r'"model"\s*:\s*"([^"]+)"', text)
        model_name = names[0] if names else service["name"]
        key = (model_name, service["name"])
        if key in seen:
            continue
        seen.add(key)
        models.append({"name": model_name, "service": service["name"],
                       "endpoint": "/v1/chat/completions",
                       "source": rel(app_path, root)})
    return models


def collect_flows(root: Path) -> list[dict]:
    """langflow flows/*.json —— 第二个 agent（编排 flow）的声明面。"""
    flows = []
    flow_paths = sorted((root / "langflow" / "flows").glob("*.json"))
    if not flow_paths:
        flow_paths = sorted(path for path in root.rglob("*.json")
                            if "flow" in path.name.lower() and not _skipped_path(path, root))
    for path in flow_paths:
        doc = json.loads(path.read_text(encoding="utf-8"))
        data = doc.get("data") or {}
        agent_nodes = [n for n in data.get("nodes", [])
                       if str(n.get("type", "")).lower() == "agent"]
        flows.append({
            "name": doc.get("name", path.stem),
            "description": doc.get("description", ""),
            "nodes": [n.get("type") for n in data.get("nodes", [])],
            "agent_nodes": agent_nodes,
            "mcp_tools": [t for n in agent_nodes
                          for t in (n.get("data") or {}).get("mcp_tools", [])],
            "model_base": next(iter([((n.get("data") or {}).get("base_url"))
                                     for n in agent_nodes]), None),
            "source": rel(path, root),
        })
    return flows


# ---------------------------------------------------------------- 通道 5: env 文件

def collect_env_files(root: Path) -> list[dict]:
    items = []
    # Prefer known challenge fixtures, then discover generic dotenv examples.
    env_paths = [root / ".env.example", root / "backends/secrets/secrets.env.example",
                 root / "mcp/managed-host.env"]
    env_paths.extend(sorted(p for p in root.rglob("*.env.example")
                            if p not in env_paths and not _skipped_path(p, root)))
    env_paths.extend(sorted(p for p in root.rglob(".env")
                            if p not in env_paths and not _skipped_path(p, root)))
    for path in env_paths:
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            items.append({"key": key.strip(), "value": value.strip(),
                          "source": f"{rel(path, root)}:{lineno}"})
    # Dockerfile 的 ENV 指令也是配置声明面（处理 \ 续行的多行 ENV）
    for dockerfile in find_files(root, "Dockerfile"):
        logical, start_line = [], 0
        lines = dockerfile.read_text(encoding="utf-8").splitlines()
        for lineno, raw in enumerate(lines, 1):
            stripped = raw.strip()
            if raw.startswith((" ", "\t")) and logical:      # 续行
                logical.append(stripped)
                continue
            if logical:
                _emit_env_logical(items, logical, rel(dockerfile, root), start_line)
                logical = []
            if stripped.startswith("ENV") and not stripped.startswith("ENTRYPOINT"):
                logical, start_line = [stripped], lineno
        if logical:
            _emit_env_logical(items, logical, rel(dockerfile, root), start_line)
    return items


def _emit_env_logical(items: list, parts: list[str], source: str, lineno: int):
    body = " ".join(parts).removeprefix("ENV").strip()
    tokens = body.split()
    if not tokens:
        return
    if "=" in tokens[0]:                      # ENV KEY=VALUE [KEY2=VALUE2 ...]
        for token in tokens:
            key, _, value = token.partition("=")
            items.append({"key": key, "value": value.strip('"'),
                          "source": f"{source}:{lineno}"})
    else:                                     # legacy: ENV KEY VALUE
        segs = body.split(None, 1)
        if len(segs) == 2:
            items.append({"key": segs[0], "value": segs[1].strip('"'),
                          "source": f"{source}:{lineno}"})


# ---------------------------------------------------------------- 通道 6: 组件版本

def collect_versions(root: Path) -> dict:
    versions = {}
    for dockerfile in find_files(root, "Dockerfile"):
        args: dict[str, str] = {}   # ARG 默认值，用于展开 FROM ${VAR}
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            m = re.match(r"ARG\s+(\w+)(?:=(\S+))?", line)
            if m and m.group(2):
                args[m.group(1)] = m.group(2)
            m = re.match(r"FROM\s+([\w./${}-]+)(?::([\w.${}-]+))?", line)
            if m:
                image = re.sub(r"\$\{(\w+)\}", lambda x: args.get(x.group(1), ""),
                               m.group(1))
                ver = re.sub(r"\$\{(\w+)\}", lambda x: args.get(x.group(1), ""),
                             m.group(2) or "")
                if not ver:  # 无版本标签无法比对，跳过
                    continue
                if image not in versions:  # 每个镜像只记首个（基础镜像）
                    versions[image] = {"version": ver,
                                       "source": rel(dockerfile, root)}
    return versions


# ---------------------------------------------------------------- 风险规则（R1/R2/R3 首版）

def run_rules(bundle: dict, rules: dict | None = None, *, use_profile: bool = True) -> list[dict]:
    root = Path(bundle["root"])
    rules = rules or loader.load_rules(root, use_profile=use_profile)
    risks: list[dict] = []
    ev = lambda p, ln: f"{p}:{ln}"

    # --- R2 供应链恶意组件 ---
    for srv in bundle["mcp_servers"]:
        src = srv["source"]
        for tool in srv["tools"]:
            hits = looks_injected(tool["description"], rules)
            if hits:
                risks.append(finding(
                    "desc-poisoning", f"tool:{srv['server']}.{tool['name']}", src,
                    f"工具描述含注入指令结构 {hits}：{tool['description'][:80]}",
                    "OWASP LLM01 / CWE-74", "high"))
            if tool["hidden"]:
                risks.append(finding(
                    "hidden-tool", f"tool:{srv['server']}.{tool['name']}", src,
                    "代码注册 hidden=True，不出现在 tools/list 但可被调用",
                    "CWE-912", "high"))
            caps = tool["capabilities"]
            if caps["subprocess"] and not tool["hidden"]:
                risks.append(finding(
                    "shell-capability", f"tool:{srv['server']}.{tool['name']}", src,
                    "声明工具具备任意命令执行能力（是否恶意需结合声明与用途判断）",
                    "CWE-78", "info"))
            wildcard_description = re.search(
                r"(?:tenant.{0,24}['\"]?\*|all\s+(?:demo\s+)?tenants)",
                tool["description"], re.IGNORECASE)
            if caps["wildcard_check"] or "全部租户" in tool["description"] \
                    or wildcard_description:
                risks.append(finding(
                    "permissive-semantics", f"tool:{srv['server']}.{tool['name']}", src,
                    "支持通配符(*)查询，可绕过租户隔离读取全部数据",
                    "CWE-863", "medium"))
            if caps["env_read"] and caps["net_out"] and caps.get("network_send"):
                exfil = finding(
                    "handler-data-exfiltration", f"tool:{srv['server']}.{tool['name']}", src,
                    f"同一工具处理函数读取环境变量并向 {caps['net_out']} 发送数据",
                    "CWE-200 / CWE-918", "high")
                exfil.update({"category": "malicious_mcp",
                              "malicious_type": "data_exfiltration",
                              "confidence": 0.95})
                risks.append(exfil)
        # on_start 上下文的出网才判供应链后门；handler 内请求时出网属业务行为
        osc = srv["on_start_caps"]
        if srv["on_start"] and (osc["net_out"] or osc["env_read"]):
            detail = f"on_start={srv['on_start']} 出网={osc['net_out']} " \
                     f"读取环境变量={osc['env_read']} 敏感标记={osc['sensitive_markers']}"
            risks.append(finding(
                "startup-egress", f"mcp:{srv['server']}", src, detail,
                "CWE-506", "high"))

    for skill in bundle["skills"]:
        description = skill.get("description", "") or ""
        description_hits = looks_injected(description, rules)
        if description_hits:
            risk = finding(
                "skill-description-injection", f"skill:{skill['name']}", skill["source"],
                f"Skill 描述含提示词注入结构 {description_hits}",
                "OWASP LLM01 / CWE-74", "high")
            risk.update({"category": "malicious_skill", "malicious_type": "prompt_injection",
                         "confidence": 0.9})
            risks.append(risk)
        for comment in skill["hidden_comments"]:
            hits = looks_injected(comment, rules)
            if hits:
                risks.append(finding(
                    "hidden-comment-injection", f"skill:{skill['name']}", skill["source"],
                    f"正文 HTML 注释含指令内容 {hits}：{comment.strip()[:100]}",
                    "OWASP LLM01 / CWE-74", "high"))
        for script in skill["scripts"]:
            script_text = (root / script["path"]).read_text(encoding="utf-8", errors="replace")
            sensitive_read = bool(re.search(r"(?:open|read_text)\s*\(", script_text, re.IGNORECASE)
                                  and re.search(r"(?:\.env|id_rsa|ssh|passwd)", script_text, re.IGNORECASE))
            command_exec = bool(re.search(r"subprocess\.(?:run|Popen|call)|shell\s*=\s*True", script_text))
            network_sink = bool(re.search(r"(?:curl|requests|httpx|socket|sendall|POST)", script_text, re.IGNORECASE))
            if sensitive_read and command_exec and network_sink:
                risk = finding(
                    "skill-script-data-exfiltration", script["path"], script["path"],
                    "Skill 脚本同时读取敏感文件、执行命令并访问网络，疑似数据外泄",
                    "CWE-200 / CWE-506", "high")
                risk.update({"category": "malicious_skill", "malicious_type": "data_exfiltration",
                             "confidence": 0.9})
                risks.append(risk)
            for payload in script["b64_payloads"]:
                risk = finding(
                    "obfuscated-payload", script["path"], script["path"],
                    f"Base64 载荷解码命中 {payload['dangerous_patterns']}："
                    f"{payload['decoded'][:100]}",
                    "CWE-506", "high")
                risk.update({"category": "malicious_skill", "malicious_type": "supply_chain",
                             "confidence": 0.9})
                risks.append(risk)

    for plugin in bundle.get("plugins", []):
        for payload in plugin["b64_payloads"]:
            risks.append(finding(
                "obfuscated-payload", f"plugin:{plugin['name']}", plugin["source"],
                f"插件 Base64 载荷命中 {payload['dangerous_patterns']}："
                f"{payload['decoded'][:100]}", "CWE-506", "high"))

    for page in bundle.get("web_pages", []):
        for comment in page["hidden_comments"]:
            hits = looks_injected(comment, rules)
            if hits:
                risks.append(finding(
                    "content-poisoning", page["path"], page["path"],
                    f"外部内容源 HTML 注释含注入指令 {hits}：{comment.strip()[:100]}",
                    "OWASP LLM01 / CWE-74", "high"))

    # 标准 MCP 客户端配置：组合语义才升级为配置风险。
    for server in bundle.get("mcp_configs", []):
        spec = server.get("config") or {}
        args = [str(value) for value in spec.get("args", [])] if isinstance(spec, dict) else []
        if server.get("transport") == "stdio" and "filesystem" in server["server"].lower() \
                and any(value in {"/", "\\"} for value in args):
            risk = finding(
                "mcp-filesystem-overreach", f"mcp:{server['server']}", server["source"],
                "filesystem MCP 配置授予根目录读写范围", "CWE-22", "high")
            risk.update({"category": "misconfig", "confidence": 0.9})
            risks.append(risk)
        if server.get("transport") == "http" and isinstance(spec, dict) \
                and not any(key.lower() in {"headers", "env", "authorization", "token", "api_key"}
                            for key in spec):
            risk = finding(
                "mcp-remote-no-auth", f"mcp:{server['server']}", server["source"],
                "远程 MCP endpoint 未声明认证信息", "CWE-306", "high")
            risk.update({"category": "misconfig", "confidence": 0.9})
            risks.append(risk)

    # --- R1 配置风险（env 文件 + compose environment 合并扫描）---
    env_entries = list(bundle["env_items"])
    for svc in bundle["compose"]["services"]:
        for k, v in svc["env"].items():
            env_entries.append({"key": k, "value": v,
                                "source": f"docker-compose.yml:{svc['name']}.{k}"})
    kv = {}
    for e in env_entries:
        kv.setdefault(e["key"], []).append(e)
    auto_login_targets = set()
    for key, entries in kv.items():
        values = {}
        for e in entries:  # 同键同值多处出现 -> 合并为一条风险，证据并列
            values.setdefault(e["value"], []).append(e["source"])
        for value, sources in values.items():
            if any(marker in key.upper() for marker in ("SECRET", "PASSWORD", "TOKEN", "API_KEY", "ACCESS_KEY")):
                weak = is_weak_value(value, rules)
                placeholder = re.search(r"(?i)(x{4,}|example|dummy|placeholder)", value)
                if weak or value:

                    risk = finding(
                        "weak-secret" if weak else "plaintext-secret",
                        key, "; ".join(sources),
                        f"取值 '{value}' 命中弱模式 /{weak}/（{len(sources)} 处配置）"
                        if weak else f"敏感配置 {key} 以明文声明（值已脱敏）",
                        "CWE-321" if weak else "CWE-798", "high" if weak else "medium")
                    if not weak:
                        risk.update({"category": "secret_leak", "confidence": 0.85})
                    risks.append(risk)
        first = entries[0]
        propagation_keys = {"OPSPILOT_PROPAGATION", "PROPAGATION_MODE"}
        token_keys = {"OPSPILOT_SERVICE_TOKEN", "SERVICE_TOKEN"}
        if key in propagation_keys and first["value"] == "service-account" \
                and any(token in kv for token in token_keys):
            risks.append(finding(
                "confused-deputy", "opspilot-app", first["source"],
                "身份以宽权限服务账号传递，下游无法追溯真实用户",
                "CWE-269", "high"))
        if key.endswith("AUTO_LOGIN") and first["value"].lower() == "true":
            target = key.split("_", 1)[0].lower() or "framework"
            if target not in auto_login_targets:
                auto_login_targets.add(target)
                risks.append(finding(
                    "auto-login", target, first["source"],
                    "框架开启免认证自动登录", "CWE-798", "medium"))
    users = [e["value"] for e in kv.get("POSTGRES_USER", [])]
    pwds = [e["value"] for e in kv.get("POSTGRES_PASSWORD", [])]
    if users and pwds and users[0] == pwds[0]:
        risks.append(finding(
            "default-credentials", "postgres-customer", "docker-compose.yml",
            f"数据库账号口令相同：{users[0]}", "CWE-798", "medium"))

    # --- 路由交叉验证：app 路由引用了隐藏工具 ---
    tool_index = {}
    for srv in bundle["mcp_servers"]:
        for t in srv["tools"]:
            tool_index[(srv["server"], t["name"])] = t
    for openai_name, (server, tool_name) in bundle["app"]["routes"].items():
        tool = tool_index.get((server, tool_name))
        if tool and tool["hidden"]:
            risks.append(finding(
                "routed-hidden-tool", f"route:{openai_name}", bundle["app"]["source"],
                f"应用路由表显式映射到隐藏工具 {server}.{tool_name}",
                "CWE-912", "high"))
        if tool is None:
            risks.append(finding(
                "dangling-route", f"route:{openai_name}", bundle["app"]["source"],
                f"路由目标 {server}.{tool_name} 在已采集工具清单中不存在",
                "CWE-1163", "medium"))

    # --- R3 版本漏洞（公告库外置于 rules.yaml，版本区间匹配） ---
    for image, info in bundle["versions"].items():
        short = image.split("/")[-1]
        for adv in rules.get("advisories", {}).get(short, []):
            if info["version"] in adv.get("versions", []):
                risks.append(finding(
                    "known-vulnerable-version", f"{image}:{info['version']}",
                    info["source"],
                    f"{adv['id']}（{adv['cwe']} {adv['type']}）：{adv['summary']}",
                    adv["cwe"], "high"))

    # --- 借鉴 mcp-scanner: 跨源引用（描述指向其他 server，投毒强线索） ---
    server_names = {s["server"] for s in bundle["mcp_servers"]}
    for srv in bundle["mcp_servers"]:
        for tool in srv["tools"]:
            refs = find_cross_origin_refs(tool["description"] or "", server_names,
                                          srv["server"])
            if refs:
                risks.append(finding(
                    "cross-origin-reference", f"tool:{srv['server']}.{tool['name']}",
                    srv["source"],
                    f"工具描述引用其他 MCP server：{[r['token'] for r in refs]} "
                    f"上下文如 '{refs[0]['context']}'",
                    "CWE-74", "medium"))

    # --- 借鉴 mcp-scanner: ANSI 隐形文本 ---
    for skill in bundle["skills"]:
        for comment in skill["hidden_comments"]:
            ansi = has_ansi_invisible(comment, rules)
            if ansi:
                risks.append(finding(
                    "ansi-invisible-text", f"skill:{skill['name']}", skill["source"],
                    f"隐藏注释含 ANSI 隐形文本模式 /{ansi}/",
                    "CWE-1006", "high"))
    for srv in bundle["mcp_servers"]:
        for tool in srv["tools"]:
            ansi = has_ansi_invisible(tool["description"] or "", rules)
            if ansi:
                risks.append(finding(
                    "ansi-invisible-text", f"tool:{srv['server']}.{tool['name']}",
                    srv["source"],
                    f"工具描述含 ANSI 隐形文本模式 /{ansi}/",
                    "CWE-1006", "high"))

    # --- 借鉴 mcp-scanner: 名称相似度混淆（typosquatting） ---
    known_names = sorted(server_names | set(rules.get("popular_mcp_servers", [])))
    for srv in bundle["mcp_servers"]:
        for k, score in name_similarity_hits(srv["server"], known_names, rules=rules):
            if k not in server_names:  # 只对外部知名名报警
                risks.append(finding(
                    "name-similarity", f"mcp:{srv['server']}", srv["source"],
                    f"与知名 MCP server '{k}' 相似度 {score}，疑似名称混淆",
                    "CWE-1006", "medium"))
    return risks


# ---------------------------------------------------------------- 对账

def reconcile(bundle: dict, risks: list[dict]) -> list[tuple]:
    """Run the official exact oracle only for the official player.

    Other targets use structural smoke checks; their expected inventory belongs in
    an external oracle manifest and is evaluated by targets/bench.py.
    """
    mcp = bundle["mcp_servers"]
    tools = [t for s in mcp for t in s["tools"]]
    official = (Path(bundle["root"]) / "opspilot-app").exists()
    if not official:
        return [
            ("compose 至少 1 个服务", len(bundle["compose"]["services"]) > 0, True),
            ("网络字段可解析", isinstance(bundle["compose"]["networks"], list), True),
            ("MCP server 至少 1 个", len(mcp) > 0, True),
            ("工具至少 1 个", len(tools) > 0, True),
            ("Skill/extension 至少 1 个", len(bundle["skills"]) > 0, True),
            ("依赖资产可采集", len(bundle.get("packages", [])) > 0, True),
        ]
    checks = [
        ("compose 服务数 = 14", len(bundle["compose"]["services"]), 14),
        ("网络数 = 2", len(bundle["compose"]["networks"]), 2),
        ("MCP server = 8", len(mcp), 8),
        ("工具总数 = 10", len(tools), 10),
        ("隐藏工具 = 1", sum(1 for t in tools if t["hidden"]), 1),
        ("Skill = 7", len(bundle["skills"]), 7),
        ("身份 = 5", len(bundle["app"]["identities"]), 5),
        ("工具路由 = 10", len(bundle["app"]["routes"]), 10),
    ]
    rule_expect = {
        "desc-poisoning": 1, "hidden-tool": 1, "startup-egress": 1,
        "hidden-comment-injection": 1, "obfuscated-payload": 1,
        "content-poisoning": 1, "permissive-semantics": 1, "routed-hidden-tool": 1,
        "weak-secret": 2, "confused-deputy": 1, "auto-login": 1,
        "default-credentials": 1, "known-vulnerable-version": 2,
    }
    got_rules = {}
    for r in risks:
        got_rules[r["rule"]] = got_rules.get(r["rule"], 0) + 1
    for rule, expect in rule_expect.items():
        checks.append((f"规则 {rule} 命中 = {expect}", got_rules.get(rule, 0), expect))
    decoy_targets = {r["target"] for r in risks}
    for decoy in ("skill:password-policy-check", "tool:sandbox-exec.run_test",
                  "tool:threat-intel.lookup"):
        checks.append((f"诱饵 {decoy} 零告警", 0 if decoy not in decoy_targets else 1, 0))
    return checks


# ---------------------------------------------------------------- 主流程

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="静态 Agent 资产采集器")
    parser.add_argument("root", nargs="?", default=str(RANGE), help="扫描根目录")
    parser.add_argument("--output", default=None, help="输出目录（默认 solution/out）")
    parser.add_argument("--generic-only", action="store_true",
                        help="只加载通用规则，不使用目标 profile")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    out_dir = Path(args.output).expanduser().resolve() if args.output else \
        Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    rules = loader.load_rules(root, use_profile=not args.generic_only)

    compose = collect_compose(root)
    mcp_servers = collect_mcp_code(root, compose, rules)
    mcp_configs = collect_mcp_configs(root)
    # Merge config-only servers with source servers before risk analysis.
    for config in mcp_configs:
        current = next((item for item in mcp_servers if item["server"] == config["server"]), None)
        if current:
            current.setdefault("config_sources", []).extend(config.get("config_sources", []))
            current["config"] = config.get("config")
            current["transport"] = config.get("transport")
        else:
            mcp_servers.append(config)
    skills = collect_skills(root, rules)
    app = collect_app(root)
    env_items = collect_env_files(root)
    versions = collect_versions(root)
    packages = collect_packages(root, compose)
    plugins = collect_plugins(root, rules)
    models = collect_models(root, compose)
    agents = collect_agents(root, compose)
    model_files = collect_model_files(root)
    web_pages = collect_web_pages(root)
    flows = collect_flows(root)

    bundle = {"root": str(root), "compose": compose, "mcp_servers": mcp_servers,
              "skills": skills, "mcp_configs": mcp_configs, "app": app, "env_items": env_items,
              "versions": versions, "packages": packages, "plugins": plugins,
              "models": models, "model_files": model_files, "agents": agents,
              "web_pages": web_pages, "flows": flows}
    risks = run_rules(bundle, rules, use_profile=not args.generic_only)
    checks = reconcile(bundle, risks)
    bundle["risks"] = risks

    (out_dir / "scan.json").write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---- 控制台报告 ----
    print(f"=== 静态采集结果 root={root.name} ===\n")
    print(f"[服务 {len(compose['services'])} / 网络 {len(compose['networks'])}]")
    for s in compose["services"]:
        print(f"  {s['name']:<18} {s['category']:<10} nets={','.join(s['networks'])}"
              f" image={s['image'] or s['build']}")
    print(f"\n[MCP {len(mcp_servers)} / 工具 {sum(len(s['tools']) for s in mcp_servers)}]")
    for s in mcp_servers:
        flags = []
        if s["on_start"]:
            flags.append(f"on_start={s['on_start']}")
        hidden = [t["name"] for t in s["tools"] if t["hidden"]]
        if hidden:
            flags.append(f"hidden={hidden}")
        print(f"  {s['server']:<14} tools={[t['name'] for t in s['tools']]} {' '.join(flags)}")
    print(f"\n[Skills {len(skills)}]")
    for sk in skills:
        print(f"  {sk['name']:<22} allowed={sk['allowed_tools']} "
              f"scripts={len(sk['scripts'])} comments={len(sk['hidden_comments'])}")
    print(f"\n[身份 {len(app['identities'])}]")
    for i in app["identities"]:
        print(f"  {i['user']:<6} {i['role']:<14} scope={i['scope']}")
    print(f"\n[编排 flow {len(flows)}]  max_steps={app.get('max_steps')}")
    for f in flows:
        print(f"  {f['name']:<20} nodes={f['nodes']} mcp_tools={f['mcp_tools']}")
    print(f"\n[模型端点 {len(models)}]  {[m['name'] for m in models]}")
    print(f"\n[插件 {len(plugins)}]  {[p['name'] for p in plugins]}")
    print(f"\n[依赖包 {len(packages)}]")
    for package in packages:
        print(f"  {package['name']:<24} specs={package['version_specs']} "
              f"scopes={package['scopes']} owners={package['owners']}")
    print(f"\n[版本指纹]")
    for img, info in versions.items():
        print(f"  {img}:{info['version']}  ({info['source']})")

    print(f"\n=== 风险发现 {len(risks)} 项 ===")
    for r in sorted(risks, key=lambda x: {"high": 0, "medium": 1, "info": 2}[x["severity"]]):
        print(f"  [{r['severity']:<6}] {r['rule']:<24} {r['target']}")
        print(f"          {r['detail'][:100]}")
        print(f"          证据: {r['evidence']}  标签: {r['tag']}")

    print(f"\n=== 对账（预期 vs 实际）===")
    fails = 0
    for name, got, expect in checks:
        ok = got == expect
        fails += (not ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<38} got={got} expect={expect}")
    print(f"\n对账结果: {len(checks) - fails}/{len(checks)} 通过"
          f"{'  <-- 存在缺口' if fails else ''}")
    print(f"完整输出: {out_dir / 'scan.json'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
