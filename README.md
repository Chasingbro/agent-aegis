# Agent-Aegis（智盾）

面向 AI Agent 的安全防护系统 demo：**资产风险静态识别 + 运行时异常监控与阻断**。

当前为概念验证（PoC）阶段——已在 AgentRange 靶场环境完成功能与指标验证，供小组评估讨论，是否正式采用待定。

> 本仓库只包含自研算法/系统与文档；官方靶场 `AgentRange-player` 源码与官方作品模板不在仓库内，请按官方渠道另行获取。

**快速导航**：[系统架构](#1-系统架构) · [实测效果](#2-实测效果) · [使用方法](#3-使用方法) · [目录结构](#4-目录结构) · [下一步计划](#5-下一步计划) · [文档](#6-文档导航)

---

## 1. 系统架构

### 1.1 分层总览

```
┌──────────────────────── 采集层（11 通道）────────────────────────┐
│ 静态（8，collect_static.py，纯源码解析）                          │
│   compose   mcp_code   skills    app_code                       │
│   env_files versions   flows     web_pages                      │
│ 运行时（3，runtime/，快照式探测，需靶场在跑）                      │
│   mcp_probe  identity_probe  http_probe                         │
└──────────┬───────────────────────────────────────────────────────┘
           │ scan.json + runtime/*.json
           ▼
┌── 静态规则引擎 R1/R2/R3（16 发现，结构模式非关键词）───────────────┐
└──────────┬───────────────────────────────────────────────────────┘
           ▼
┌──────────────── 图谱层（graph/store.py，NetworkX 属性图）─────────┐
│ 14 类节点闭集 · declared/observed 双 facet · provenance           │
│ 57 节点 / 86 边 · JSON Schema 校验 + 引用完整性/双源对账校验器      │
└──────────┬──────────────────────────────────────▲────────────────┘
           │                                      │ observe.py（观测入图）
           ▼                                      │
┌── BOM 层（bom/，AgentRiskBOM 兼容）──────────┐   │
│ T1-T5 工具分级 · A1-A4 自主等级 · 6 输入评分  │   │
│ 控制映射 · 版本差分 · 声明-观测差分           │   │
└──────────┬──────────────────────────────────┘   │
           │ bom.json（2 agents）                  │
           ▼                                      │
┌── 推理层（graph/rules.py 包络校验 12 规则 + 差分）┴───────────────┐
│  35 条风险发现 = 静态 16 + 包络 15 + 运行时 4 + 校验器 0          │
└──────────┬───────────────────────────────────────────────────────┘
           ▼
┌── 展示 / 服务层（server/app.py + web/）───────────────────────────┐
│ FastAPI: /api/graph /api/bom /api/risks /api/summary             │
│          /api/baseline /api/judge /api/artifacts                 │
│ 前端三视图：资产图谱 / 权限包络(BOM) / 风险与控制（四来源标签）     │
└──────────────────────────────────────────────────────────────────┘

┌──────────────── aegis-guard（v1.0-asset-guard 增量）─────────────┐
│ runner ──► guard(反代, 提取 JWT → trace↔actor 绑定) ──► opspilot  │
│ opspilot ──MCP_*──► guard /mcp/{server} ──► 真实 MCP server      │
│          └─ api.judge_events（资产基线驱动 + 链路污点状态机）      │
│             block → JSON-RPC error（链路断而不崩）· JSONL 审计     │
└──────────────────────────────────────────────────────────────────┘
编排：cli.py（scan→graph→bom→import→runtime→verify 六步，可单步）
```

### 1.2 模块

| 模块 | 位置 | 说明 |
|---|---|---|
| **aegis-asset**（v1.0-asset） | `solution/`（`collect_static.py` / `graph/` / `bom/` / `rules/` / `runtime/` / `server/` / `web/`） | 11 条采集通道 → 属性图谱（声明/观测双面 + provenance）→ AgentRiskBOM → 包络校验 + 声明-观测差分双推理 → L1 工件 / L2 Python 库 / L3 REST 三层融合接口 |
| **aegis-guard**（v1.0-asset-guard） | `solution/guard/` | opspilot-app → MCP 的 `tools/call` 链路拦截代理：反代提取 JWT 绑定 trace↔actor → 与资产版同引擎、按资产基线逐事件判定 → `off/observe/enforce` 三模式（enforce 可阻断）→ JSONL 审计留痕 |

两模块共用一套资产基线：静态识别产出「工具清单 / 隐藏工具 / 身份 scope / 出网白名单」，运行时据此区分「合法出网 vs 恶意外传」「危险命名诱饵 vs 真后门」「正常前缀 vs 异常偏移」。

### 1.3 关键设计点

- **声明/观测双面**：每个资产节点同时保存「声明面」（源码/配置/manifest 推导）与「观测面」（运行时探测实证），检测即两者的差分；
- **基线驱动、零手写黑名单**：guard 的拦截规则全部由 `policy_baseline()` 从资产识别结果自动导出（隐藏工具禁用清单、身份 scope、通配符工具、敏感路径、出网白名单）；
- **多通道交叉印证**：隐藏后门 `debug_exec` 的证据来自三通道闭环——代码注册（`hidden=True`）∩ 应用路由映射 ∩ 运行时 `tools/list` 缺席；
- **误报控制机制**：规则全部为结构模式（禁止关键词规则）；白名单/诱饵降级（sandbox-exec 声明式白名单 → T2 不判恶意）；身份 scope 单向判定（无 scope 身份不触发越权信号）。

---

## 2. 实测效果

### 2.1 能力一：资产风险静态识别（aegis-asset）

| 项 | 值 |
|---|---|
| 资产对账 | **24/24**（14 服务 / 8 MCP / 10 工具含 1 隐藏 / 7 技能 / 5 身份 / 10 路由 + 规则期望 + 3 诱饵零告警） |
| 工具风险分级 | **10/10** 正确（含 sandbox-exec 白名单降级 T2、隐藏工具 T5） |
| 包络校验 vs 标准答案 | **12/12** |
| BOM 变异差分 | **10/10** |
| 完整性校验（schema / 引用 / 双源对账） | **0 违规** |
| 风险发现 | **35 条**（静态 16 / 包络 15 / 运行时 4 / 校验器 0） |
| 良性诱饵误报 | **0**（password-policy-check / sandbox-exec / threat-intel 全通过） |
| 单测 | **16/16**（集成用例无 Docker 自动跳过） |

### 2.2 能力二：运行时监控与阻断（aegis-guard 组合效果评测）

全量语料 replay（seed=1337，**5200 事件 / 80 恶意 / 5120 良性**）过 MCP 拦截代理，两相对比：

| 指标 | 无声明知识 | 有资产基线 | 赛题目标 |
|---|---|---|---|
| cat2 恶意检出（guard 可见 56 条） | 44 | **56/56** | ≥95% ✅ |
| cat2 恶意阻断 | 22 | **56/56** | — |
| 良性误标 | 0 | **0 / 5120** | <5% ✅ |
| 良性误阻断（业务中断） | 0 | **0** | 0 ✅ |
| 判定时延 avg / max | 0.056ms / 2.98ms | **0.052ms / 19.7ms** | <1000ms ✅ |
| 合并静态 C1 检出 | — | **80/80（100%）** | ≥95% ✅ |

**资产基线的增益（对比实验结论）**：

- 无声明知识相漏掉的 **12 条** 全部是 C2-A 越权——只有身份 scope 知识才能发现，纯内容规则原理上不可见；
- 阻断数 22 → 56 的差距来自「隐藏工具清单」（`debug_exec` 后门调用）与「scope」信号——同样只能来自资产识别；
- 判定引擎 CPU 开销可忽略（0.052ms/事件，每相 6521 次判定合计 <0.4s）；容器整体 CPU 为 HTTP 反代开销且属压测峰值工况。

完整报告：[solution/guard/EVAL_REPORT.md](solution/guard/EVAL_REPORT.md)

### 2.3 验收记录（单场景级）

| 验收项 | 结果 |
|---|---|
| 代理透明性（observe 模式） | C2-B 全量回放零差错，44 次调用全部过判定（avg 0.13ms） |
| 正确阻断（enforce 模式） | 11/11 个 C2-B 实例在 `notes-sync.debug_exec` 处阻断（105 分），应用侧优雅降级（链路断而不崩） |
| 良性零误伤 | B-SUP 全量 **1284 事件：0 告警 / 0 阻断 / 0 非零分** |
| 语义测试 | C2-A/B/C/D 四剧本全阻断；四良性模板 + 三诱饵全通过 |

---

## 3. 使用方法

### 3.1 环境要求

- Python 3.12+（`pip install -r solution/requirements.txt`）
- Docker + Docker Compose v2（仅 guard 部署与运行时探测需要）

### 3.2 A. 资产识别（不依赖靶场运行）

```bash
cd solution
pip install -r requirements.txt
python cli.py all              # 静态全流程（scan→graph→bom→import→runtime→verify）
python cli.py all --root <目录> # 指定其他项目根目录
python cli.py serve            # 前端与 REST @ http://127.0.0.1:8080
```

三层融合接口（队友监测系统接入，详见 [solution/README_集成.md](solution/README_集成.md)）：

```python
# L2 Python 库
from api import run_all, policy_baseline, judge_events
art  = run_all()                 # 全流程，工件带版本元数据
base = policy_baseline(art)      # 声明包络：工具清单/隐藏工具/scope/敏感路径/出网白名单
r    = judge_events([{"trace_id": "t1", "server": "notes-sync", "tool": "debug_exec",
                      "args": {"cmd": "curl x | sh"}}], base)
# => verdicts[0]: score=100, action='block', signals=['hidden_tool_call','dangerous_exec']
```

```bash
# L3 REST
curl http://127.0.0.1:8080/api/baseline            # 判定基线
curl -X POST http://127.0.0.1:8080/api/judge \
     -H "Content-Type: application/json" \
     -d '[{"trace_id":"t1","server":"notes-sync","tool":"debug_exec","args":{"cmd":"x"}}]'
curl -OJ http://127.0.0.1:8080/api/artifacts       # 全工件 zip（L1 工件契约）
```

前端三视图：**资产图谱**（14 类着色、隐藏工具虚线框、节点详情含声明/观测双面）· **权限包络**（评分、T1-T5 分级表、凭据 scope、审批门、治理弱点与控制建议）· **风险与控制**（35 条发现按来源/严重度筛选）。

### 3.3 B. 拦截代理（需靶场在跑）

```bash
cd 揭榜挑战赛赛题2靶场-AgentRange-player

# 上链（override 方式，不改靶场原文件）
docker compose -f docker-compose.yml \
  -f ../solution/guard/guard-compose.yml \
  -f ../solution/runtime/hostport.override.yml up -d --build

# 刷新资产基线（重扫后）
cd ../solution && python -c "import json; from api import policy_baseline; json.dump(policy_baseline(), open('out/baseline.json','w',encoding='utf-8'), ensure_ascii=False)"

# 回放（走 guard 入口；GUARD_MODE=off|observe|enforce）
OPSPILOT_BASE=http://localhost:18080 python scenario-runner/runner.py C2-B

# 状态与审计
curl http://127.0.0.1:18090/status
tail solution/guard/audit/guard.jsonl

# 两相全量评测（生成效果对比报告）
python solution/guard/evaluate.py
```

细节（判定信号表、模式开关、端口规避、架构图）见 [solution/guard/README.md](solution/guard/README.md)。

### 3.4 测试

```bash
cd solution && pytest -q     # 单元 + 回归 + 集成（无 Docker 环境自动跳过集成用例）
```

---

## 4. 目录结构

```
solution/
├── collect_static.py      # 8 条静态采集通道 + R1/R2/R3 规则引擎 + 对账
├── api.py                 # 库入口：run_all / policy_baseline / judge_events
├── cli.py                 # 编排：六步流水线 / 单步 / serve
├── requirements.txt / pytest.ini / README_集成.md
├── graph/                 # 属性图：store（14 类闭集）/ rules（包络 12 规则）/
│   │                      #   validators（完整性）/ export / schema/*.json
├── bom/                   # AgentRiskBOM：schema/tiers/autonomy/builder/scorer/
│                          #   controls/diff/importer
├── runtime/               # 运行时探测：mcp_probe / identity_probe / http_probe /
│                          #   observe（观测入图+差分）/ hostport.override.yml
├── rules/                 # 外置规则库（rules.yaml + loader）
├── server/ + web/         # FastAPI 服务 + 前端三视图（cytoscape 本地化）
├── guard/                 # 拦截代理：app.py / Dockerfile / guard-compose.yml /
│                          #   evaluate.py / README.md / EVAL_REPORT.md
├── tests/                 # 测试套件
├── oracle/                # 评测标准答案与评分脚本
└── out/                   # 生成物（gitignore：scan/graph/bom/基线/评测数据）
docs/                      # 项目知识库（导航见 docs/index.md）
```

---

## 5. 下一步计划

| 优先级 | 事项 | 说明 | 预估 |
|---|---|---|---|
| P0 | **与队友监测系统融合交接** | 交付 `release/v1.0-asset`（三层接口 + 集成文档），接入后做联合冒烟 | 依赖队友进度 |
| P1 | **审计链 STIX 化 + 前端阻断视图** | 当前审计为 JSONL 简版；赛题要求"完整攻击链路可追溯"（prompt → tool_calls → 阻断依据），输出 STIX 并在前端展示阻断事件 | 1~2 天 |
| P1 | **采集器插件化与路径泛化** | 去掉对靶场目录结构的依赖（全项目 AST 模式扫描 + 通道按特征激活），使系统可扫任意 Agent 项目 | 2 天（对应原《端到端动态扫描系统计划》P1） |
| P2 | **guard 转发开销优化** | 判定引擎开销可忽略（0.05ms/事件），容器 CPU 主要来自 HTTP 反代；ASGI 直通/旁路镜像可进一步压低 | 1 天 |
| P2 | **通用性自检（防过拟合）** | 改容器名/服务名/实例 ID 后重跑指标不退化，答辩加固项 | 0.5 天 |

完整优化 backlog（六维度 28 项 + 批次建议）见 [docs/plans/资产识别优化计划清单.md](docs/plans/资产识别优化计划清单.md)。

---

## 6. 文档导航

| 文档 | 内容 |
|---|---|
| [docs/index.md](docs/index.md) | 知识库导航（唯一入口） |
| [docs/architecture.md](docs/architecture.md) | 组件架构现状：采集通道清单、下游组件职责、数据流与工件、已知边界 |
| [docs/challenge.md](docs/challenge.md) | 赛题要求原文与量化指标 |
| [docs/modules/range.md](docs/modules/range.md) | 官方靶场逐文件分析：架构、风险/漏洞清单、攻击剧本、语料机制、取证点（"标准答案"） |
| [docs/plans/](docs/plans/) | 计划文档：资产识别实施计划 / 双版本发布计划 / 优化计划清单 |
| [docs/changelog.md](docs/changelog.md) | 项目统一变更日志 |
| [solution/README_集成.md](solution/README_集成.md) | 资产识别三层融合接口使用说明（供队友接入） |
| [solution/guard/README.md](solution/guard/README.md) | 拦截代理：架构、启用方式、判定信号表、模式开关 |
| [solution/guard/EVAL_REPORT.md](solution/guard/EVAL_REPORT.md) | 组合效果评测报告（两相对比） |

## 边界与合规说明

- 仓库仅含自研代码与文档；靶场源码、官方模板、已冻结的 `release/` 快照不入库（见 `.gitignore` 白名单）；
- 运行时探测与拦截实验均在本地官方靶场环境内进行（授权测试场景），不针对任何真实系统；
- 核心算法均为自研实现；未使用靶场 `/admin/trajectories` 接口（赛题明确约束）。
