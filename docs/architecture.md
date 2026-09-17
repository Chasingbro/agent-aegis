---
type: architecture
covers: "solution/**"
last_updated: 2026-09-15
---

# 组件架构文档（当前实现状态）

> 更新：2026-09-15。对应 solution/ 目录代码现状。P2 Package/FastMCP、目标 profile/oracle/bench 已接入原生采集链。
> 一句话：**12 条原生采集通道（9 静态 + 3 运行时，含 Package/FastMCP AST）+ 隔离调用队友 agent-scanner → canonical 融合图谱 → AgentRiskBOM / 双推理引擎 → 脱敏 FastAPI + Cytoscape 前端**。
> P0/P1/P2/P3 已完成：可靠生产 last-good peer 工件、两侧 canonical 融合、Package 原生依赖图、FastMCP AST/外泄检测、generic/profile 规则分层与统一留出集 bench。

---

## 1. 分层架构总览

```
┌─────────────────────────── 采集层（12 通道） ───────────────────────────┐
│                        静态（9，collect_static.py）                      │
│  compose    mcp_code(+FastMCP)  skills    app_code    packages           │
│  env_files  versions           flows     web_pages                      │
│                        运行时（3，runtime/，快照式探测）                  │
│  mcp_probe  identity_probe  http_probe                                  │
└──────────┬──────────────────────────────────────────────────────────────┘
           │ scan.json                     runtime/*.json
           ▼                               │
┌──── 静态规则引擎（R1/R2/R3，16 findings）┐ │
└──────────┬──────────────────────────────┘ │
           ▼                                ▼
┌──────────────────── 图谱层（graph/store.py）────────────────────────────┐
│  NetworkX 属性图：15 类节点闭集，declared/observed 双 facet + provenance │
│  原生官方靶场：65 节点 / 118 边；风险发现映射为节点 severity/risks       │
└──────────┬──────────────────────────────────────────────▲──────────────┘
           │ graph.json                                   │ observe.py（观测入图，
           ▼                                              │  17 节点带 observed）
┌──── BOM 层（bom/）───────┐                    ┌─────────┴──────────┐
│ schema/tiers/autonomy    │                    │ declared-vs-observed│
│ builder→scorer→controls  │                    │ 差分（bom/diff.py）  │
└──────────┬───────────────┘                    └─────────┬──────────┘
           │ bom.json（2 agents）                          │ runtime_findings.json
           ▼                                              │
┌──── 推理层（graph/rules.py 包络校验 12 规则）────────────┴──────────┐
│  静态 15 findings（含 GT 映射）+ 运行时 4 findings（实证升级）        │
└──────────┬──────────────────────────────────────────────────────────┘
           ▼
┌──── 融合与展示层（fusion/ + server/app.py + web/）──────────────────────┐
│  canonical：两引擎 ID/类型/边/风险归一化，graph-only 补齐，质量不变式       │
│  FastAPI：/api/dashboard（86 节点/155 边/51 风险）+ 兼容 API，全链路脱敏   │
│  原 Cytoscape 三视图继续消费兼容 API；队友 ECharts 主界面移植待后续          │
└───────────────────────────────────────────────────────────────────────┘
编排：cli.py（scan→graph→bom→import→runtime→verify 六步，可单步执行）
路径解析：range_root.py —— 靶场根目录唯一入口（`AgentRange-player` / 旧长名回退 + AGENT_RANGE_ROOT 覆盖），
          采集器 / 库入口 / CLI / guard 评测共用，代码内不再出现硬编码目录名
```

## 2. 采集器清单（12 条通道）

### 2.1 静态采集器（9，纯源码解析；mcp_code 含 FastMCP AST，packages 为新增通道）

| # | 采集器 | 函数 | 输入 | 技术 | 关键产出 |
|---|---|---|---|---|---|
| 1 | compose | `collect_compose` | docker-compose.yml | YAML 解析 | 14 服务、2 网络、镜像、env、URL 引用、构建 context/dockerfile、MCP 模块映射 |
| 2 | mcp_code | `collect_mcp_code` / `McpModuleScan` | `**/server.py` | **AST** | Tool/create_server + FastMCP 实例/装饰器、handler 能力、socket 外联与环境读取组合 |
| 3 | packages | `collect_packages` | requirements*.txt / Dockerfile | 行解析 + shell 逻辑指令 | PEP503 包名、版本约束、来源/行号、runtime/dev/attack scope、owner_entries |
| 4 | skills | `collect_skills` | skills/**/SKILL.md + scripts | YAML frontmatter + 正则 | allowed-tools、隐藏注释、脚本 SHA256、Base64 载荷解码 |
| 5 | app_code | `collect_app` | opspilot-app/api/app.py | AST | USERS 身份表（5，含 scope）、OPENAI_TOOL_ROUTES 路由（10）、SYSTEM_PROMPT、max_steps |
| 6 | env_files | `collect_env_files` | .env* / secrets / managed-host.env / Dockerfile ENV | 行解析 + 多行续行 | 配置声明面（弱密钥、服务账号、auto_login 的取值与出处） |
| 7 | versions | `collect_versions` | **/Dockerfile | FROM 行 + **ARG 变量替换 | 组件版本指纹（langflow 1.8.4 → CVE 匹配载体） |
| 8 | flows | `collect_flows` | langflow/flows/*.json | JSON | 编排 flow 资产（AgentFlow 节点、mcp_tools 挂载、model_base） |
| 9 | web_pages | `collect_web_pages` | attack/**/*.html | 正则注释提取 | 外部内容源（投毒页）注入载体 |

### 2.2 运行时探测器（3，需靶场在跑；容器名动态发现，零改动靶场）

P2 的 FastMCP 识别属于 `mcp_code` 静态通道，不新增运行时依赖；`get_config` 的环境读取 + socket `connect/sendall` 组合在静态阶段形成 `malicious_mcp/data_exfiltration` 发现。

| # | 探测器 | 通路 | 关键动作 | 产出 |
|---|---|---|---|---|
| 9 | mcp_probe | docker exec -i opspilot-app `python -`（stdin 注入，urllib JSON-RPC） | initialize + tools/list ×8 | 运行时广播工具清单（9 个）；`debug_exec` 缺席 → 隐藏工具运行时实证 |
| 10 | identity_probe | HTTP :8100 | 5 用户 /login + 弱密钥验签 + **伪造 ops-admin token** + 错密钥阴性对照 | 伪造 token 被接受（CWE-321 实证）、claims 观测 |
| 11 | http_probe | HTTP 宿主端口 | 组件指纹 + **c2-sink /receipts 聚合**（by_src、外传敏感键）+ 投毒页内容比对 | notes-sync 启动信标外传 JWT_SECRET/GPG_KEY（供应链后门铁证） |

### 2.3 观测集成器（1，非采集但属运行时链路）

| 组件 | 职责 |
|---|---|
| `runtime/observe.py` | 汇聚 runtime/*.json → 图节点 observed facet upsert（provenance=runtime:probe，17 节点）→ 调 `bom.diff.declared_vs_observed` 产出三类异常 → 生成 4 条 runtime findings |

## 3. 下游组件

| 组件 | 文件 | 职责 | 当前状态 |
|---|---|---|---|
| 静态规则引擎 | collect_static `run_rules` | R1 配置 / R2 供应链 / R3 版本 + FastMCP handler 外泄组合，**结构模式非关键词** | 官方 24/24；留出集外泄规则命中 |
| 图谱构建 | graph/store.py | 15 类节点闭集、声明/观测双面、Package 依赖边、provenance | 官方 65 节点 / 118 边；8 Package / 32 depends_on |
| 工具分级 | bom/tiers.py | capabilities+hidden+声明约束 → T1-T5 | 10/10 正确（白名单降级防误报） |
| 自主分级 | bom/autonomy.py | max_steps/审批门 → A1-A4 | OpsPilot=A3, flow=A2 |
| BOM 构建 | bom/builder.py | 图 → AgentRiskBOM（论文字段组兼容），`external_bom_refs.packages` 增量引用 | 2 agents；Package 不改变评分；round-trip 零丢失 |
| 评分器 | bom/scorer.py | 6 输入规则分 + 象限 | OpsPilot=100/high |
| 控制映射 | bom/controls.py | weakness/driver → 10 控制族 | 每风险 ≥1 控制 |
| 差分引擎 | bom/diff.py | ① 版本变异 diff（10 变异测试）② **declared-vs-observed 三类异常** | 10/10 + 4 异常 |
| 包络校验 | graph/rules.py | 12 条 ENV 规则（图遍历推导，与静态规则独立） | 12/12 标准答案覆盖 |
| 导入器 | bom/importer.py | BOM → 图 upsert + round-trip 校验 | 通过 |
| 服务端 | server/app.py | /api/graph /bom /risks(四来源) /summary /baseline /judge /artifacts | 35 findings |
| 前端 | web/ | 三视图 + observed 侧栏 + 来源标签 | 目视验收通过 |
| 拦截代理 | guard/app.py | MCP tools/call 逐事件判定 + 身份绑定 + 阻断 + JSONL 审计（v1.0-asset-guard） | 56/56 阻断、0 误报 |
| 编排 | cli.py | 六步原生流水线 + `peer-scan` 隔离执行 + serve | P0：peer last-good/状态/超时/锁已落地 |
| 队友扫描 runner | fusion/peer_runner.py、peer_io.py | 子进程隔离、路径约束、job 工件、严格校验、原子 current 指针 | 实测 61 资产 / 55 边 / 20 风险，约 899 ms |
| P2 原生采集 | collectors/packages.py、collect_static.py | Package 依赖盘点；FastMCP decorator/tool 与 socket 外泄 AST 识别 | 留出集 5 packages / 2 tools / 外泄风险命中 |
| canonical 融合 | fusion/models.py、ids.py、normalize_*.py、merge.py、payload.py | 双引擎节点/边/风险归一化、alias、质量报告、dashboard payload | 86 节点 / 155 边 / 51 风险 / 118 aliases；引用不变式全绿 |
| 对外脱敏 | fusion/redact.py、server/app.py | 两遍跨工件秘密发现；统一保护 dashboard/兼容 API/ZIP | 已知 JWT/service token/数据库凭据不出接口 |
| 测试 | tests/ | 单元 + 回归 + integration（无 Docker 跳过） | P2 后 38 passed / 2 skipped（含 Package/FastMCP/跨 target 回归） |

## 4. 数据流与工件

```
靶场源码 ──9 静态采集──► scan.json（含 packages）──规则──► 16 findings
                │                               │
                └──build_graph──► graph.json ───┴──(severity/risks)
                                      │
                          bom build/score/controls
                                      ▼
                                  bom.json ──import──► graph.enriched.json
                                      │                     ▲
运行中的靶场 ──3 探测──► runtime/*.json ──observe.py──┘（observed facet + 差分）
                                      │
                                      ▼
                        runtime/runtime_findings.json（4 findings）
                                      │
                                      ▼
        server/app.py ◄── 原生工件 + peer current ──► fusion-dashboard-v1
              │                                      86 节点 / 155 边 / 51 风险
              └── 两遍跨工件脱敏 ──► dashboard / 兼容 API / JSON ZIP
```

工件清单：`out/scan.json`、`out/graph.json`、`out/bom.json`、`out/graph.enriched.json`、`out/runtime/{mcp_tools,identity,http_fingerprint,runtime_findings}.json`；
队友扫描工件：`out/peer/jobs/<job-id>/`（不可变任务目录）、`out/peer/current.json`（last-good 指针）、`out/peer/status.json`（状态）。原始 peer 工件不进入 `/api/artifacts`。

## 5. 指标现状

| 指标 | 数值 |
|---|---|
| 静态采集对账 | 24/24（14 服务/8 MCP/10 工具/7 技能/5 身份/10 路由 + 13 规则期望 + 3 诱饵零告警） |
| 工具分级 | 10/10 |
| 包络校验 vs 标准答案 | 12/12 |
| 变异差分 | 10/10 |
| BOM round-trip | 零丢失 |
| 原生风险发现总量 | 35（静态 16 / 包络 15 / 运行时 4） |
| 融合风险总量 | 51（含 peer 发现；前端 dashboard） |
| 观测面覆盖 | 17 节点带 observed facet |
| 测试 | 38 passed / 2 skipped（P0-P2 runner、canonical、Package/FastMCP、API 与跨 target 回归；integration 无 Docker 自动跳过） |
| 融合图谱 | 88 canonical 节点 / 123 边 / 55 风险 / 120 aliases；0 悬空边、0 未解析风险 |
| 原生 P2 静态图 | 65 节点 / 118 边 / 8 Package / 32 depends_on；BOM 评分 100/44，validator 0 |
| guard 组合评测 | cat2 56/56 检出并阻断；良性 5120 条 0 误报；判定时延 avg 0.052ms |

## 6. 外部目标与留出环境

- `test-ranges/agent-asset-lab/` 是自有安全留出靶场：12 个服务、2 个网络、6 个独立 MCP 风格服务、扩展文件、PostgreSQL、模型桩和本地 canary sink；服务名、端口和目录刻意不同于官方 player。
- `solution/targets/profiles.yaml` 管理官方靶场、留出靶场和外部项目元数据；`solution/targets/bench.py` 用独立 oracle 计算目标级资产/风险召回率，并在目标或 oracle 缺失时返回 `not_measured`。
- 外部项目台账见 [`docs/modules/oss-ranges.md`](modules/oss-ranges.md) 和 `reference/oss-ranges/README.md`。首批候选为 DVAA、Appsecco MCP Lab、MCP Breach-to-Fix、Dify/LibreChat 和 LLMVault；无明确许可证的仓库不直接再分发。

## 7. 已知边界（下一步方向）

1. 探测为**快照式**；事件级监控（tools/call 拦截代理 + 逐事件差分 + 风险分 + 阻断）已在 v1.0-asset-guard 落地，审计链 STIX 化待做；
2. 静态采集对靶场内部**目录结构**有依赖（mcp/*/server.py 等），**插件化 + 结构泛化**（原《端到端动态扫描系统计划》P1，该计划原文未归档，仅存引用）未实施；靶场**根目录名**依赖已于 2026-09-14 收敛到 `range_root.py`（目录改名不再影响采集）；
3. runtime findings 目前进 out/runtime/，按 job 隔离未做；
4. audit 链还原（prompt/tool_calls/函数栈帧）guard JSONL 已覆盖简版，STIX 化未开始；运行时基线工件现在会自动创建输出目录，API 工件测试在 clean checkout 缺少 out/ 时明确跳过。

> 后续优化项的完整排期见 [《资产识别优化计划清单》](plans/资产识别优化计划清单.md)（六维度 28 项 + 批次建议）；
> 把本系统跑起来的实操步骤（依赖、`cli.py all` 期望值、前端/API、运行时探测、guard、排错）见
> [《solution 快速启动》](modules/solution-quickstart.md)。
