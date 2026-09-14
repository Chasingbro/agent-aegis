---
type: architecture
covers: "solution/**"
last_updated: 2026-09-11
---

# 组件架构文档（当前实现状态）

> 更新：2026-09-11。对应 solution/ 目录代码现状。
> 一句话：**11 条采集通道（8 静态 + 3 运行时）→ 属性图谱（声明/观测双面）→ AgentRiskBOM → 双推理引擎（包络校验 + 声明-观测差分）→ FastAPI + Cytoscape 前端三视图**。

---

## 1. 分层架构总览

```
┌─────────────────────────── 采集层（11 通道） ───────────────────────────┐
│                        静态（8，collect_static.py）                      │
│  compose    mcp_code    skills    app_code                              │
│  env_files  versions    flows     web_pages                             │
│                        运行时（3，runtime/，快照式探测）                  │
│  mcp_probe  identity_probe  http_probe                                  │
└──────────┬──────────────────────────────────────────────────────────────┘
           │ scan.json                     runtime/*.json
           ▼                               │
┌──── 静态规则引擎（R1/R2/R3，16 findings）┐ │
└──────────┬──────────────────────────────┘ │
           ▼                                ▼
┌──────────────────── 图谱层（graph/store.py）────────────────────────────┐
│  NetworkX 属性图：14 类节点闭集，declared/observed 双 facet + provenance │
│  57 节点 / 75+ 边；风险发现映射为节点 severity/risks                     │
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
┌──── 展示层（server/app.py + web/）──────────────────────────────────┐
│  FastAPI: /api/graph /api/bom /api/risks /api/summary               │
│  前端三视图：资产图谱 / 权限包络(BOM) / 风险与控制（来源三标签）        │
└─────────────────────────────────────────────────────────────────────┘
编排：cli.py（scan→graph→bom→import→runtime→verify 六步，可单步执行）
```

## 2. 采集器清单（11 条通道）

### 2.1 静态采集器（8，纯源码解析，不依赖靶场运行）

| # | 采集器 | 函数 | 输入 | 技术 | 关键产出 |
|---|---|---|---|---|---|
| 1 | compose | `collect_compose` | docker-compose.yml | YAML 解析 | 14 服务、2 网络、镜像、env、URL 引用、`SERVER=<mod>.server` → MCP 模块映射 |
| 2 | mcp_code | `collect_mcp_code` | mcp/*/server.py | **AST** | Tool 注册表（含 hidden）、on_start、handler 能力（subprocess/文件/出网/env/通配符）、描述常量回溯 |
| 3 | skills | `collect_skills` | skills/**/SKILL.md + scripts | YAML frontmatter + 正则 | allowed-tools、正文隐藏注释、脚本 SHA256、**Base64 载荷解码** |
| 4 | app_code | `collect_app` | opspilot-app/api/app.py | AST | USERS 身份表（5，含 scope）、OPENAI_TOOL_ROUTES 路由（10）、SYSTEM_PROMPT、max_steps |
| 5 | env_files | `collect_env_files` | .env* / secrets / managed-host.env / Dockerfile ENV | 行解析 + 多行续行 | 配置声明面（弱密钥、服务账号、auto_login 的取值与出处） |
| 6 | versions | `collect_versions` | **/Dockerfile | FROM 行 + **ARG 变量替换** | 组件版本指纹（langflow 1.8.4 → CVE 匹配载体） |
| 7 | flows | `collect_flows` | langflow/flows/*.json | JSON | 编排 flow 资产（AgentFlow 节点、mcp_tools 挂载、model_base） |
| 8 | web_pages | `collect_web_pages` | attack/**/*.html | 正则注释提取 | 外部内容源（投毒页）注入载体 |

### 2.2 运行时探测器（3，需靶场在跑；容器名动态发现，零改动靶场）

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
| 静态规则引擎 | collect_static `run_rules` | R1 配置 / R2 供应链 / R3 版本，**结构模式非关键词**，负规则防诱饵误报 | 16 findings；3 诱饵零误报；对账 24/24 |
| 图谱构建 | graph/store.py | 14 类节点闭集、声明/观测双面、provenance、风险→节点 severity | 57 节点 / 75 边 |
| 工具分级 | bom/tiers.py | capabilities+hidden+声明约束 → T1-T5 | 10/10 正确（白名单降级防误报） |
| 自主分级 | bom/autonomy.py | max_steps/审批门 → A1-A4 | OpsPilot=A3, flow=A2 |
| BOM 构建 | bom/builder.py | 图 → AgentRiskBOM（论文字段组兼容） | 2 agents；round-trip 零丢失 |
| 评分器 | bom/scorer.py | 6 输入规则分 + 象限 | OpsPilot=100/high |
| 控制映射 | bom/controls.py | weakness/driver → 10 控制族 | 每风险 ≥1 控制 |
| 差分引擎 | bom/diff.py | ① 版本变异 diff（10 变异测试）② **declared-vs-observed 三类异常** | 10/10 + 4 异常 |
| 包络校验 | graph/rules.py | 12 条 ENV 规则（图遍历推导，与静态规则独立） | 12/12 标准答案覆盖 |
| 导入器 | bom/importer.py | BOM → 图 upsert + round-trip 校验 | 通过 |
| 服务端 | server/app.py | /api/graph /bom /risks(四来源) /summary /baseline /judge /artifacts | 35 findings |
| 前端 | web/ | 三视图 + observed 侧栏 + 来源标签 | 目视验收通过 |
| 拦截代理 | guard/app.py | MCP tools/call 逐事件判定 + 身份绑定 + 阻断 + JSONL 审计（v1.0-asset-guard） | 56/56 阻断、0 误报 |
| 编排 | cli.py | 六步流水线 + 单步 + serve | 全绿；runtime 步可优雅跳过 |
| 测试 | tests/ | 单元 + 回归 + integration（无 Docker 跳过） | 16/16 |

## 4. 数据流与工件

```
靶场源码 ──8 静态采集──► scan.json ──规则──► 16 findings
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
        server/app.py ◄── 所有工件 ──► web 三视图（35 findings = 16+15+4）
```

工件清单：`out/scan.json`、`out/graph.json`、`out/bom.json`、`out/graph.enriched.json`、`out/runtime/{mcp_tools,identity,http_fingerprint,runtime_findings}.json`

## 5. 指标现状

| 指标 | 数值 |
|---|---|
| 静态采集对账 | 24/24（14 服务/8 MCP/10 工具/7 技能/5 身份/10 路由 + 13 规则期望 + 3 诱饵零告警） |
| 工具分级 | 10/10 |
| 包络校验 vs 标准答案 | 12/12 |
| 变异差分 | 10/10 |
| BOM round-trip | 零丢失 |
| 风险发现总量 | 35（静态 16 / 包络 15 / 运行时 4） |
| 观测面覆盖 | 17 节点带 observed facet |
| 测试 | 16/16（integration 无 Docker 自动跳过） |
| guard 组合评测 | cat2 56/56 检出并阻断；良性 5120 条 0 误报；判定时延 avg 0.052ms |

## 6. 已知边界（下一步方向）

1. 探测为**快照式**；事件级监控（tools/call 拦截代理 + 逐事件差分 + 风险分 + 阻断）已在 v1.0-asset-guard 落地，审计链 STIX 化待做；
2. 静态采集对靶场路径有依赖（mcp/*/server.py 等），**插件化 + 路径泛化**（原《端到端动态扫描系统计划》P1，该计划原文未归档，仅存引用）未实施；
3. runtime findings 目前进 out/runtime/，按 job 隔离未做；
4. audit 链还原（prompt/tool_calls/函数栈帧）guard JSONL 已覆盖简版，STIX 化未开始。

> 后续优化项的完整排期见 [《资产识别优化计划清单》](plans/资产识别优化计划清单.md)（六维度 28 项 + 批次建议）。
