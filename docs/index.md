# 知识库导航

> 本目录是项目唯一知识库（doc-keeper 维护）。**不要再在工作区其他位置新建总结/计划类 md**；
> 新文档落位后必须回来同步本文件。最后更新：2026-09-17。

## 目录结构

```
docs/
├── index.md                            # 本导航
├── challenge.md                        # 赛题要求原文
├── architecture.md                     # solution 系统架构（现状）
├── modules/
│   ├── range.md                        # 靶场 AgentRange 信息整理（10 章）
│   ├── range-quickstart.md             # 靶场快速启动与回放实操（实测命令）
│   ├── solution-quickstart.md          # 我方 demo 快速启动（静态全流程/前端/运行时/guard）
│   ├── agent-scanner.md                # 队友项目事实档案（闭集/规则/度量/实测/局限）
│   ├── oss-ranges.md                   # 开源靶场台账、自有留出环境与 profile/oracle/bench
│   └── taxonomy-comparison.md          # 恶意维度对照表（三数据集 taxonomy × generic 规则现状）
├── plans/                              # 计划文档（含状态标注）
│   ├── 资产识别实施计划.md              # 第一阶段 P0-P5（已完成）
│   ├── 资产识别优化计划清单.md          # 六维度 28 项优化 backlog（进行中）
│   ├── 双版本发布计划.md                # v1.0-asset / v1.0-asset-guard（已完成）
│   ├── 融合与测试计划.md                # 与队友 scanner 的融合计划（P0–P3 已完成，进入前端融合准备）
│   └── 论文对照静态检测计划.md          # 外部数据集反哺计划（P0/P1 已完成，P2 待启动）
├── decisions/                          # ADR 技术决策（首个条目出现时创建，按 NNN-短标题.md）
├── changelog.md                        # 项目统一变更日志
└── archive/
    └── 资产识别优化清单-设计草稿.md     # 已被正式清单取代的会话草稿
```

> 工作区根目录的 `AgentRange-player/`（官方靶场源码，旧名 `揭榜挑战赛赛题2靶场-AgentRange-player/`）
> 与 `reference/`（队友 `agent-scanner` 项目、官方作品 doc 模板）是**外部材料**：落在 `.gitignore`
> 白名单之外、不入库，也不属于本知识库；对它们的整理结论写在 [modules/range.md](modules/range.md)
> 与工作区根的 `AGENTS.md`。

## 文档索引

| 文档 | 类型/状态 | 内容 |
|---|---|---|
| [challenge.md](challenge.md) | 原文 | 赛题两大能力要求与量化指标原文照录 |
| [architecture.md](architecture.md) | 状态型，2026-09-15 | solution 现状：12 原生采集通道（9 静态 + 3 运行时，含 Package/FastMCP）+ peer runner → canonical 融合图谱 → BOM/脱敏 API |
| [modules/range.md](modules/range.md) | 状态型，2026-09-14 | 官方靶场逐文件分析：架构、组件、风险/漏洞清单、攻击剧本、语料机制、取证点（静态识别与运行时检测的"标准答案"） |
| [modules/range-quickstart.md](modules/range-quickstart.md) | 操作型，2026-09-14 | 靶场快速启动：依赖、4 步启动、make 的原生命令替代、场景代号与回放、攻击落地取证、guard override、排错表 |
| [modules/solution-quickstart.md](modules/solution-quickstart.md) | 操作型，2026-09-15 | 我方 demo 快速启动：原生全流程、peer-scan、融合 dashboard API、运行时探测、guard、工件与排错 |
| [modules/agent-scanner.md](modules/agent-scanner.md) | 状态型，2026-09-14 | 队友项目 agent-scanner 事实档案：架构与数据流、13 类资产 / 9 类边 / 6 检测器、规则三层外置与 bench 度量机制、同靶实测数据、已知局限 |
| [modules/oss-ranges.md](modules/oss-ranges.md) | 状态型，2026-09-15 | 开源 Agent/MCP 靶场台账、自有 agent-asset-lab 留出环境、目标 profile、oracle 与 bench |
| [modules/taxonomy-comparison.md](modules/taxonomy-comparison.md) | 状态型，2026-09-17 | P1 产出：SkillTrustBench/MalSkillBench/MCPTox taxonomy × 我方 generic 规则逐维对照（37 维），P2 规则增强排序输入 |
| [plans/资产识别实施计划.md](plans/资产识别实施计划.md) | 计划，已完成 | 能力 1 第一阶段：通道矩阵、ground truth、R1/R2/R3 规则、验收与时间线（实际落地差异见文首标注） |
| [plans/资产识别优化计划清单.md](plans/资产识别优化计划清单.md) | 计划，进行中 | 六维度 28 项优化（采集/Schema/展示/证明/推理/约束）+ 5 个批次建议 + 依赖关系 + 不做清单 |
| [plans/双版本发布计划.md](plans/双版本发布计划.md) | 计划，已完成 | A 资产识别融合版 + B 拦截代理实验版的交付计划（三层融合接口、评测对比） |
| [plans/融合与测试计划.md](plans/融合与测试计划.md) | 计划，P0–P3 已完成 | peer runner、canonical 合并、Package/FastMCP 原生静态能力、规则分层与统一 bench；下一阶段为前端融合 |
| [plans/论文对照静态检测计划.md](plans/论文对照静态检测计划.md) | 计划，进行中（P0/P1 已完成） | 用 MalSkillBench/MCPTox/SkillTrustBench 的恶意维度 taxonomy 与样本反哺 generic 规则与采集器，建立靶场外的外部回归证据（P0–P4） |
| [changelog.md](changelog.md) | 事件型 | v1.0-asset / v1.0-asset-guard 交付记录；新条目追加于此 |

## 代码随附文档（留在代码目录，不迁入 docs/）

| 文档 | 说明 |
|---|---|
| `solution/README_集成.md` | v1.0-asset 三层融合接口使用说明（L1 工件 / L2 Python 库 / L3 REST），供队友监测系统接入 |
| `solution/guard/README.md` | 拦截代理架构、启用方式（compose override）、判定信号表、模式开关 |
| `solution/guard/EVAL_REPORT.md` | 全量 replay 两相评测报告（固化副本；生成物默认落 out/eval/） |
| `release/v1.0-asset*/`（README、CHANGELOG、快照） | 已交付版本的冻结快照，勿改 |

## 已知问题

- 《端到端动态扫描系统计划》被 [architecture.md](architecture.md) §6 与 [优化计划清单](plans/资产识别优化计划清单.md) 引用，
  但原文不在工作区（可能产生于未落盘的讨论）。做优化项 A1（采集器插件化）前如仍找不到，由 A1 设计文档重述其 P1 内容。
- `AGENTS.md`（工作区根目录）是给 Agent 的本地上下文入口（含内部信息，**不入仓库**），
  不属于本知识库，但其中的目录索引与本文件需保持一致。
