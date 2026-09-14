# 知识库导航

> 本目录是项目唯一知识库（doc-keeper 维护）。**不要再在工作区其他位置新建总结/计划类 md**；
> 新文档落位后必须回来同步本文件。最后更新：2026-09-11。

## 目录结构

```
docs/
├── index.md                            # 本导航
├── challenge.md                        # 赛题要求原文
├── architecture.md                     # solution 系统架构（现状）
├── modules/
│   └── range.md                        # 靶场 AgentRange 信息整理（10 章）
├── plans/                              # 计划文档（含状态标注）
│   ├── 资产识别实施计划.md              # 第一阶段 P0-P5（已完成）
│   ├── 资产识别优化计划清单.md          # 六维度 28 项优化 backlog（进行中）
│   └── 双版本发布计划.md                # v1.0-asset / v1.0-asset-guard（已完成）
├── decisions/                          # ADR 技术决策（暂无条目，按 NNN-短标题.md 追加）
├── changelog.md                        # 项目统一变更日志
└── archive/
    └── 资产识别优化清单-设计草稿.md     # 已被正式清单取代的会话草稿
```

## 文档索引

| 文档 | 类型/状态 | 内容 |
|---|---|---|
| [challenge.md](challenge.md) | 原文 | 赛题两大能力要求与量化指标原文照录 |
| [architecture.md](architecture.md) | 状态型，2026-09-11 | solution 现状：11 采集通道 → 图谱 → BOM → 双推理引擎 → 服务端/前端，指标与已知边界 |
| [modules/range.md](modules/range.md) | 状态型，2026-09-09 | 官方靶场逐文件分析：架构、组件、风险/漏洞清单、攻击剧本、语料机制、取证点（静态识别与运行时检测的"标准答案"） |
| [plans/资产识别实施计划.md](plans/资产识别实施计划.md) | 计划，已完成 | 能力 1 第一阶段：通道矩阵、ground truth、R1/R2/R3 规则、验收与时间线（实际落地差异见文首标注） |
| [plans/资产识别优化计划清单.md](plans/资产识别优化计划清单.md) | 计划，进行中 | 六维度 28 项优化（采集/Schema/展示/证明/推理/约束）+ 5 个批次建议 + 依赖关系 + 不做清单 |
| [plans/双版本发布计划.md](plans/双版本发布计划.md) | 计划，已完成 | A 资产识别融合版 + B 拦截代理实验版的交付计划（三层融合接口、评测对比） |
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
- `AGENTS.md`（工作区根目录）是给 Agent 的上下文入口，不属于本知识库，但其中的目录索引与本文件需保持一致。
