---
type: module
covers: "test-ranges/**"
last_updated: 2026-09-15
---

# 外部 Agent 安全靶场与留出环境

## 职责

本模块维护可用于资产探测泛化评测的外部项目台账、自有安全留出靶场、目标 profile 和独立 oracle。第三方源码不默认 vendor；自有靶场用于在不修改官方 player 的前提下复现相同资产关系类别。

## 关键文件与入口

| 路径 | 说明 |
|---|---|
| `reference/oss-ranges/README.md` / `projects.yaml` | 开源项目来源、许可证状态、部署方式、缓存状态和安全边界 |
| `test-ranges/agent-asset-lab/docker-compose.yml` | 自有留出靶场的 12 服务、2 网络和本地 canary 边界 |
| `test-ranges/agent-asset-lab/README.md` | 启动、停止、扫描和安全约束 |
| `solution/targets/profiles.yaml` | 官方、留出和外部目标的 profile 元数据 |
| `solution/targets/oracle-agent-asset-lab.yaml` | 不被扫描器读取的留出环境真值 |
| `solution/targets/bench.py` | 目标扫描与 oracle 对账入口 |
| `solution/collect_static.py` | 通用 Compose/MCP/Skill/依赖采集入口 |

## 数据流与依赖

`test-ranges/agent-asset-lab` 通过 Compose 提供 Agent、模型桩、框架 fixture、PostgreSQL、6 个 MCP 风格服务、扩展文件和 core/edge 双网络。`solution/collect_static.py <root>` 解析源码与配置，生成 `solution/out/scan.json`；`python solution/cli.py bench --root <root>` 再加载外部 oracle，报告可测的资产与风险召回率。oracle 不放在目标目录，避免扫描器读取标签。

第三方目标按 profile 单独运行：DVAA 适合多 Agent/MCP/A2A，Appsecco 适合 MCP 供应链，Breach-to-Fix 适合 vulnerable/secure 对照，LLMVault 适合低资源离线回归；详细许可限制见台账。

## 已知问题

- 当前留出环境的通用 bench 已接入，但资产匹配仍是保守的 source/标识符匹配，不等同于最终精确图谱对账。
- 自有留出环境的 MCP 代码采用最小 FastAPI fixture；它不模拟真实攻击，也不应作为运行时阻断性能基准。
- 未验证许可证的第三方项目只可作为外部参考，不能直接复制进发布物。

## 变更历史

- 2026-09-15：新增开源项目台账、自有 `agent-asset-lab` 留出环境、profile/oracle/bench 契约，目的在于验证探测器不依赖官方靶场字面量。
