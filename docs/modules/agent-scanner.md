---
type: module
covers: "reference/agent-scanner/**"
last_updated: 2026-09-14
---

# 队友项目 agent-scanner 事实档案（Agent 资产静态识别扫描器）

> 对象：`reference/agent-scanner/`（队友同期项目，v0.2.0，pyproject `requires-python >=3.11`）。
> 本文只记录**可核查的事实**（附 `file:line`），不含优劣评价；与 `solution/` 的差距分析、
> 融合与测试方案见 [../plans/融合与测试计划.md](../plans/融合与测试计划.md)。
> 实测数据为 2026-09-14 在本机（Windows / Python 3.14）跑出。

## 1. 定位

面向赛题**第一部分**（Agent 资产风险静态识别）的独立工具：给一个 Agent 环境目录，输出资产清单、
资产图谱、风险清单与 `file:line:snippet` 证据，并生成可离线查看的报告。
纯静态、无外联、断网可用（`README.md`）；**不含任何运行时检测、阻断或策略下发能力**。

## 2. 架构与数据流

| 模块 | 职责 |
|---|---|
| `agent_scanner/cli.py` | 子命令 `scan` / `serve` / `bench`；`--target/--output/--process/--network/--generic-only` |
| `agent_scanner/scanner.py` | 编排：`_discover → _build_graph → _analyze → _ensure_placeholder → build_summary` |
| `discovery/` | 文件遍历（2MB 上限）、配置/凭据文件分类、依赖包解析（requirements.txt / Dockerfile）、可选 psutil 进程与端口快照 |
| `identify/` | 9 个识别器：skills / mcp / agents / frameworks / models / configs / packages / services / runtime 增强 |
| `graph/builder.py` | 推断 9 类关系边；`add()` 统一丢弃悬空边与自环 |
| `risk/` | 6 个检测器 + `taint.py`（AST 常量折叠 / base64 还原 / 工具注册解析）+ `_util.py`（风险→资产五级回退，兜底 `unknown:unmapped`） |
| `report/` | 7 个产物：`assets.json` / `graph.json` / `risks.json` / `summary.json` / `bench.json` / `graph.html`（单文件）/ `report.md` |
| `bench/metrics.py` | 基线对照评测（四项指标） |
| `web/` | Flask 10 路由 + 内置 ECharts 前端 |

## 3. 闭集与规则

- **资产类型 13 种**（`identify/engine.py:27-41`）：agent / framework / model / skill / script / mcp_server /
  mcp_tool / service / endpoint / package / config / credential / unknown；每项带 `confidence` 与 `evidence[]`。
- **关系边 9 类**（`graph/builder.py:30-38`）：provides / uses / connects_to / loads / contains / serves /
  depends_on / configured_by / exposes。
- **风险类别 6 类**（`common/models.py:130-137`）：secret_leak / misconfig / malicious_skill / malicious_mcp /
  dangerous_capability / supply_chain；`malicious_type` ∈ prompt_injection / backdoor / data_exfiltration /
  command_execution / supply_chain。
- **规则外置三层 YAML**：`rules/generic/{fingerprints,config_risks,malicious_iocs}.yaml` + `rules/profile/<target>.yaml`；
  合并语义为"dict 递归合并、带 id/name 的列表按键覆盖"（`common/rules.py:95-148`，有单测）。
  profile 按**目标目录名归一化**匹配（`rules.py:52-62`），匹配不到即只用 generic（留出集刻意无 profile）。
- **`--generic-only`**：跳过 profile，用于单独度量通用层能力（`rules.py:154-156`）。

## 4. 度量机制（本项目最值得借鉴的部分）

- `bench/metrics.py` 每次运行算出四项指标：漏报率、盘点准确率、风险准确率、风险漏报率；
  分母为 0 时返回 `None`（`not_measured`）而非伪造 100%（`metrics.py:42-72`），并有测试禁止
  "空扫描 → 准确率 100% 且通过"（`tests/test_bench_baselines.py:67-76`）。
- 基线为**自建对照基线**（`provenance.kind = self-authored-baseline` + disclaimer），每条带 `source`；
  含**负样本陷阱**（合法工具/技能在这些资产上出恶意类判定即计误报）。
- 误报口径较窄：资产误报 = 非基准且非派生类型的检出；风险误报 = 负样本资产上的恶意类判定；
  其余超基准检出归入 `extra`（不计误报）。
- 官方靶场基线 `bench/agentrange-player.yaml`：23 资产 / 8 风险 / 12 负样本 / 8 派生类型 / 4 阈值。

## 5. 实测（本机，2026-09-14，官方靶场同靶对跑）

```
$ python -m agent_scanner bench --target <AgentRange-player>
扫描完成：资产 61，边 55，风险 20（耗时 646 ms）
资产 23/23、风险 8/8、负样本误报 0；漏报 0.00% / 盘点准确率 100% / 风险准确率 100% / 风险漏报 0.00%（四项通过）
```

- 实测资产分布：mcp_tool 10、mcp_server 8、package 8、config 8、skill 7、endpoint 6、credential 4、
  framework 3、service 3、agent 1、model 1、script 1、unknown 1。
- 实测 20 条风险覆盖：notes-sync（data_exfiltration / backdoor / prompt_injection）、pdf-export 脚本
  （command_execution）、meeting-summary（prompt_injection）、langflow 自动登录、service-account 传播、
  3 处弱凭据、postgres 弱口令、managed-host.env 明文凭据 ×4、危险能力 ×5（含 `attack/` 下的攻击脚本）。

## 6. 已知局限（事实清单）

1. **无运行时/事件级能力**：唯一"运行时"成分是可选 psutil 进程/端口快照，只作为证据附加，不参与判定。
2. **无阻断能力**：无代理、中间件或策略下发。
3. **依赖生态标准命名**：`SKILL.md`、`docker-compose.yml`、`.mcp.json` / `claude_desktop_config.json`、
   `requirements.txt` / `Dockerfile`、`.env` 与名字含 `secret(s)` 的文件；不使用这些约定的项目整体漏检。
4. **MCP 源码识别只认 `create_server("name")` 与 `Tool("name")`**（`identify/mcp.py:20-21`）：
   FastMCP 装饰器风格 `@mcp.tool()` 不在覆盖内（留出集 `simulated-target/mcp/evil-mcp/server.py` 即此形态）。
5. **由客户端配置（`.mcp.json`）产出的 mcp_server 无法做结构级恶意分析**：结构层检测把 `asset.path`
   当 Python 源码读取，而该 path 指向 JSON 配置文件本身，解析失败即返回空。
6. **通用层仍内嵌官方靶场形态字面量**：`create_server` / `class Tool`（`rules/generic/fingerprints.yaml:37-38`）、
   `run_stub_agent`（`:58`）、`MCP_SERVICES` / `OPENAI_TOOL_ROUTES`（`:42-43,61-62`），
   与 `identify/agents.py:20-45` 的默认值同源。仓库黑名单测试只覆盖 8 个字面量
   （`tests/test_rules_layering.py:17-36`）。
7. **产物无 schema/版本字段**：仅 `summary.json` 有 `tool_version`；`assets/graph/risks/bench.json` 均无版本元数据。
8. **文档与产物不一致**：README 称 `make scan/serve/test/bench`，仓库内无 Makefile；README 称 88 passed，
   `tests/` 实为 89 个 test 函数；根 README 快速开始代码块围栏提前闭合。
9. **若干规则键未被消费**：`hidden_tool_flag`、`startup_hook_markers`、`benign_allowlist.paths`、
   `mcp.config_hints`、`frameworks[].port`、基线 `thresholds.dangerous_capability_is_negative`。
10. **指标口径为自建基线**：官方未提供答案清单；四项指标的分母完全取决于自建 baseline 的条目数。

## 7. 与 solution/ 的交集

两侧都实现了赛题**第一部分**，资产闭集（13 类 vs 14 类）、关系边（9 vs 10）、风险族高度重叠
（弱凭据 / 配置风险 / 危险能力 / 供应链 / 恶意 Skill / 恶意 MCP），但口径不同，不能直接比较数量：
本机同靶对跑，对方 61 资产 / 20 风险，我们 57 节点 / 16 条静态发现 + 15 条包络 + 4 条运行时 = 35 条。
逐条差异与裁决见 [../plans/融合与测试计划.md](../plans/融合与测试计划.md) §2。
