---
type: module
covers: "reference/agent-scanner/**"
last_updated: 2026-09-17
---

# 队友项目 agent-scanner 事实档案（Agent 资产静态识别扫描器）

> 对象：`reference/agent-scanner/`（队友同期项目，2026-09-17 拉取；扫描器 pyproject 仍为
> `version = "0.2.0"`、`requires-python >=3.11`）。本文只记录**可核查的事实**（附 `file:line`），
> 不含优劣评价；与 `solution/` 的差距分析、融合与测试方案见
> [../plans/融合与测试计划.md](../plans/融合与测试计划.md)。
> 实测数据为 2026-09-17 在本机复跑（Windows / `uv run --with pyyaml`，非队友 venv 环境）。

## 0. 仓库顶层构成（2026-09-17 版）

| 路径 | 状态 | 说明 |
|---|---|---|
| `赛事概况.md` | **新增** | 队伍联合总体架构文档 v1.0（见 §8） |
| `README.md` | **新增/重写** | 项目门户：特性、命令、输出、实测结果、提交边界 |
| `agent-scanner/` | 功能扩充 | 扫描器本体（§1–§6） |
| `simulated-target/` | 沿用 | 自建留出集（LangChain + MCP 模拟环境） |
| `third-party-targets/` | 沿用 | 公开语料风格留出集（skill-holdout / mcp-holdout） |
| `filterC2/` | **新增** | 队友运行时侧实验数据（见 §7） |

## 1. 定位

面向赛题**第一部分**（Agent 资产风险静态识别）的独立工具：给一个 Agent 环境目录，输出资产清单、
资产图谱、风险清单与 `file:line:snippet` 证据，并生成可离线查看的报告。
纯静态、无外联、断网可用；**扫描器本体不含运行时检测、阻断或策略下发能力**（运行时动向见 §7–§8）。

## 2. 架构与数据流

| 模块 | 职责 |
|---|---|
| `agent_scanner/cli.py` | 子命令 `scan` / `serve` / `bench`；`--target/--output/--process/--network/--generic-only/--profile` |
| `agent_scanner/target_source.py` | **新增**：目标解析统一入口，四种输入——目录、zip/tar 压缩包（安全解压）、`docker://`（`target_source.py:56-57`，只读快照挂载目录/WorkingDir/常见应用目录）、`http(s)://`（`:58`，探测 /health、OpenAPI、MCP initialize+tools/list） |
| `agent_scanner/scanner.py` | 编排：discover → build_graph → analyze → export |
| `discovery/` | 文件遍历（2MB 上限）、配置/凭据文件分类、依赖包解析、可选 psutil 进程与端口快照 |
| `identify/` | 识别器：skills / mcp / agents / frameworks / models / configs / packages / services / runtime / **remote（新增）** |
| `identify/remote.py` | **新增**：把 HTTP/Docker 采集产物 `remote-inventory.json` 转成统一 Asset 模型，显式 partial 置信度（`remote.py:1-8`） |
| `graph/builder.py` | 推断 9 类关系边；丢弃悬空边与自环 |
| `risk/` | 6 个检测器 + `taint.py`（AST 常量折叠 / base64 还原）+ `_util.py`（风险→资产五级回退） |
| `report/` | 7 个产物：`assets/graph/risks/summary/bench.json`、`graph.html`（单文件离线）、`report.md` |
| `bench/metrics.py` | 基线对照评测（四项指标） |
| `web/` | Flask 9 路由（`web/app.py:33-147`）+ 内置 ECharts 六视图（概览/资产图谱/**攻击链拓扑**/资产清单/风险清单/评测对照） |

## 3. 闭集与规则

- **资产类型 13 种**（`identify/engine.py` `TYPE_ORDER`）：agent / framework / model / skill / script /
  mcp_server / mcp_tool / service / endpoint / package / config / credential / unknown；每项带
  `confidence` 与 `evidence[]`。
- **关系边 9 类**（`graph/builder.py:29-37`）：provides / uses / connects_to / loads / contains /
  serves / depends_on / configured_by / exposes。
- **风险类别 6 类**（`common/models.py:130-137`）：secret_leak / misconfig / malicious_skill /
  malicious_mcp / dangerous_capability / supply_chain；`malicious_type` ∈ prompt_injection /
  backdoor / data_exfiltration / command_execution / supply_chain。
- **规则外置三层 YAML**：`rules/generic/{fingerprints,config_risks,malicious_iocs}.yaml` +
  `rules/profile/<target>.yaml`；合并语义"dict 递归合并、带 id/name 的列表按键覆盖"。
- **profile 匹配升级（本次新增）**：`--profile auto` 先按目标目录名匹配，匹配不到再按 profile 内
  **源码指纹**匹配（`common/rules.py:78,94-99` `_match_profile_by_fingerprint`）——目标目录改名后
  仍可命中环境适配层；`none` 强制只用通用层，`--generic-only` 保留为通用能力度量口径。

## 4. 度量机制

- `bench/metrics.py` 四项指标：漏报率、盘点准确率、风险准确率、风险漏报率；分母为 0 返回
  `not_measured` 而非伪造 100%；有测试禁止"空扫描 → 满分通过"。
- 基线为自建对照基线（`provenance.kind = self-authored-baseline` + disclaimer），每条带 `source`；
  含负样本陷阱（合法资产上出恶意类判定即计误报）。误报口径较窄：超基准检出归 `extra` 不计误报。
- **基线现为 4 份**（2026-09-17 用 PyYAML 实测条目数）：

| 文件 | 环境 | 基准资产 | 基准风险 | 负样本 |
|---|---|---|---|---|
| `bench/agentrange-player.yaml` | 官方靶场 | 23 | **10**（09-14 为 8） | 12 |
| `bench/simulated-target.yaml` | 自建留出集 | 11 | 6 | 2 |
| `bench/skill-holdout.yaml` | Skill 留出集 | 5 | 2 | 3 |
| `bench/mcp-holdout.yaml` | MCP 留出集 | 3 | 3 | 2 |

## 5. 实测（本机复跑，2026-09-17）

```
$ uv run --with pyyaml python -m agent_scanner bench --target <AgentRange-player>
扫描完成：资产 61，边 55，风险 22（耗时 2.4 s）
资产 23/23、风险 10/10、负样本误报 0；四项指标全部通过（漏报 0.00% / 准确率 100%）

$ ... bench --target ../simulated-target            # 留出集，含 profile
扫描完成：资产 23，边 7，风险 10（耗时 0.4 s）
资产 11/11、风险 2/6、负样本误报 0；风险漏报率 66.67% —— 未通过

$ ... bench --target ../simulated-target --generic-only
结果与含 profile 完全一致（留出集无 profile，符合设计）
```

- **留出集风险 2/6（漏报 4 条，bench.json `risks.missing`）**：
  ① `plaintext-api-key`（app/.env 明文 API Key）；
  ② `mcp-filesystem-overreach`（configs/.mcp.json 文件系统权限过大）；
  ③ `mcp-remote-no-auth`（configs/.mcp.json 远程无鉴权）；
  ④ `malicious-mcp-exfiltration`（mcp/evil-mcp/server.py 环境变量外泄，FastMCP 装饰器风格）。
  四条均对应 §6 既有局限（配置级 MCP 风险、FastMCP 形态、明文 key 词根）。
- **注意**：顶层 README 实测结果表只展示主靶场四项全过 + 留出集资产 11/11；留出集风险 2/6
  仅以"退出码 1（风险项未全部达标）"带过，未公开数字。README 声称测试 120 passed，
  `tests/` 实测 113 个 test 函数（含参数化差异）。
- 误报面干净：两个环境负样本均 0 误报；留出集 10 条检出风险中 8 条为 `extra` 扩展发现
  （危险能力 ×2、供应链未固定版本 ×6），按其口径不计误报。

## 6. 已知局限（2026-09-17 复核）

仍在：
1. **无运行时/事件级能力**（扫描器本体）：唯一"运行时"成分是可选 psutil 进程/端口快照。
2. **无阻断能力**。
3. **MCP 源码识别只认 `create_server("name")` 与 `Tool("name")`**（`identify/mcp.py:20` `SERVER_RE`、
   `:31` `server_code` 默认值）：FastMCP 装饰器风格 `@mcp.tool()` 仍不覆盖（留出集 evil-mcp 即此形态，
   直接导致 §5 漏报④）。
4. **由客户端配置（.mcp.json）产出的 mcp_server 无法做结构级恶意分析**，配置级 misconfig 规则
   （文件系统过权 / 远程无鉴权）也未覆盖该形态（§5 漏报②③）。
5. **通用层仍内嵌官方靶场形态字面量**：`create_server`（`rules/generic/fingerprints.yaml:37`）、
   `MCP_SERVICES` / `OPENAI_TOOL_ROUTES`（`:42-43,62`）、`run_stub_agent`（`:58`）。
6. **产物无 schema/版本字段**：仅 `summary.json` 有 `tool_version`（`report/exporter.py:32`、
   `report/payload.py:21`）。
7. **若干规则键未被消费**：`hidden_tool_flag`、`startup_hook_markers`、`mcp.config_hints`。
8. **指标口径为自建基线**：官方未提供答案清单，四项指标分母取决于自建 baseline 条目数。

已修复（09-14 版局限消除）：
- README 虚构 `make` 命令问题已改（现明确"只有一种运行方式"并补 Windows 说明）。
- `benign_allowlist` 规则键已被消费（`risk/malicious.py`）。
- 目标仅支持本地目录的限制已消除（四种输入，§2）。
- profile 仅按目录名匹配的限制已消除（指纹回退匹配，§3）。

## 7. filterC2/（新增，队友运行时侧实验）

- `filter.py`：JSONL 日志过滤脚本，保留 `kind == "attack"` 的行（支持 stdin/stdout 与文件参数，
  统计打 stderr）。
- `log.json`：11,586 行 JSONL 的运行时监控评估日志，每行字段
  `time / no / instance / scenario / kind(benign|attack) / prompt / calls / blocked / findings / ms`；
  场景编号（B-RD、C2-A-146 等）与官方语料命名一致，但总行数大于官方 5200 条语料（来源未注明）。
  已带 `blocked` / `findings` 字段，说明队友已在跑运行时"检测+阻断"评估。
- `output.json`：filter 过滤后的攻击子集，90 行。

## 8. 赛事概况.md（新增，队伍联合架构蓝图）

- 署名全体队员（龙悦、程浩森、陈星伊、龙正贤），v1.0，覆盖赛题两部分。
- **双平面架构**：静态识别平面（即 agent-scanner 现有五阶段）+ 运行时监控平面（规划中），共用
  Asset / Edge / Risk / Trace / Session / Decision / AuditRecord 模型与四个关联键
  （`asset_id / trace_id / instance_id / rule_id`）。
- **运行时平面规划**（文中标注"建议/规划"）：模块 `agent_scanner/runtime/`（collectors /
  correlator / detectors 单点规则·行为序列·语义确认 / blocking / audit）；CLI 规划扩展为
  `scan / serve / bench / guard / replay / audit`；分层检测 Layer 0 采集关联 → L1 单点规则 →
  L2 行为序列 → L3 语义确认；阻断窄口为 tool dispatch → MCP tools/call → egress → Langflow
  exploit endpoint，fail-open + 白名单。
- **提交物形态**：只交 `agent-scanner/`（代码 + `rules/generic/`），不交官方靶场、留出集与
  `bench/agentrange-player.yaml`。
- **对分工的含义（事实性指出，评价见融合计划）**：运行时平面的采集/检测/阻断规划与
  `solution/` 的 guard 主干职责重叠，融合分工需尽早对齐。

## 9. 与 solution/ 的交集

两侧都实现赛题第一部分：资产闭集（13 类 vs 14 类）、关系边（9 vs 10）、风险族高度重叠，
口径不同不能直接比较数量。本机同靶对跑（2026-09-17 复跑口径）：对方 61 资产 / 22 风险，
我们 57 节点 / 16 条静态发现 + 15 条包络 + 4 条运行时 = 35 条。逐条差异与裁决见
[../plans/融合与测试计划.md](../plans/融合与测试计划.md) §2。

## 10. 变更历史

### 2026-09-14 版要点（已被上文取代）

- v0.2.0：目标仅支持本地目录；profile 仅按目录名匹配；`bench/agentrange-player.yaml` 基准
  风险 8 条；实测扫描 61 资产 / 55 边 / 20 风险，基线 8/8 全过。
- 测试 89 个 test 函数；README 存在虚构 make 命令、代码块围栏提前闭合等问题；
  `benign_allowlist` / `hidden_tool_flag` 等规则键均未消费。
- 仓库顶层无《赛事概况.md》、顶层 README 与 filterC2/。
