# CHANGELOG

> 项目统一变更日志：**新条目只追加在这里**（最新在上，含日期、改动摘要、涉及模块）。

## 队友项目 agent-scanner 新版本核查与事实档案更新（2026-09-17）

- `reference/agent-scanner/` 拉取队友新版（拷贝件无 git 历史，对比基准为档案 09-14 版）：
  ① 新增顶层《赛事概况.md》（队伍联合双平面架构蓝图，运行时平面 `agent_scanner/runtime/`
  与 CLI `guard/replay/audit` 为规划项，与我方 guard 主干职责重叠）；② 新增顶层 README 门户；
  ③ 扫描器新增四种目标输入（目录/压缩包/`docker://`/`http(s)://`，`target_source.py` +
  `identify/remote.py`）与 `--profile auto` 源码指纹回退匹配；④ 官方靶场基线风险 8→10 条；
  ⑤ 测试 89→113 个 test 函数；⑥ 新增 `filterC2/` 运行时评估日志（11,586 行 JSONL，
  含 blocked/findings 字段，队友已开跑运行时侧）。
- 本机复跑 bench（uv 临时环境）：官方靶场 23/23 资产、10/10 风险、四项全过；**留出集
  simulated-target 风险仅 2/6（漏报 66.67%）**，漏报 4 条对应其既有局限（.mcp.json 配置级
  风险、FastMCP 形态、明文 key），README 未公开该数字——已在档案中如实记录。
- `docs/modules/agent-scanner.md` 全文更新至 2026-09-17 版（局限清单复核：4 项已修复、
  8 项仍在），09-14 版要点移入"变更历史"。

涉及模块：`docs/modules/agent-scanner.md`、`docs/index.md`、`docs/changelog.md`；
核查对象 `reference/agent-scanner/`（外部材料不入库）。

## P1 恶意维度对照表完成（2026-09-17）

- 新增 `docs/modules/taxonomy-comparison.md`（P1 主产出）：SkillTrustBench T01–T09 ×
  Agent Dependency、MalSkillBench 108 格（B1–B15 × 载体 × 插入策略）、MCPTox 三范式
  提取到统一粒度，与我方 generic 层 22 个风险 id + 采集器字段面逐维对照——
  **37 个统一维度全部归属**：✅已有 10 / 🟡部分 9 / ➕需新增规则 12 / 🔧需采集器增强 3 /
  ⛔静态不可检 4 / ➖超范围 1，无"未评估"残留。
- 我方现状盘点：`run_rules` 22 个风险 id 分级清单；`packages[]` 依赖已采集但**零规则消费**
  （P2 规则面最大空白）；Skill 脚本 AST、记忆 API 面缺位。
- P2 输入清单成形：11 项纯 regex 可落地（持久化写入、下载执行链、代码内硬编码密钥、
  多层混淆、延时触发、提示词泄露等）在前；零宽字符、包名相似度、packages 规则次之；
  AST 增强与静态边界（误导性描述/运行时确证）记录不硬造。
- 诚实备注入档：MCPTox 10 类后果完整枚举在论文表格中不可自动提取（P2 如需逐类规则
  人工补录）；STB 宣传页"5 层依赖 A–E"无可核实定义，以数据集卡 9 行 Agent Dependency 为准。
- `docs/index.md` 同步：新增对照表条目，修正计划文档改名后的链接与两处状态标注。

涉及模块：`docs/modules/taxonomy-comparison.md`（新增）、`docs/plans/论文对照静态检测计划.md`、
`docs/index.md`、`docs/changelog.md`；无代码改动。

## P0 数据获取与核实完成 + 积累进度推送 GitHub（2026-09-17）

- **GitHub 同步**：2026-09-14~15 积累的全部进度（融合 P0–P2、规则分层与统一 bench P3、
  留出环境 `test-ranges/agent-asset-lab`、oss-ranges 台账、本计划文档）以提交 `c12e7d7`
  推送 `Chasingbro/agent-aegis` main 分支（81 文件，+4,561 行）。`.gitignore` 白名单模式
  补齐 `/reference/*`、`/test-ranges/*` 收窄规则，修复 agent-scanner 与官方作品模板被
  意外放行的问题（两者仍不入库）。提交前验证：solution 单测 49 passed / 3 skipped，
  暂存清单无禁区路径、无真实凭证模式（留出环境敏感值均为 canary 假值）。
- **《论文对照静态检测计划》P0 完成**（结论详见该文档 P0 节）：
  - SkillTrustBench：Hugging Face `cuhk-zhuque/SkillTrustBench`（腾讯朱雀 × 港中深），
    **CC BY-NC-SA 4.0**；样本包已缓存校验（5,520 cases + ground_truth.json，恶意 2,863 /
    正常 1,643 / 可疑 1,014），**fixture-ready**。
  - MalSkillBench：108 格 taxonomy 与样本数（3,944 恶意 + 4,000 良性）核实无误；
    **无 LICENSE** 仅外部参考；样本目录名含冒号（~999 处）Windows 不可直接 checkout，
    本地为 blobless 稀疏克隆缓存，取样需改名映射提取。
  - MCPTox：正式发表确认（AAAI 2026）；匿名仓库有 Cloudflare 盾自动抓取受阻，
    **降级为 taxonomy 参考**，样本如需转 fixture 走浏览器人工下载。
- **ResearchGate 存疑条目已核实**：正式出处 arXiv:2602.06547（USENIX Security 2026）；
  可用数字为 157 个行为验证恶意 skill、632 漏洞中 84.2% 藏于 SKILL.md；
  旧摘录数字（~1,070 / 47.5%）正式版未出现，弃用。
- oss-ranges 台账（`projects.yaml` + `README.md`）新增三个 dataset 条目及 2026-09-17 缓存状态；
  `sources/` 缓存目录维持不入库。

涉及模块：`docs/plans/论文对照静态检测计划.md`、`reference/oss-ranges/`、`docs/changelog.md`；
本地缓存 `reference/oss-ranges/sources/`（不入库）。

## 计划文档修订：论文核实完成 + 精简为关键信息对照（2026-09-17）

- `docs/plans/外部数据集反哺静态检测计划.md` §2 重写为核实后的关键信息对照表：
  MalSkillBench（v3，3,944 恶意 + 4,000 良性、108 格）、MCPTox（AAAI 2026，1,312 用例、
  匿名仓库开源）、MCIP（v7）、MCPSecBench（v3，4 攻击面 17 类攻击）、STAC（v3，483 案例）、
  DiagChain（v1，**定位纠偏**：是 LLM 攻击链重建能力评测而非攻击数据集）均对照 arXiv 原文核实。
- 未核实项仅剩 ResearchGate 供应链投毒条目（数字暂不引用，P0 处理）。
- 文档尾部章节按"只保留关键信息"要求精简（用户侧删除回归门禁/风险/分工/不做清单四节，
  核实信息并入 §2 与 P0）。

## 新增计划：外部数据集反哺静态检测（2026-09-17）

- `docs/plans/外部数据集反哺静态检测计划.md`：基于公开恶意数据集调研（MalSkillBench / MCPTox /
  SkillTrustBench 为主体，MCIP / MCPSecBench / ClawHub 事件为参考），制定
  "taxonomy 维度对照 → generic 规则与采集器增强 → 样本转 fixture+oracle 挂 bench 外部回归
  → 报告通用性论证"的 P0–P4 计划（约 1 周），含回归门禁、风险对策与队友分工建议。
- 同步决策：砍掉此前讨论的"自生成攻击链数据框架"路线（轨迹 IR/模板引擎/LLM-judge 闭环），
  以更低成本获取"通用算法"证据链；轨迹级数据集（STAC/R-Judge）留待能力 2 评估。
- 涉及模块：仅文档（`docs/plans/`、`docs/index.md`）；待执行面为 `solution/rules/generic/`、
  `solution/collectors/`、`solution/targets/bench.py`。

## P3 规则分层与统一留出集 bench（2026-09-15）

### 新增
- `solution/rules/generic/` 与 `solution/rules/profile/agent-range.yaml`：通用规则和官方目标专用语义分离；扫描支持 `--generic-only`。
- `solution/targets/bench.py`：统一适配两种 oracle 格式，输出 TP/FN/FP/extra、四项指标、负样本误报和 `not_measured`/`verdict` 状态。
- `solution/cli.py`：`bench`/`fused-bench` 支持 `--oracle`、`--output` 和独立工件目录；`fused-bench` 写入 `fusion-bench.json`。
- `solution/tests/test_generic_blacklist.py`、`test_fused_bench.py`：通用字面量黑名单、双目标目录隔离与退出码回归。

### 验证口径
- `simulated-target`（generic-only）：11/11 资产、6/6 风险、恶意类负样本误报 0。
- `agent-asset-lab`（generic-only）：10/10 资产、5/5 风险、恶意类负样本误报 0。
- solution 测试：46 passed、3 skipped；P3 专项回归 12 passed。

## 开源靶场收集与留出环境（2026-09-15）—— 第二测试目标与 profile/oracle/bench

### 新增
- `reference/oss-ranges/README.md`、`projects.yaml`：记录 DVAA、Appsecco MCP Lab、MCP Breach-to-Fix、LLMVault、Dify、LibreChat、n8n、AgentDojo、SCAM、MCPSecBench 等候选项目的来源、许可证状态、部署方式、缓存状态和安全边界；GitHub 网络受限时不伪造源码已收集。
- `test-ranges/agent-asset-lab/`：自有安全留出靶场，包含 Agent、模型桩、框架 fixture、PostgreSQL、6 个 MCP 风格服务、扩展文件、双网络和本地 canary sink；不修改官方 player，不执行真实外联或命令。
- `solution/targets/profiles.yaml`、`oracle-agent-asset-lab.yaml`、`bench.py`：目标分类、独立真值和 `not_measured` 口径的目标级评测入口。

### 变更
- `solution/collect_static.py`：MCP 采集兼容独立 Compose build context、FastMCP/紧凑 Tool 注册、非官方扩展目录、通用 dotenv 示例和留出环境的结构性对账；官方靶场继续使用原精确对账。
- `solution/cli.py`：新增 `bench --root <目录>` 入口。
- `docs/modules/oss-ranges.md`、`docs/index.md`、`docs/architecture.md`：归档项目矩阵、留出环境边界和泛化评测方法。

### 验证口径
- 目标扫描器不读取 oracle；第三方无明确许可证项目只做外部参考，不进入发布物。
- 留出环境所有敏感行为为本地 canary 标记；真实靶场与 `release/` 冻结快照未修改。

涉及模块：`test-ranges/agent-asset-lab`、`solution/collect_static.py`、`solution/targets`、`solution/cli.py`、`docs/modules/oss-ranges.md`。

### 后续修复
- `solution/runtime/mcp_probe.py` 在写入 baseline 与变化工件前主动创建父目录；`test_peer_api.py` 在缺少生成工件时明确跳过，使清理 `solution/out` 后的干净测试仍可运行。

> `release/v1.0-asset*/CHANGELOG.md` 是各版本快照内的冻结副本，与发布物一起留存，勿改。

## 融合 P2（2026-09-15）—— Package 原生依赖图与 FastMCP AST 识别

### 新增
- `solution/collectors/packages.py`：解析 requirements/Dockerfile 的 Python 依赖，支持递归 `-r`、extras、specifier、direct URL 和多行 pip 指令；按 PEP 503 归一化并聚合来源。
- `collect_static.py` 接入 `packages[]`；保留 runtime/dev/attack scope 与逐来源 `owner_entries`，避免攻击端/开发依赖污染 Agent BOM。
- `graph/store.py`、节点/边 Schema、exporter 新增 `Package` 与 `depends_on`；原生图扩为 15 类节点、11 类边；BOM 在 `external_bom_refs.packages` 中增量记录可达 runtime 包，评分不变。
- `McpModuleScan` 支持真实 FastMCP import/实例、`@mcp.tool()`/`@mcp.tool`、装饰器名称/描述、docstring、async handler、重复注册去重；识别 socket connect/sendall 与环境读取组合并输出 `malicious_mcp/data_exfiltration`。
- validator 增加 `source_root` 跨 target 防护，避免 scan/graph 工件混用造成伪造漏报。

### 验证
- AgentRange：原生 **65 节点 / 118 边 / 8 Package / 32 depends_on**；对账 24/24；BOM 评分 100/44；包络 12/12；变异 10/10；validator 0。
- simulated-target：5 个去重 Package；evil-mcp 识别 2 个 FastMCP 工具；`get_config` 外泄风险命中；非 FastMCP 装饰器负样本不误报。
- solution 全量：**38 passed / 2 skipped**。

### 边界
- 依赖和 FastMCP 已进入 solution 原生静态链；generic/profile 规则分层、统一 fused-bench 与 `.mcp.json` 配置语义属于下一阶段。

## 融合 P1（2026-09-15）—— canonical 图谱、严格读取与全链路脱敏

### 新增
- `solution/fusion/models.py`、`ids.py`、`normalize_solution.py`、`normalize_peer.py`、`merge.py`、`payload.py`：将 solution 与 agent-scanner 统一为 canonical 资产、边和风险；保留 source IDs、证据、provenance、declared/observed 与 BOM facets。
- 实际 alias 覆盖 MCP server/tool、Skill 脚本和同名 compose 服务角色；peer 独有 package/credential/endpoint 保留为增量资产。
- graph-only 节点以低置信度补齐；未解析边和风险进入 `quality`，不再静默丢弃。
- `peer_io.py` 每次读取重验五件套，并以 current 指针中的 target 防止 summary 自证或篡改；区分 `not_run/not_configured/invalid/ready`；新增 `GET /api/dashboard`（`fusion-dashboard-v1`）。
- `fusion/redact.py` 两遍跨工件脱敏：从敏感配置上下文收集秘密候选，再清理风险描述、证据和所有对外 payload；兼容 API、peer 状态与 ZIP 共用同一脱敏器。

### 验证
- 真实 AgentRange 融合：**88 canonical 节点 / 123 边 / 55 风险 / 120 aliases**；0 悬空边、0 未解析风险。
- 已知 JWT 弱密钥、service token 和数据库连接凭据不出现在 `/api/dashboard|graph|bom|risks|baseline` 或 ZIP。
- P1 定向 10 项；solution 全量 **30 passed / 2 skipped**。

### 边界
- 根页面仍为原 Cytoscape UI；队友 ECharts 主展示层尚未移植。
- solution 原生 Package/FastMCP 已接入；`.mcp.json` 配置语义、generic/profile 规则和统一 bench 属 P3 以后。

## 融合 P0（2026-09-14）—— 队友扫描器隔离执行与 last-good 工件

### 新增
- `solution/fusion/peer_runner.py`：以参数数组、`shell=False` 和固定 scanner root 启动 agent-scanner；支持 `AGENT_SCANNER_PYTHON`、`--generic-only`、超时和最小化子进程环境。
- peer 工件采用不可变 `out/peer/jobs/<job-id>/` + 原子 `current.json` 指针 + `status.json`；超时、非零退出或坏工件不覆盖 last-good，`.scan.lock` 防同根并发写。
- 五件套严格校验：assets/graph/risks/summary/bench 的 JSON 结构、资产和关系引用、target、tool version、bench 可度量/不可度量契约。
- `solution/fusion/peer_io.py`：读取当前 last-good 与扫描状态；`solution/cli.py peer-scan` 显式触发扫描，dashboard HTTP 请求不触发长任务。
- `GET /api/peer/status`：只读状态接口；`/api/artifacts` 排除未经脱敏的 peer 原始工件。

### 验证
- 单元/API 回归：runner 6 项 + peer API 2 项；solution 全量 **22 passed / 2 skipped**。
- 真实 AgentRange：首次用系统 Python 因缺 PyYAML 返回 `scanner_failed`，没有创建/覆盖 current；配置 `AGENT_SCANNER_PYTHON=AgentRange-player/.venv/Scripts/python.exe` 后成功，agent-scanner 0.2.0 检出 **61 资产 / 55 边 / 20 风险**，约 **899 ms**。

### 边界
- P0 只负责可靠生产和读取 peer 工件；canonical ID/边/风险合并、前端融合、package/FastMCP 和统一 bench 属后续阶段。

## solution 快速启动文档（2026-09-14）—— docs/modules/solution-quickstart.md

### 变更
- 新增 [modules/solution-quickstart.md](modules/solution-quickstart.md)：我方 demo（`solution/`）实操启动手册 ——
  三条路径（A 静态全流程+前端 / B 运行时探测 / C guard 拦截代理）、`cli.py all` 六步期望值、
  7 个 API 端点实测返回、工件清单、单测自查、8 条排错表、清理方式。
- [index.md](index.md) 目录树与索引表同步；与既有 [modules/range-quickstart.md](modules/range-quickstart.md)
  互为上下游（靶场侧 ↔ 我方侧）。

### 实测（Windows 11 + Git Bash + Python 3.14.0；靶场 14 容器已 Up）
- `pip install -r requirements.txt` → 8 个依赖；`python cli.py all` 全绿：对账 **24/24**、图 **57 节点/86 边**、
  agent 评分 `opspilot-app=100(high)` / `opspilot_support=44(moderate)`、round-trip pass、
  包络校验 **12/12**、变异差分 **10/10**、完整性 0 违规；墙钟 **约 5 秒**。
- `python cli.py serve` → `:8080` 首页 200；`/api/summary` 14 服务/8 MCP/10 工具(1 隐藏)/7 技能/5 身份；
  `/api/risks` total **35**（静态 16 + 包络 15 + 运行时 4 + 校验器 0）；`/api/artifacts` 200 · 28 KB。
- `/api/judge` 三样本：`notes-sync.debug_exec` + 下载执行 = **140 block**；`tenant="*"` = 45 alert；
  诱饵 `sandbox-exec.run_test` = **0 pass**（诱饵零误伤）。
- 三探测器单跑：mcp_probe 广播 9 工具且 `debug_exec` 缺席；identity_probe 登录 5/5、伪造 ops-admin token 被接受、
  错密钥阴性对照被拒；http_probe 组件存活 5/5、投毒页注入确认。
- `pytest -q` → **16 passed**（约 1.5 秒）。

### 记录到的坑（此前文档未写）
- **`solution/out/` 在 `.gitignore` 内**：新检出无工件，此时 `cli.py serve` 首页仍 200 但**所有 `/api/*` 为 500**
  （实测 `GET /api/summary` → 500）。必须先 `python cli.py all` 再 `serve`。
- **`cli.py all` 的 runtime 步几乎总打印 `skipped`**：`cli.py` 只在三个探测器**全部返回 0** 时才跑 `observe`，
  而 `http_probe` 的成功条件含 `"notes-sync" in by_src`；`notes-sync` 的启动外联只在容器启动那一刻发一次，
  若它比 c2-sink 先就绪该收据即永久丢失（receipts 只剩 `src=beacon` / `src=cat2`），自检必然不过。
  三份 `out/runtime/*.json` 照常写出，可用 `python -c "from runtime.observe import run; run()"` 单独补跑观测入图
  （实测 17 节点、5 条运行时发现）；补发信标：`docker compose restart mcp-notes-sync`。
- **测试依赖工件，且会把夹具数据写进真实工件目录**：`test_rug_pull_baseline` 只 monkeypatch 了
  `mcp_probe.BASELINE`、没 monkeypatch `mcp_probe.OUT`，而 `check_baseline()` 会写 `OUT/baseline_changes.json`
  —— 于是 ① 把 `out/` 移走后 `pytest -q` 为 `1 failed, 12 passed, 3 skipped`（`FileNotFoundError`，非代码问题）；
  ② 跑过测试后 `baseline_changes.json` 里躺着夹具的 `srv:t1`（`old_head="evil desc"`），下一次 `observe`
  会把它读成 `RT-tool-disappeared srv:t1` **假发现**（这就是运行时发现 4→5 的来源）。
  清理：`rm out/runtime/baseline_changes.json && python -m runtime.mcp_probe`。
  建议的一行修法（本次未改代码）：在该用例中补 `monkeypatch.setattr(probe_mod, "OUT", tmp_path)`，
  可同时消除上面的 ① 与 ②。
- **运行时风险数是环境相关的**（4–5 条，随靶场状态与探测历史浮动）；固定口径是静态 16 + 包络 15 + 校验器 0。
- `README_集成.md` 的 `judge_events` 示例标注 `score:100` 为早期数值，当前单事件累加为 **140**，
  已在 quickstart §2.4 以实测值为准（`README_集成.md` 本次未改）。

### 涉及
- docs/modules/solution-quickstart.md（新增）、docs/index.md、docs/changelog.md
- 未改任何代码；`solution/out/`（gitignore）已按 pipeline 重新生成，并清掉测试夹具污染，
  当前回到文档口径：运行时 4 条、`/api/risks` total 35

## 靶场快速启动文档（2026-09-14）—— docs/modules/range-quickstart.md

### 变更
- 新增 [modules/range-quickstart.md](modules/range-quickstart.md)：靶场 AgentRange-player 实操启动手册 ——
  依赖清单、4 步启动、Git Bash 下 `make` 的原生命令替代、场景代号与事件数、单/全量回放、攻击落地取证、
  guard override 叠加、停止/重置/清残留、9 条排错表。
- [modules/range.md](modules/range.md) §8 增加指向该文的入口，并补注 `make seed` 额外需要 `psycopg2-binary`；
  [index.md](index.md) 目录树与索引表同步。

### 实测（Windows 11 + Git Bash + Docker Desktop 29.7.2 / Compose v5.5.1 + Python 3.14.0）
- `docker compose up -d --build` 起 14 个服务；`GET :8100/health` → `{"status":"ok"}`。
- `customers` 表需手动 seed（app 启动不建表）：acme 8 / globex 8。
- 单场景 C2-B → c2-sink receipts 0→11（`src:cat2`）；一次全量回放约 2 分 20 秒，receipts 累计 33 条
  （22 条 cat2 外传 + 11 条 beacon）；C1-A 在 langflow 容器留下 12 个 `/tmp/pwned_<t>`。

### 记录到的坑（官方选手手册未提）
- Git Bash 无 `make`；`requirements-dev.txt` 缺 `psycopg2-binary`（不装则 seed 直接失败）
- `SCENARIO` 传选手手册表里的 1–7 序号会「退出码 0 但零回放」（未知代号静默空转）
- `make test` / `pytest -q` 在靶场目录是 **0 收集**：靶场包内不含任何测试文件（只有 conftest.py 夹具），
  选手手册"运行全量单元测试"的说法对不上实际；我们的单测在 `solution/`（16 passed）
- Git Bash 的 MSYS 路径转换（`docker exec ... ls /etc/...`）与中文 body 编码（`curl -d` 报 body 解析错误）
- **并发跑两个回放会互相清空 llm-stub 轨迹表**：先启动的那个静默降级为 `[stub:...]`，工具调用链一条都不发生，
  退出码仍为 0

### 涉及
- docs/modules/range-quickstart.md（新增）、docs/modules/range.md、docs/index.md

## 项目对比与融合计划（2026-09-14）—— 我方 solution × 队友 agent-scanner

### 新增文档
- [docs/modules/agent-scanner.md](modules/agent-scanner.md)：队友项目事实档案（架构与数据流、13 类资产 /
  9 类边 / 6 检测器、规则三层外置与 bench 度量机制、同靶实测数据、10 条已知局限）
- [docs/plans/融合与测试计划.md](plans/融合与测试计划.md)：同靶对跑实测、15 项 ground truth 逐条裁决、
  11 维度差距、融合方案 A/B、阶段 0-3 测试计划、9 项验收门禁

### 实测（本机 2026-09-14，官方靶场同靶对跑）
- 队友：`python -m agent_scanner bench --target AgentRange-player`（仅需 pyyaml，无需装依赖）
  → 61 资产 / 55 边 / 20 风险 / 646 ms；自建基线 23 资产、8 风险、12 负样本，四项指标全过
- 我方：`cli.py all` → 57 节点 / 86 边 / 16 静态发现（+15 包络 +4 运行时 = 35）；
  对账 24/24、包络 12/12、变异 10/10、完整性 0 违规

### 结论（详见计划文档 §3）
- 两侧在赛题**能力 1** 上重复投入。对方胜在**度量自证与泛化纪律**（bench 评测器、`not_measured` 口径、
  负样本陷阱、`--generic-only`、留出集 simulated-target）；我方胜在**覆盖面与证据深度**
  （观测面 / BOM / 包络 / CVE 版本匹配 / 页面投毒 / 越权语义）
- **能力 2**（运行时监控与阻断）对方完全没有；15 项关键 ground truth 中不存在"双方都漏"的项
- 建议方案 A：我方主干 + 移植对方三件套（generic/profile 分层、bench 评测器与负样本口径、留出集），
  约 3~4 天；若分工已定"队友静态、我方动态"则走方案 B（双引擎工件级融合，映射器 + 去重 + 统一 `_meta`）

## 目录整理（2026-09-14）—— 靶场目录改短名 + reference/ 收拢外部材料

### 变更
- 靶场目录 `揭榜挑战赛赛题2靶场-AgentRange-player/` → **`AgentRange-player/`**（与官方包名、队友 scanner
  的目录约定一致，人眼快速可辨）。旧路径已不存留，代码通过 `range_root.py` 自动解析新名。
- 新增 `reference/`（不入库）：队友同期项目 `agent-scanner/`（Agent 资产静态识别扫描器：13 类资产识别、
  9 类关系边、6 个风险检测器、离线单文件 HTML 报告）、官方作品 doc 模板（由根目录迁入）。

### 代码
- 新增 `solution/range_root.py`：靶场根目录唯一解析入口，按 `AgentRange-player` → 旧长名 回退，
  支持环境变量 `AGENT_RANGE_ROOT` 覆盖
- `cli.py` / `api.py` / `collect_static.py` / `guard/evaluate.py` 四处硬编码路径改为引用该模块
- 涉及模块：solution（采集 / 库入口 / CLI / 评测）、docs/modules/range.md、docs/architecture.md、README、AGENTS.md

### 回归
- 改名后：`pytest -q` 14 passed / 2 skipped；`collect_static.py` 对账 24/24 通过、scan.json root 已指向新路径；
  靶场 `.venv`（guard 评测用）在新路径下可正常启动

### 注意
- 改名途中该目录曾被一个 ZCode 会话进程（app-server）以独占句柄占用，Windows 下重命名/删除均被拒；
  结束该进程后改名成功 —— 同类操作前先确认无 IDE 会话或终端停留在该目录
- Docker Compose 项目名默认取目录名：改名后旧项目名下的容器/数据卷不会被复用，
  需 `docker compose -p <旧项目名> down -v` 清理
- `release/` 冻结快照内仍硬编码旧目录名（相对快照自身目录解析），复现快照需调整路径；快照不改

## v1.0-asset-guard（2026-09-11）—— 资产识别 + 拦截代理实验版

在 v1.0-asset 之上增加 MCP 拦截代理，验证"静态资产识别 × 运行时监测"组合效果。

### 新增
- `guard/`：拦截代理（compose override 上链，不改靶场文件）——MCP tools/call 逐事件判定
  + 编排层反代身份绑定（trace↔actor）+ 链路污点状态机 + JSONL 审计 + 阻断（JSON-RPC error）
- 判定引擎与 A 版 `api.judge_events` 同源，基线由 `policy_baseline()` 自动导出（零手写黑名单）
- `api.judge_events` 增加持久 state 参数（跨事件污点）与 no_declaration_checks 开关
- `guard/evaluate.py`：两相全量评测（无声明知识 vs 完整基线）

### 评测结果（5200 事件全量 replay）
- cat2 恶意 56/56 检出、56/56 阻断（有基线）vs 44 检出/22 阻断（无声明知识）
- 良性 5120 条：0 误标、0 误断（业务零中断）；合并静态 C1 检出 = 80/80（100%）
- 判定时延 avg 0.052ms / max 19.7ms（<1s 达标）；判定引擎 CPU 可忽略
- 详见 out/eval/eval_report.md

## v1.0-asset（2026-09-11）—— 资产识别独立版（融合交付）

静态资产识别 + 风险评定的第一个版本，面向与监测系统的融合。

### 能力
- 11 条采集通道（8 静态采集器 + 3 运行时探测器）
- 属性图谱：14 类节点闭集、declared/observed 双面、provenance，JSON Schema 校验
- AgentRiskBOM：工具 T1-T5 分级、自主 A1-A4、6 输入评分、控制映射、版本差分
- 双推理引擎：包络校验 12 规则（标准答案 12/12）+ 声明-观测差分
- 完整性校验器：schema / 引用完整性 / 双源对账
- 三层融合接口：JSON 工件（`_meta` 版本元数据）/ Python 库（`api.run_all` /
  `policy_baseline` / `judge_events`）/ REST（`/api/baseline` `/api/judge` `/api/artifacts`）

### 指标（靶场实测）
对账 24/24 · 包络 12/12 · 变异差分 10/10 · 完整性 0 违规 · 风险发现 35 条 · 诱饵零误报 · 测试 16/16

### 已知边界
- 非靶场项目规则覆盖有限（L2 模式库以靶场特征为主，通用化在路线图）
- `judge_events` 的 scope 判定需要编排层提供 actor（guard 版代理解决）
