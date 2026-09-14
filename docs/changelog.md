# CHANGELOG

> 项目统一变更日志：**新条目只追加在这里**（最新在上，含日期、改动摘要、涉及模块）。
> `release/v1.0-asset*/CHANGELOG.md` 是各版本快照内的冻结副本，与发布物一起留存，勿改。

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
