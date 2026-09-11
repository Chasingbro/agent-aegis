# CHANGELOG

> 项目统一变更日志：**新条目只追加在这里**（最新在上，含日期、改动摘要、涉及模块）。
> `release/v1.0-asset*/CHANGELOG.md` 是各版本快照内的冻结副本，与发布物一起留存，勿改。

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
