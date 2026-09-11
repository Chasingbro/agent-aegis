# Agent-Aegis（智盾）

面向 AI Agent 的安全防护系统：**资产风险静态识别 + 运行时异常监控与阻断**。
第五届中国研究生网络安全创新大赛 · 揭榜挑战赛赛题 2（AgentRange 靶场）参赛作品。

> 本仓库只包含自研算法/系统与文档；官方靶场 `AgentRange-player` 源码与官方作品模板不在仓库内，请按官方渠道另行获取。

## 模块

| 模块 | 位置 | 说明 |
|---|---|---|
| **aegis-asset**（v1.0-asset） | `solution/`（`collect_static.py` / `graph/` / `bom/` / `rules/` / `runtime/` / `server/` / `web/`） | 11 条采集通道（8 静态 + 3 运行时）→ 属性图谱（declared/observed 双面 + provenance）→ AgentRiskBOM（工具 T1-T5 分级、自主等级、凭据 scope）→ 包络校验 + 声明-观测差分双推理 → L1 JSON 工件 / L2 Python 库 / L3 REST 三层融合接口 |
| **aegis-guard**（v1.0-asset-guard） | `solution/guard/` | opspilot-app → MCP 的 `tools/call` 链路拦截代理：反代提取 JWT 绑定 trace↔actor → 与资产版同引擎、按资产基线逐事件判定 → `off/observe/enforce` 三模式（enforce 可阻断）→ JSONL 审计留痕 |

两模块共用一套资产基线：静态识别产出「工具清单 / 隐藏工具 / 身份 scope / 出网白名单」，运行时据此区分「合法出网 vs 恶意外传」「危险命名诱饵 vs 真后门」「正常前缀 vs 异常偏移」。

## 靶场实测指标

**aegis-asset**（详见 [solution/README_集成.md](solution/README_集成.md)）

| 项 | 值 |
|---|---|
| 资产对账 | 24/24（14 服务 / 8 MCP / 10 工具含 1 隐藏 / 7 技能 / 5 身份 / 10 路由） |
| 包络校验 vs 标准答案 / BOM 变异差分 | 12/12、10/10 |
| 风险发现 | 35 条（静态 16 / 包络 15 / 运行时 4 / 校验器 0） |
| 良性诱饵误报 | 0（password-policy-check / sandbox-exec / threat-intel 全通过） |
| 单测 | 16/16 |

**aegis-guard**（实验版，组合效果评测见 `solution/guard/evaluate.py` 与 [docs/changelog.md](docs/changelog.md)）

- cat2 提示词攻击 56/56 检出并阻断，良性基线 0 误报。

## 快速开始

```bash
cd solution
pip install -r requirements.txt
python cli.py all          # 静态全流程，工件落 solution/out/
python cli.py serve        # L3 REST @ 127.0.0.1:8080
# guard 部署（Docker 反代、三模式切换）见 solution/guard/README.md
```

单测：`cd solution && pytest -q`（无 Docker 环境自动跳过集成用例）。

## 文档

- 导航入口：[docs/index.md](docs/index.md)
- 架构现状：[docs/architecture.md](docs/architecture.md)
- 靶场分析（攻击剧本/语料/取证点）：[docs/modules/range.md](docs/modules/range.md)
- 变更日志：[docs/changelog.md](docs/changelog.md)
