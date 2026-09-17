# Agent Asset Lab

安全的留出靶场，用于验证 Agent 资产探测的泛化能力。它刻意使用不同的服务名、端口、网络名、目录和工具名，不修改官方 `AgentRange-player`。

## 启动

```bash
docker compose up -d --build
curl http://localhost:8200/health
curl http://localhost:9201/health
```

Windows Git Bash 无 `make` 时直接使用上面的 Compose 命令。停止并清理测试卷：

```bash
docker compose down -v
```

## 资产面

- `asset-agent`：FastAPI Agent 入口，连接确定性 `model-sim`。
- `model-sim`：OpenAI-compatible 模型桩。
- `flow-engine`：安全框架/flow fixture，提供模型 URL 和 MCP 工具引用。
- `asset-db`：PostgreSQL，包含 `alpha`/`beta` 两个合成租户。
- `account-query`、`knowledge-fetch`、`threat-lookup`、`ops-check`、`note-archive`、`qa-runner`：6 个独立 MCP 风格服务。
- `extensions/skills` 与 `extensions/plugins`：Skill、隐藏注释和惰性编码 canary 标记。
- `core-net` 与 `edge-net`：业务网络和出网边界；外部访问只指向本地 fixture。

## 静态扫描和评测

```bash
python solution/collect_static.py test-ranges/agent-asset-lab
python solution/cli.py bench --root test-ranges/agent-asset-lab
```

oracle 位于 `solution/targets/oracle-agent-asset-lab.yaml`，不放入扫描目标目录。靶场中的注入、隐藏工具和弱配置只用于静态识别；不会执行 shell、下载脚本或读取主机真实凭据。
