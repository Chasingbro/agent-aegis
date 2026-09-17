# 外部开源靶场台账

本目录只保存来源与许可台账，默认不缓存第三方源码。机器可读清单见 `projects.yaml`。所有仓库应固定到审查过的 tag/commit 后再运行；无明确许可证的项目不得直接再分发。

2026-09-15 尝试浅克隆 DVAA/Appsecco 时 GitHub 连接被重置，匿名 API 随后触发限流，因此本地 `sources/` 缓存未建立，清单状态标记为 `not-cached`，不能视为源码已收集。

2026-09-17 补登记三个恶意数据集（《论文对照静态检测计划》P0）：SkillTrustBench 样本包已缓存并校验（CC BY-NC-SA 4.0，仅限非商业）；MalSkillBench 无许可证仅外部参考，且样本目录名含冒号在 Windows 上不可直接 checkout，本地为稀疏克隆缓存；MCPTox 匿名仓库有 Cloudflare 盾自动抓取受阻，taxonomy 以论文（AAAI 2026）为准。

| 项目 | 类型 | 来源 | 许可证状态 | 推荐用途 |
|---|---|---|---|---|
| OpenA2A DVAA | direct-range | https://github.com/opena2a-org/damn-vulnerable-ai-agent | Apache-2.0 | 多 Agent、MCP、A2A、容器与场景资产 |
| Appsecco Vulnerable MCP Servers Lab | direct-range | https://github.com/appsecco/vulnerable-mcp-servers-lab | MIT | MCP 工具投毒、依赖、Secrets、命名仿冒 |
| MCP Breach-to-Fix Labs | direct-range | https://github.com/PawelKozy/mcp-breach-to-fix-labs | 未发现 LICENSE | vulnerable/secure MCP 对照；仅外部参考 |
| LLMVault | direct-range | https://github.com/CyberSunil/LLMVault | MIT | 低资源、离线 Agent/RAG 回归 |
| Damn Vulnerable LLM Agent | direct-range | https://github.com/ReversecLabs/damn-vulnerable-llm-agent | Apache-2.0 | LangChain/ReAct/工具/SQL 小型回归 |
| Dify | platform-target | https://github.com/langgenius/dify | Dify Open Source License | 大型 API/Worker/插件/数据库/向量库拓扑 |
| LibreChat | platform-target | https://github.com/danny-avila/LibreChat | MIT | Node/Mongo/MCP/Actions 多用户拓扑 |
| n8n | platform-target | https://github.com/n8n-io/n8n | Sustainable Use/Enterprise | workflow、worker、凭据、MCP 节点 |
| AgentDojo | benchmark/simulation | https://github.com/ethz-spylab/agentdojo | MIT | 行为任务与 prompt/tool injection 基线 |
| 1Password SCAM | benchmark/simulation | https://github.com/1Password/SCAM | MIT | Skills 与模拟 MCP 工作场景 |
| MCPSecBench | benchmark/simulation | https://github.com/AIS2Lab/MCPSecBench | MIT | MCP 命名仿冒、签名、MITM/DNS rebinding |
| SkillTrustBench | dataset | https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench | CC BY-NC-SA 4.0（非商业） | 恶意 skill 扫描器外部回归：5,520 cases + ground_truth.json |
| MalSkillBench | dataset | https://github.com/lxyeternal/MalSkillBench | 未发现 LICENSE（仅引用请求） | 108 格 taxonomy 对照；样本仅外部参考 |
| MCPTox | dataset | https://anonymous.4open.science/r/AAAI26-7C02 | 未声明 | 投毒工具描述 taxonomy（以 AAAI 2026 论文为准） |

## 安全约束

- 第三方项目在隔离网络运行，使用假凭据；所有外传目标替换为本地 receipt/canary sink。
- 不执行真实 RCE、下载执行、SSH key 读取或公开 C2 外联；编码样本只保留惰性 canary 标记。
- `test-ranges/agent-asset-lab` 是自有重实现，不声称复制第三方代码。
