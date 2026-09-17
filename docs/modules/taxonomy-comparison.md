# 恶意维度对照表（外部数据集 × 我方静态检测现状）

> P1 产出（2026-09-17），属《[论文对照静态检测计划](../plans/论文对照静态检测计划.md)》。
> 回答一个问题：**公开数据集归纳出的每个恶意维度，我方 generic 层静态检测落在哪种状态**，
> 为 P2（规则与采集器增强）给出排序输入。处置词：✅已有 / 🟡部分 / ➕需新增规则 /
> 🔧需采集器增强 / ⛔静态不可检（运行时职责） / ➖超范围。

## 1. 输入源与可核实性

| 来源 | taxonomy 结构 | 本地缓存 | 可用性结论 |
|---|---|---|---|
| SkillTrustBench（腾讯朱雀×港中深） | T01–T09 攻击类 × 9 行 Agent Dependency 攻击面；三级 judgment；12 族 attack_pattern 代码 | `sources/skilltrustbench/`（zip 已校验） | fixture-ready；CC BY-NC-SA 4.0 非商业 |
| MalSkillBench（arXiv:2606.07131） | 108 格 = 载体 CI/PI/MIXED × 行为 B1–B15 × 插入策略 10 种 | `sources/malskillbench/`（稀疏克隆，Windows 非法路径无法 checkout） | 无 license 仅外部参考；taxonomy 从 README 核实 |
| MCPTox（AAAI 2026） | 工具描述投毒 3 范式 P1/P2/P3 × 后果类（10/11 类） | 未取得（Cloudflare 盾） | taxonomy 参考档；完整类别枚举在不可提取的表格中（见 §5 诚实备注） |
| USENIX Sec'26 野生实测（arXiv:2602.06547） | 攻击目标 3 类 × 载体 2 类（代码级/指令级）；84.2% 漏洞在 SKILL.md | 论文（arXiv 可及文本） | 作交叉验证与报告引证 |

## 2. 我方现状盘点（2026-09-17 时点）

### 2.1 generic 层风险产出（`collect_static.py: run_rules`，22 个风险 id）

| 风险 id | 触发条件摘要 | 级别 |
|---|---|---|
| desc-poisoning / skill-description-injection / hidden-comment-injection / content-poisoning | `injection_patterns` 正则命中工具描述 / Skill 描述 / HTML 注释 / 网页注释 | high |
| cross-origin-reference | 工具描述引用其他 MCP server 名 | medium |
| ansi-invisible-text | ANSI 隐形转义序列（Skill 注释、工具描述） | high |
| hidden-tool / routed-hidden-tool | `hidden=True` 注册；应用路由映射到隐藏工具 | high |
| dangling-route | 路由目标不存在 | medium |
| shell-capability | 工具声明任意命令执行能力（需人工研判） | info |
| permissive-semantics | 通配符租户/全量查询语义 | medium |
| handler-data-exfiltration | 同一工具 handler 读环境变量 + 出网发送 | high |
| startup-egress | on_start 上下文出网/读敏感环境 | high |
| skill-script-data-exfiltration | Skill 脚本同时读敏感文件 + 执行命令 + 访问网络 | high |
| obfuscated-payload | Base64 载荷解码命中危险模式（Skill/插件） | high |
| mcp-filesystem-overreach / mcp-remote-no-auth | filesystem 根目录授权；远程端点无认证声明 | high |
| weak-secret / plaintext-secret / default-credentials | env+compose 敏感键弱值 / 明文 / 账号=口令 | high/medium |
| confused-deputy | service-account 传播 + 宽权限服务 token | high |
| auto-login | `*_AUTO_LOGIN=true` | medium |
| known-vulnerable-version | 镜像版本命中 advisories（langflow 2 CVE） | high |
| name-similarity | 与知名 MCP server 名相似（typosquatting） | medium |

### 2.2 采集器字段面

- **已就绪**：MCP 工具五元组（description/hidden/capabilities/on_start_caps）、Skill（描述/隐藏注释/脚本全文/b64）、插件 b64、网页注释、`.mcp.json` 配置、env+compose 全量、应用路由表、镜像版本、**`packages[]` 依赖清单**（requirements/Dockerfile，P2 融合已入图谱但**尚无任何风险规则消费**）。
- **缺位**：Skill 脚本 AST（FastMCP AST 仅覆盖 MCP server 代码）、Skill 包 manifest/metadata 字段、记忆类 API 面、包依赖完整性（lock/来源 URL）。

## 3. 统一维度对照表（主表）

### G1 指令层（SKILL.md / 工具描述 / 隐藏载体）

| # | 统一维度 | MSB | STB | MCPTox | 我方现状 | 处置 |
|---|---|---|---|---|---|---|
| 1 | 工具/Skill 描述直接投毒（隐藏指令） | PI 载体 | T01 | P1/P2/P3 全部 | desc-poisoning 等 4 规则 | ✅ |
| 2 | 指令覆盖（ignore previous 类） | B12 | T01 子型 | P2 载体 | `ignore (all )?previous` 等 | ✅ |
| 3 | 角色劫持（persona 注入） | B10 | T01 子型 | — | `you are now`/`act as` 字面 | 🟡仅字面 |
| 4 | 安全绕过/越狱话术 | B11 | T01 子型 | — | developer/god mode 字面 | 🟡仅字面 |
| 5 | 系统提示词泄露诱导 | B13 | T01 子型（V_CONTEXT_LEAK 相邻） | — | 无规则 | ➕ |
| 6 | 目标劫持（隐性任务改道） | B14 | T01 子型 | P1/P2 手法 | `then call`/`然后调用` 覆盖显式改道 | 🟡 |
| 7 | 内容操纵（输出偏见/虚假） | B15 | T01 子型 | Message Hijacking 示例 | 无规则 | ➕字面弱规则 + ⛔语义 |
| 8 | 记忆投毒（长期记忆/会话状态写入） | — | T02 | — | 无规则、采集器无记忆 API 面 | 🔧➕ |
| 9 | 隐写载体（HTML 注释/ANSI/零宽字符） | PI-Steganographic | encoding 字段 | — | HTML 注释✅、ANSI✅；零宽/Unicode 同形无规则 | 🟡→🔧➕ |

### G2 代码层（scripts/、工具 handler）

| # | 统一维度 | MSB | STB | MCPTox | 我方现状 | 处置 |
|---|---|---|---|---|---|---|
| 10 | 嵌入恶意代码/危险 API 调用 | CI 载体 | T04 | — | dangerous_decoded + b64 + 三重组合 | 🟡无 AST |
| 11 | 函数追加/注入（Append/Inject） | CI 策略 | T04 子型 | — | skill 脚本仅 regex，无 AST | 🔧 |
| 12 | 远程载荷下载执行（curl\|sh 类） | B3/B4，MIXED 三策略 | T03，E1–E4 | P1/P2 外泄执行段 | 三重组合需三条件同时；单一下载执行链无规则 | ➕ |
| 13 | 反弹 shell | B6 | T03 子型 | — | MCP 侧 FastMCP 有 socket 组合识别；skill 脚本侧无 | ➕ |
| 14 | 持久化（cron/bashrc/systemd/启动项） | B5 | T06，P1/P2/P4，PY_PYTHON_PERSIST | — | 仅 advisory 侧 CVE-5027；脚本写启动面无规则 | ➕ |
| 15 | 勒索行为（加密+勒索话术） | B7 | — | — | 无规则 | ➕低优先级 |
| 16 | 资源滥用/挖矿 | B8 | — | — | 无规则 | ➕（xmrig/stratum IOC 词） |
| 17 | 提权（SUID/sudo/容器逃逸） | B9 | T05，PE1–PE3 | — | 配置语义面✅（permissive/confused-deputy）；脚本级无 | ➕ |
| 18 | 凭据窃取（仅读取不外发） | B2 | T05 子型 | P2 示例（读 SSH key） | 三重组合的读取分量；单独读取无信号 | ➕suspicious 级 |
| 19 | 数据外泄（读取+外发组合） | B1 | EX_COVERT_EXFIL | 后果主类之一 | handler/skill/startup 三规则 | ✅ |
| 20 | 延时触发/定时炸弹 | — | DT_TIMEBOMB | — | 无规则 | ➕（datetime/sleep 触发模式） |
| 21 | 多层混淆（marshal/zlib/翻转/compile） | — | EV_EVAL_BYPASS，OB_STRING_OBFUSC | — | 仅 b64decode 单点 | ➕ |
| 22 | 无确认破坏性操作（rm -rf/DROP） | — | V_DESTRUCTIVE_NO_CONFIRM | — | 无规则 | ➕suspicious 级 |

### G3 供应链/依赖/名称

| # | 统一维度 | MSB | STB | MCPTox | 我方现状 | 处置 |
|---|---|---|---|---|---|---|
| 23 | 恶意/不安全依赖（包面） | — | T08，SC1–SC3，V_UNSAFE_DEP_SOURCE | — | packages 已采集**但零规则消费** | 🔧已就绪+➕ |
| 24 | 名称仿冒（typosquatting 扩展） | — | T07 子型 | P1 仿冒常用函数 | MCP server 名相似度✅；package/Skill 名未覆盖 | ➕扩展 |
| 25 | 工具遮蔽/影子工具（"别调 X 改调我"） | — | T07 | P1 本体 | name-similarity + cross-origin-ref 覆盖大半 | 🟡 |
| 26 | 配置投毒（.mcp.json/compose 注入） | MIXED-Config+Load | CF_CONFIG_POISON | — | mcp_configs 两规则 + env 面 R1 | 🟡 |
| 27 | 框架/镜像已知漏洞 | — | T08 相邻 | — | advisories 版本匹配 | ✅可扩目录 |

### G4 配置/凭据

| # | 统一维度 | MSB | STB | MCPTox | 我方现状 | 处置 |
|---|---|---|---|---|---|---|
| 28 | 代码内硬编码密钥 | B2 相邻 | V_HARDCODED_SECRET | — | env/compose 面✅；**脚本代码内** `key=` 字面量无规则 | ➕ |
| 29 | 弱值/默认口令 | — | T09 子型 | — | weak_value_patterns + default-credentials | ✅ |
| 30 | 过宽权限声明（chmod 777 类） | B9 相邻 | V_WILDCARD_PERMS | — | 租户通配✅；文件系统权限位无 | ➕ |
| 31 | 过度遥测（可疑上报端点） | — | V_EXCESSIVE_TELEMETRY | — | 无规则（误报敏感） | ➕suspicious 级 |
| 32 | 无认证端点/免认证登录/身份传递 | — | T09 子型 | — | mcp-remote-no-auth / auto-login / confused-deputy | ✅ |
| 33 | 误导性描述（描述与行为不符） | PI-Full Camouflage | V_MISLEADING_DESCRIPTION | — | 无 | ⛔语义一致性需 LLM/运行时 |

### G5 意图与行为确证（静态边界声明）

| # | 统一维度 | MSB | STB | MCPTox | 我方现状 | 处置 |
|---|---|---|---|---|---|---|
| 34 | suspicious vs malicious 意图分级 | — | 三级 judgment | — | confidence 数值已有，无三级语义 | 🟡P3 oracle 对齐 |
| 35 | 运行时行为确证（触发后才恶意） | runtime-verified 本体 | — | ASR 评测本体 | — | ⛔能力 2/guard 职责 |
| 36 | 参数篡改（调用时发生） | — | — | P3 本体 | 仅描述模式可静态 | ⛔静态只能检描述 |
| 37 | 良性诱饵/误报压测面 | benign 4,000 | FP_* 两族 | — | 良性诱饵经验同构（sandbox-exec 等） | ➖非恶意维度，P3 负样本直接可用 |

## 4. 缺口汇总与 P2 输入清单

**统计（37 维）**：✅已有 10 · 🟡部分 9 · ➕需新增规则 12 · 🔧需采集器增强 3（#8、#9、#11，另有 #23 规则侧缺位）· ⛔静态边界 4 · ➖超范围 1。

**P2 建议优先级**（低成本高价值在前，均为 generic 层、带来源标注）：

1. **纯 regex 即可**（脚本全文字段已就绪，`test_generic_blacklist` 纪律沿用）：
   #14 持久化写入、#12 下载执行链、#28 代码内硬编码密钥、#21 多层混淆、#20 延时触发、#5 提示词泄露、#13 反弹 shell、#16 挖矿 IOC、#17/#30 提权与权限位、#22 破坏性操作、#15 勒索话术。
2. **需小量采集/规则面扩展**：#9 零宽/Unicode 同形字符、#24 包名/Skill 名相似度（复用 name_similarity）、#23 packages 风险规则（unsafe source/相似包名）。
3. **需 AST 或较大增强**：#11 Skill 脚本 AST、#8 记忆 API 面。
4. **边界记录进文档不硬造**：#33 误导性描述、#35/#36 运行时确证（写入能力 2 边界说明）。

**误报控制要求**：#18/#22/#31 建议落 suspicious/info 级并要求组合语义，避免 STB 指出的"高召回高误报不可用"问题；STB 的 FP_TEST_FIXTURE/FP_SECURITY_TOOL 族作 P3 误报压测负样本。

## 5. 验收对照与诚实备注

- **MSB**：B1–B15 共 15/15 全部落表（#2–#18 行）；载体 CI/PI/MIXED 3/3（G1/G2 行头）；插入策略 10 种归并入对应行（New Script File/Append/Inject/Inline → #10/#11；Full/Partial/Steganographic → #1/#9；Download+Execute/Config+Load/Fetch+Run → #12/#26）。
- **STB**：T01–T09 共 9/9 落表（T01→#1–#7，T02→#8，T03→#12/#13，T04→#10/#11，T05→#17/#18，T06→#14，T07→#24/#25，T08→#23/#27，T09→#28–#32）；三级 judgment → #34；12 族 pattern 代码归并入对应行。
- **MCPTox**：P1/P2/P3 范式 3/3 落表（→#1/#25/#36）；后果类完整枚举在论文表格中不可自动提取（v1 正文 10 类与 11 类表述亦有出入），已核实示例（Privacy Leakage、Message Hijacking、SSH key 外泄）分别映射 #19/#7/#18；如 P2 需要逐类规则，人工读 AAAI 版表格后补录。
- **其他备注**：STB 官网宣传页的"5 层依赖 A–E"在数据集卡与 ground_truth.json 中均无可核实定义，P1 以数据集卡实际给出的 9 行 Agent Dependency 攻击面为准；MalSkillBench 数字均以其 README 为准（无 license，外部参考）。
- **验收结论**：第一梯队三家 taxonomy 的全部顶级维度均已落表，无"未评估"残留。✅
