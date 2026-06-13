# 情报采集智能体研究路线：迁移 Claude Agent SDK 与自主智能提升

更新时间：2026-06-13
状态：P0-P2 已实施并通过 P0 验收（DeepSeek Anthropic 兼容端点全矩阵实测达标，见第 5 章）；P3 评估资产就绪、sdk 引擎已可 live 运行（见 10.1 实施状态），完整 A/B 与默认引擎切换待执行。GLM 端点因 Coding Plan 到期保留为备选 provider

本文档回答三个问题：当前情报采集智能体的真实智能水平如何？怎样在不引入强化学习的前提下提升其智能？为何以及如何从 CrewAI 迁移到 Claude Agent SDK？最终给出分阶段实施计划与可量化的验收标准。

---

## 1. 背景与现状诊断

### 1.1 核心结论

当前的"采集智能体"实质是一个**确定性规则控制器，外加默认关闭的 LLM 装饰层**：

1. **LLM 决策默认不生效**。`intel/real_loop.py` 的 `RealIntelRunController` 在 7 个决策点通过 `_kickoff_json()`（L1260）调用 CrewAI agent，但整体受 `_agent_kickoff_enabled()`（L1288）控制，环境变量 `INTEL_ENABLE_AGENT_KICKOFF` **默认为 false**——日常运行时所有决策走的都是确定性规则 fallback。
2. **CrewAI 用得很浅**。3 个 agent（autonomous_planner / source_intelligence_collector / reflection_coverage_critic）仅作 `Agent.kickoff(prompt)` 单次调用的包装；`config/tasks.yaml` 只是声明、从未参与编排；没有 Crew process；planner 与 critic 没有工具调用能力。框架的多智能体编排价值实际未被使用。
3. **决策信号齐备，但没有喂给决策者**。blackboard（`schemas/runtime.py` 的 `IntelRunBlackboard`）已记录每轮 `novelty_score` / `noise_ratio` / `duplicate_ratio`（`QueryHistoryEntry`）、`coverage_gaps`、`reflection_notes`；源工具（`tools/registered_source_tools.py`）已支持高级检索参数——NVD 的 `cwe_id` / `cvss_v3_severity` / 时间窗 / KEV 过滤，arXiv 的布尔组合与 `cat:` 分类限定，OSV 的 ecosystem / package / purl。但这些高级参数由确定性代码（`_source_query_specs` + 轮转切片）选择，agent 完全接触不到。
4. **相关性判断是纯关键词规则**。`_estimate_relevance()` 基础分 0.45 起步加关键词/长度加成，几乎所有条目 ≥0.45，区分度弱；`_classify_ai_vulnerability()` 靠三组关键词列表分类。噪声信号（noise_ratio）因此可信度有限。
5. **LLM 调用配置保守且脆弱**。GLM-5 main 档 `max_tokens=1400`、`max_retries=0`；coverage 分析 prompt 把全量 `raw_items` 直接 dump 进上下文，长 run 时极易超长或解析失败，而失败是静默降级、不可观测。

### 1.2 决策点清单（迁移对象）

| # | 决策点 | real_loop.py 行号 | 职责 | 当前 fallback 规则 |
|---|---|---|---|---|
| 1 | `_select_next_actions` | L223 | 从 ActionCatalog 选下一步行动 | 固定动作序列 |
| 2 | `_assess_collection_yield` | L570 | 评估本轮收益（novelty/noise/dup） | 直接由计数计算 |
| 3 | `_analyze_coverage_gaps` | L640 | 覆盖缺口分析 | `detect_topics()` 与 target_topics 比对 |
| 4 | `_expand_search_semantics` | L705 | 语义扩展检索词 | 硬编码 topic→terms 映射 |
| 5 | `_rewrite_search_strategy` | L909 | 检索策略改写 | 高 ROI gap → 非重复模板 query |
| 6 | `_evaluate_search_completeness` | L1035 | 是否继续下一轮 | 预算耗尽 / 收益递减 / 覆盖达标 |
| 7 | （采集执行）`_collect_real_sources` | — | 调源工具 | 确定性 source query specs |

### 1.3 含义

"提升智能"的瓶颈不在换一个更花哨的框架，而在于：**让一个真正带工具、带上下文、能多步推理的 agent 接管这 7 个决策点，并把已有的指标信号作为其决策依据**。框架迁移是实现该目标的载体，而非目标本身。

---

## 2. 目标与非目标

### 2.1 目标

1. 落地 CLAUDE.md「方向一」的四个自主决策能力：**源选择决策、检索词决策、高级检索策略、轮次决策**（详见第 6 章）。
2. 采集循环从 CrewAI 迁移到 **claude-agent-sdk**，获得原生 agentic loop（工具循环、hooks、subagents、上下文管理）。
3. 相关性判断从纯关键词升级为**三层混合过滤**（规则 → embedding → flash LLM），见第 7 章。
4. 建立**评估基线**，使"智能提升"可以用同预算 A/B 对比量化证明（第 9 章）。

### 2.2 非目标

- **不做 Agentic RL**。理由：(a) 当前使用的 GLM API 模型不可训练，真要做 RL 必须换开源可微调模型（如 Qwen）+ GPU 训练设施 + verl/trl 等训练栈，成本与本项目体量不匹配；(b) 尚无规模化、可信的 reward 信号——相关性标注目前是弱规则，reward 噪声会主导训练；(c) 工程手段（上下文工程、bandit、相关性升级）的边际收益远未吃完。**保留重估口子**：第 9 章评估基线建成后，其指标体系（每轮新增相关条目/调用、精确率）天然是未来 RL reward 的雏形，届时可重新评估可行性。
- **不动 KG 链路**。`kg/ctinexus_adapter.py` 走独立的 litellm 调用，与采集 LLM 链路本就解耦；"KG 生成失败不影响采集主流程"原则不变。
- **不改输出约定**。`data/intel_runs/<run_id>.json` 的 blackboard 结构、`latest.json`、KG manifest 路径全部保持，Gradio 前端与下游消费不受影响。

---

## 3. 框架选型论证：为何迁移 Claude Agent SDK

### 3.1 现状的框架错配

CrewAI 的核心价值是 Crew/Task 声明式编排与角色协作，而本项目实际需要的是：一个**循环内自主决策的单 agent（带评审 subagent）**，能在一轮内多次调用检索工具、观察结果、调整参数。当前代码绕过了 CrewAI 的编排（手写控制循环 + 单发 kickoff），等于只用 CrewAI 做了一层 LLM 调用封装——这层封装反而带来了 `_kickoff_json` 的解析脆弱性和"决策只能一锤子买卖"的限制。

### 3.2 Claude Agent SDK 提供什么

以下为已核实事实（来源：[claude-agent-sdk PyPI](https://pypi.org/project/claude-agent-sdk/)，v0.2.99，2026-06-12 发布，MIT，Anthropic 维护）：

- `query()` 单次任务 / `ClaudeSDKClient` 双向多轮会话；
- `@tool` 装饰器 + `create_sdk_mcp_server()` 定义进程内自定义工具，agent 在原生工具循环中自主多次调用、自主选择参数；
- **hooks**（PreToolUse 等）可在代理循环的特定点拦截行为——预算强制、重复 query 拦截、指标回写的理想挂载点；
- programmatic subagents 与 session forking——critic 角色的天然实现；
- 自带 Claude Code CLI 运行时（随包捆绑），含上下文压缩等长会话管理能力。

这些恰好对应本项目的需求：工具循环 ↔ 让 agent 自己选源选参数；hooks ↔ blackboard 记账与安全阀；subagents ↔ planner/critic 分工；上下文管理 ↔ 10+ 轮长循环。

### 3.3 模型接入路径（Anthropic 兼容端点，多 provider）

`agent_runtime/client.py` 支持多 provider，经 `INTEL_SDK_PROVIDER=deepseek|glm` 选择（未设置时自动探测：有 `DEEPSEEK_API_KEY` 先用 DeepSeek，否则 GLM）；显式设置 `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` 可覆盖一切。

**DeepSeek（当前默认，2026-06-13 实测可用）**：

```bash
DEEPSEEK_API_KEY=<key>
# 端点 https://api.deepseek.com/anthropic；仅支持两个模型名：
#   deepseek-v4-pro（reasoning，输出 thinking block，main 档默认）
#   deepseek-v4-flash（fast 档默认）
```

**GLM（备选，需有效 Coding Plan 订阅）**（来源：[智谱接入教程](https://zhuanlan.zhihu.com/p/1993323826382139976)、[BigModel 集成指南](https://segmentfault.com/a/1190000047552132)）：

```bash
ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic
ANTHROPIC_AUTH_TOKEN=<GLM_API_KEY>
ANTHROPIC_DEFAULT_OPUS_MODEL=glm-4.7
ANTHROPIC_DEFAULT_SONNET_MODEL=glm-4.7
ANTHROPIC_DEFAULT_HAIKU_MODEL=glm-4.5-air
```

SDK 侧通过 `ClaudeAgentOptions(env={...})` 注入上述环境变量即可。端点对 SDK 高级特性（结构化输出、prompt caching、subagent 并发、长会话稳定性）的支持以第 5 章能力矩阵实测为准。

> 辨析：claude-agent-sdk（本地 CLI 驱动，本项目采用）≠ Anthropic 托管的 Agents/Sessions API（仅支持 Claude 模型、无法接 GLM，不适用本项目）。两者名称相近，调研时易混淆。

### 3.4 迁移成本评估

迁移面是**可控的**，因为现有架构的稳定资产都不在 CrewAI 层：Pydantic schemas、源工具 HTTP 逻辑、blackboard 持久化、测试体系全部保留（见 4.4 清单）。真正重写的只有控制循环与 prompt，约对应 `real_loop.py` 的决策编排部分。

---

## 4. 目标架构

### 4.1 概念映射

| 现状（CrewAI） | 目标（claude-agent-sdk） | 说明 |
|---|---|---|
| `RealIntelRunController` 六步确定性循环 | **混合架构**：Python 控制器保留轮次骨架、安全阀、记账与持久化；每轮内部由一个 SDK 会话完成"规划→选源→定词→采集→评估"的合并决策 | 不一步跳到"agent 完全自主循环"；控制器始终掌握预算与落盘 |
| 7 处 `_kickoff_json(agent, prompt, Model)` | `agent_runtime/structured.py` 的 `structured_decision(prompt, schema, fallback)`：SDK 查询 → JSON 提取 → Pydantic 校验 → 失败返回 None 由调用方走规则 | **完整保留"解析失败即回退规则"契约**，仅替换底层引擎；新增失败计数可观测 |
| `RegisteredApiSourceSearchTool` 单工具分发 4 源 | `create_sdk_mcp_server(name="intel_sources")` + 4 个独立 `@tool`：`search_nvd` / `search_arxiv` / `search_cisa_kev` / `search_osv`，**typed 参数直接暴露高级算子** | HTTP/解析逻辑零改动——`@tool` 函数是 thin wrapper，内部调用现有 `registered_source_tools.py` |
| 3 个 CrewAI agent | planner 为主 agent；critic 为 subagent（fast 档模型，独立上下文做收益评估与终止判断）；collector 角色取消——采集就是主 agent 调工具 | subagent 为可选优化，Phase 1 可先用同一会话两段 prompt |
| 无预算强制（仅 `RunBudget` 字段） | **hooks**：PreToolUse 强制 `max_api_calls` 与每轮调用上限、对照 `_executed_source_query_keys` 拦截重复 query；PostToolUse 把每次工具调用结果回写 blackboard（`query_history` / `SourceExecutionStat`）并更新 bandit 统计 | hooks 在本地 Python 进程运行，不依赖端点能力，是最可靠的控制面 |
| `llms.py` 经 OpenAI 兼容端点 | `ClaudeAgentOptions(env=...)` 走 Anthropic 兼容端点（3.3 节） | `llms.py` 在 Phase 4 移除 |
| Pydantic 决策输出模型 | 默认 **tool-forcing**：强制 agent 调用 `submit_decision` 工具，工具入参 schema 即 Pydantic schema | 比依赖端点的 output_format 更稳，对 GLM 兼容性最好；若 spike 证实端点支持结构化输出可二选一 |

### 4.2 目标模块结构

```
src/sufe_saads_crewai/
├── agent_runtime/                # 新增：SDK 运行时封装层（与业务无关）
│   ├── client.py                 #   SDK 工厂：GLM 端点 env、模型档位映射、超时/重试
│   ├── structured.py             #   structured_decision()：tool-forcing/JSON 双模式 + Pydantic 校验 + fallback 契约
│   └── hooks.py                  #   PreToolUse 预算/去重拦截、PostToolUse blackboard 回写与审计
├── tools_mcp/                    # 新增：MCP 工具层
│   └── source_server.py          #   create_sdk_mcp_server + 4 个 @tool（thin wrapper → registered_source_tools）
├── intel/
│   ├── real_loop.py              # 保留：规则基线 + 引擎级 fallback（CrewAI 引用在 Phase 4 摘除）
│   ├── rules.py                  # 新增：从 real_loop 抽取的共享规则函数（避免双引擎漂移）
│   ├── sdk_loop.py               # 新增：SDK 主控制器，构造签名与 RealIntelRunController 对齐
│   ├── context.py                # 新增：上下文工程——blackboard → 紧凑指标摘要渲染
│   ├── relevance.py              # 新增：三层相关性过滤
│   └── bandit.py                 # 新增：多臂老虎机源选择统计
└── （schemas/ tools/ persistence/ kg/ web/ 不变）
```

引擎切换：环境变量 `INTEL_ENGINE=rules|sdk`（Phase 1-2 默认 `rules`，Phase 3 达标后切 `sdk`），`main.py` 与 `web/app.py` 经一个工厂函数选择控制器，下游无感。

### 4.3 三层 fallback（既有设计原则的延续与强化）

"agent 输出优先、确定性 fallback 兜底"与"采集失败不影响 KG"是既有设计原则，迁移后**保留并强化为三层**：

1. **决策点级**：`structured_decision` 失败（超时/解析失败/校验失败）→ 返回 None → 调用方执行 `intel/rules.py` 中与 real_loop 相同的确定性规则。规则函数抽取为共享模块，双引擎共用一份实现。
2. **轮级**：某轮 SDK 会话整体异常 → 该轮整体降级为纯规则轮，记入 blackboard 的 `errors` 与 `action_history`，run 不中断。
3. **引擎级**：SDK 运行时不可用（CLI 缺失、端点 4xx、启动探测失败）→ 直接落回 `RealIntelRunController`。KG 只消费已落盘的 blackboard，采集引擎与 KG 链路天然隔离。

与现状的关键差异：**fallback 不再静默**——每次降级记录原因与层级，作为可观测指标（第 9 章会用到"决策成功率"）。

### 4.4 保留 / 重写 / 删除清单

| 类别 | 内容 |
|---|---|
| **保留（不动或微调）** | `schemas/` 全部 Pydantic 模型；`tools/registered_source_tools.py` 的 HTTP 请求、参数构造与解析（`_estimate_relevance` 降级为相关性管线第一层）；`persistence/` 与 `data/intel_runs/` 输出约定；`kg/` 全部；`web/app.py`（仅换控制器工厂）；`tests/` 作为回归 harness；`intel/real_loop.py` 本体长期保留为规则基线 |
| **重写** | 控制循环 → `intel/sdk_loop.py`；agent 定义与 prompt：`config/agents.yaml` / `tasks.yaml` → 代码内 prompt 模板（系统 prompt 固定化以利缓存）；`_kickoff_json` → `agent_runtime/structured.py` |
| **删除（仅 Phase 4）** | `crewai[tools]` 依赖、`crew.py`、`config/agents.yaml`、`config/tasks.yaml`、`llms.py`、环境变量 `INTEL_ENABLE_AGENT_KICKOFF`、`adaptive_loop.py` 中 CrewAI 耦合部分 |

---

## 5. Anthropic 兼容端点能力矩阵（Phase 0 spike 回填）

**2026-06-13 最终结论：DeepSeek Anthropic 兼容端点全矩阵实测通过 P0 验收**（`spikes/agent_sdk_glm/results.deepseek.json`）。工具调用成功率 100%（20/20，达标线 ≥95%）、tool-forcing 结构化决策解析率 100%（20/20，达标线 ≥90%）、多轮会话 5/5、长会话 10/10。三个不达标项均有预定降级方案且不影响混合架构（见表）。

历史记录：GLM Anthropic 端点（`https://open.bigmodel.cn/api/anthropic`）对 `.env` 中全部 4 个 GLM key 返回 `429 code=1309`（Coding Plan 套餐到期；同账号 OpenAI 兼容端点 `/api/paas/v4` 正常，即账号有效、仅订阅到期）。GLM 续费后可设 `INTEL_SDK_PROVIDER=glm` 重跑矩阵对比（结果写 `results.glm.json`）。

| 验证项 | 验证方法 | 达标线 | 不达标的降级方案 | 结论（2026-06-13，DeepSeek deepseek-v4-pro/flash） |
|---|---|---|---|---|
| 基础连通：`query()` 经端点完成单轮问答 | 最小脚本 | 可用 | 阻塞项，重新评估端点 | **通过**：main 4.1s / fast 1.7s |
| 多轮会话：`ClaudeSDKClient` 连续 5+ 轮 | 最小脚本 | 稳定 | 每决策点独立 `query()` | **通过**：5/5 轮（8.2s） |
| `@tool` / MCP 工具调用 | mock 工具调用 20 次 | 成功率 ≥95% | 重写工具 description / 减少工具数 | **通过**：100%（20/20，81.6s） |
| JSON 决策输出可靠率（tool-forcing） | 20 次结构化决策 | 解析成功 ≥90% | 加重试 + 修复性 re-prompt | **通过**：100%（20/20，187s；v4-pro 为 reasoning 模型，单决策约 9s） |
| hooks（PreToolUse/PostToolUse）触发 | 拦截与回写各验证一次 | 可用 | 应用侧消息流手动拦截 | **通过**：deny 拦截生效、回写触发（本地进程运行，另有单测） |
| subagent 定义与调用 | planner+critic 最小编排 | 可用 | 同会话两段 prompt 实现 critic | **不达标**：模型自行扮演 critic 作答而未调用 Task 工具 → 走降级方案（引擎本就用独立决策调用实现 critic，不依赖 subagent） |
| 高端模型经该端点可用性 | 模型映射实测 | 可用 | 用默认 main 档 | **通过**：deepseek-v4-pro 可用（端点仅支持 deepseek-v4-pro / deepseek-v4-flash 两个模型名） |
| prompt caching | 重复系统 prompt 观察计费/时延 | 有效 | 靠第 8 章摘要压缩控成本 | **不达标**：usage 中 cache 字段恒为 0（端点不透出 Anthropic 缓存语义）→ 按降级方案靠摘要压缩控成本（本就是第 8 章设计） |
| 长会话/上下文压缩 | 模拟 10 轮注入 | 不崩溃 | 每轮重置会话（本就是默认设计） | **通过**：10/10 轮（24.6s） |
| 端点结构化输出（output_format） | 若支持则对比 tool-forcing | 可选项 | 维持 tool-forcing 默认 | **不达标**：json_schema 输出导致 max_turns 耗尽报错 → 维持 tool-forcing 默认（实测 100% 解析率，无需此特性） |

---

## 6. 四个自主决策能力设计

每个能力按统一模板描述：机制 / 上下文输入 / fallback / 验收。

### 6.1 源选择决策（bandit 推荐 + agent 否决）

- **机制**：`intel/bandit.py` 实现多臂老虎机（UCB1 起步，数据多后可换 Thompson Sampling），arm = `(source, topic_bucket)`，reward = 该次调用产出的新增相关条目数 / API 调用数（novelty 加权、去重后计数——blackboard 已有全部原料）。bandit 每轮给出推荐排序与置信区间，**作为上下文喂给 agent 而非直接执行**；agent 可附 rationale 否决（探索新源组合），PostToolUse hook 记录"采纳/否决"供事后分析。
- **上下文输入**：每源历史收益小表 + bandit 排序与置信。
- **状态持久化**：`data/bandit_state.json`，跨 run 累积；冷启动用乐观初值保证探索。
- **fallback**：bandit 排序直接执行（无 LLM 也比现在的全源轮询强）。
- **验收**：离线回放历史 run 的 query_history，bandit 排序的 regret 优于全源轮询。

### 6.2 检索词决策（自由生成替代模板）


- **机制**：agent 在会话中直接看到 query_history 摘要（每条 query 的 novelty/noise/dup 三指标）与未闭合 coverage_gaps，自由生成与改写检索词；摆脱 `build_gap_query` 与话题模板。
- **防退化**：PreToolUse hook 对照 `_executed_source_query_keys` 拦截重复 query（拦截时返回提示让 agent 换词，而非静默失败）。
- **fallback**：现有 `_non_repeating_gap_query` 模板逻辑（移入 `intel/rules.py`）。
- **验收**：A/B 中 sdk 引擎生成 query 的去重后多样性（unique token 集合）与单 query 新增相关条目数均不低于规则基线。

### 6.3 高级检索策略（typed 工具暴露算子）

- **机制**：核心就是 4 个独立 `@tool` 的 typed 参数。每个工具的 JSON schema description 写明算子语义与组合示例，例如 `search_nvd` 的 description 中给出"CWE-1039（对抗样本）配 pub_date 窗口可显著降噪"这类用法提示，agent 在工具循环中自然学会组合。
- **参数面**：NVD（keyword / cwe_id / cvss_v3_severity / pub_date 窗口 / kev_only / exact_match）、arXiv（布尔表达式 / cat: 分类 / 时间窗）、OSV（ecosystem / package / purl / vuln_id）、CISA KEV（keyword / cve_ids）。全部复用现有 HTTP 层，零新增请求代码。
- **防滥用**：代码侧校验非法参数组合并降级为基础 query（fallback 契约）；PreToolUse 配额拦截防死循环。
- **验收**：PostToolUse 审计显示 agent 实际使用高级参数的调用占比 >0 且随轮次上升；使用高级参数的调用其平均 noise_ratio 低于基础调用。

### 6.4 轮次决策（边际收益终止）

- **机制**：critic（subagent 或独立决策调用）每轮收到边际收益特征——近两轮 novelty 趋势、每 API 调用新增相关条目数、coverage 增量、剩余预算——输出 `continue/stop + confidence + rationale`。
- **安全阀**：`max_rounds` 保留为硬上限（CLAUDE.md 要求），另设 `min_rounds` 下限防过早停。
- **fallback**：现有规则版终止条件（连续两轮 novelty <0.05 且 dup ≥0.6、预算耗尽、覆盖 ≥0.85）。
- **验收**：终止偏差指标（第 9 章）——实际停止轮与事后最优停止轮（边际收益拐点）的平均偏差不大于规则基线。

---

## 7. 相关性判断升级（三层混合过滤）

参照 `base_kg/pipeline/relevance.py` 已验证的三层思路（白名单 → 标题关键词 → flash 模型），按"从便宜到昂贵"分层：

1. **第 1 层（零成本规则）**：现有 `_estimate_relevance` / `_classify_ai_vulnerability` 关键词逻辑原样保留，输出 [0,1] 分。高分（>0.75）直接收、低分（<0.2）直接弃，仅中间带进入下一层。
2. **第 2 层（embedding）**：对中间带条目，title+summary 与"主题锚文本集"（每个 target topic 预写 3-5 句典型描述）算余弦相似度。embedding 用智谱 embedding API 或本地小模型；结果按 content hash 缓存为 JSONL（模仿 `relevance.jsonl` 的可恢复设计），同一条目跨 run 不重复计费。
3. **第 3 层（flash LLM 批量裁决）**：仅对 embedding 仍不确定的窄带，用 fast 档模型批量分类（一次 prompt 判 10-20 条，返回 JSON 数组）；失败回退第 2 层分数。

每条 `RawIntelItem` 落盘 `relevance: {score, label, method}`——`method` 字段（rule/embedding/llm）是第 9 章分层评估精确率的关键。升级后 noise_ratio 信号可信度提高，反过来改善 6.1 的 bandit reward 与 6.4 的终止判断。

---

## 8. 上下文工程规范

这是不依赖 RL 的最大智能杠杆，原则：**喂摘要不喂原文，固定前缀利用缓存，轮间状态走 blackboard**。

- **固定系统 prompt 前置**：任务定位、工具语义、决策输出 schema、决策准则写入系统 prompt，字节级固定（若端点支持 prompt caching 可命中）；所有易变内容置后。
- **每轮动态上下文 = ≤2-3K tokens 紧凑摘要**，由 `intel/context.py` 渲染：
  - 每源×每轮指标小表（calls / new / dup% / noise% / novelty）；
  - bandit 推荐排序与置信；
  - 未闭合 coverage_gaps 列表；
  - 最近 N 条 query 及其收益；
  - 仅采样少量"待裁决条目"的标题——**禁止 dump raw_items 全文**（现状 coverage prompt 的主要病灶）。
- **会话生命周期**：每轮一个新会话（或每 2-3 轮重置），轮间状态全靠 blackboard→摘要传递。好处：成本可控；决策可复现可审计（摘要即决策输入，随 run 落盘）。

---

## 9. 评估基线（让"智能提升"可证明）

评估体系同时服务两个目的：验收本路线的每个阶段；为未来重估 Agentic RL 储备 reward 信号。

1. **基准任务集**：固定 5-8 个采集目标（覆盖 prompt injection、jailbreak、RAG poisoning、agent tool abuse、模型供应链等），冻结为 `tests/eval_goals.json`。
2. **A/B 协议**：同一目标、同一预算（max_api_calls / max_rounds 安全阀一致）下分别跑 `INTEL_ENGINE=rules` 与 `sdk`，各重复 ≥3 次取分布。
3. **指标体系**（多数可直接从 blackboard 派生）：
   - 效率：累计去重相关条目数 / API 调用数；每轮 novelty 衰减曲线（衰减越慢越好）；
   - 质量：精确率——人工抽检（每配置抽 50 条，双人标注定金标）+ LLM-judge 大样本近似（用与采集**不同来源**的模型，避免自评偏置）；
   - 覆盖：命中 target topic 数 / 总数；coverage_gaps 闭合率；
   - 终止质量：实际停止轮 vs 事后最优停止轮（边际收益拐点）的偏差；
   - 可靠性：structured_decision 成功率、各层 fallback 触发率；
   - 成本：tokens、API 调用次数、时延。
4. **bandit 单独验证**：离线回放历史 run 的 query_history，对比 bandit 排序与全源轮询的 regret，不消耗任何 API 配额。
5. **回归保障**：mock 源工具 + LLM 响应录制（cassette）使 CI 能确定性回归 sdk_loop 控制流，延续现有 `tests/test_real_intel_loop.py` 的测试风格。

---

## 10. 分阶段实施计划

| 阶段 | 内容 | 验收标准 |
|---|---|---|
| **P0：端点 spike**（短，1 个独立脚本目录） | claude-agent-sdk + GLM Anthropic 端点连通性验证，跑完第 5 章能力矩阵全部验证项 | 能力矩阵回填；工具调用成功率 ≥95%、JSON 决策解析 ≥90%，否则按既定降级方案定稿（如 tool-forcing、每决策点独立 query） |
| **P1：并行共存** | 落地 `agent_runtime/`、`tools_mcp/`、`intel/sdk_loop.py` 骨架与 `intel/rules.py` 抽取；先迁 2 个决策点（检索词改写 + 轮次终止）；`INTEL_ENGINE` 开关上线（默认 rules） | 现有测试全绿；sdk 引擎在基准任务上端到端跑通且 blackboard 输出 schema 与 rules 引擎一致；人为注入决策失败可观察到规则 fallback 生效并被记录 |
| **P2：智能提升** | 四能力全部落地（bandit、自由检索词、高级算子工具、终止决策）+ 三层相关性过滤 + 上下文摘要渲染 | 每能力有独立单测；bandit 离线回放 regret 优于轮询；agent 使用高级参数的调用占比 >0 且上升；relevance method 字段全量落盘 |
| **P3：评估与切换默认** | 按第 9 章协议跑完整 A/B 与人工抽检；达标后 `INTEL_ENGINE` 默认切 sdk | 同预算下：去重相关条目效率 ≥ rules 基线 +20%（目标值可评审调整）、精确率不低于基线、topic 覆盖不降；web 与 KG 链路回归通过 |
| **P4：移除 CrewAI** | 删 crewai 依赖、`crew.py`、`config/*.yaml`、`llms.py`；`real_loop.py` 摘除 CrewAI 引用后保留为纯规则 fallback；更新 CLAUDE.md / AGENTS.md / 本文档收尾 | `uv lock` 无 crewai；全测试通过；引擎级 fallback 演练（断网 / 错误 key）通过 |

### 10.1 实施状态（2026-06-13）

| 阶段 | 状态 | 说明 |
|---|---|---|
| P0 | **完成（验收通过）** | SDK 0.2.99 装入 `agentsdk` group；DeepSeek Anthropic 兼容端点全矩阵实测达标（工具调用 100%、tool-forcing 解析 100%，见第 5 章与 `spikes/agent_sdk_glm/results.deepseek.json`）；GLM 端点因 Coding Plan 到期保留为备选（`INTEL_SDK_PROVIDER=glm`） |
| P1 | **完成** | `agent_runtime/`（已多 provider 化）、`tools_mcp/`、`intel/rules.py`（real_loop 已改为委托共享规则）、`intel/sdk_loop.py`、`INTEL_ENGINE` 工厂（默认 rules）全部落地；fallback 注入测试（`tests/test_sdk_loop.py`）验证三层降级可观测；全套测试绿 |
| P2 | **完成** | 四能力 + 三层相关性 + 上下文摘要全部实现并各有单测；**bandit 离线回放在 33 个历史 run / 617 轮实测 regret 1.063 < 轮询 1.245，达标**；决策解析率经 DeepSeek 端点实测 100%；高级参数占比 / 终止偏差指标已入 `scripts/eval_ab.py`（`advanced_params` / `stop_round` 字段） |
| P3 | **进行中（sdk 引擎已可 live 运行）** | `tests/eval_goals.json`（7 个冻结目标）、`scripts/eval_ab.py`、`scripts/bandit_replay.py` 就绪并已冒烟；完整 A/B（7 目标 × 2 引擎 × 3 重复）、人工抽检与默认引擎切换待执行评审 |
| P4 | **未开始（按设计 gated on P3）** | 评审通过 P3 验收前不动 CrewAI 依赖 |

实现备注：sdk 引擎当前为**混合模式**——决策点经 `structured_decision`（tool-forcing）、采集由控制器按 agent 的 `CollectionPlanDecision` 提案执行（参数白名单校验 + 去重 + 预算裁剪）。`tools_mcp/source_server.py` 与 `agent_runtime/hooks.py` 已为"agent 在会话内直接调源工具"的完全 agentic 模式备好；P0 矩阵已确认 DeepSeek 端点工具调用可靠性 100%，技术上已解锁，但混合模式仍是 4.1 节既定架构（控制器掌握预算与落盘），是否切换完全 agentic 模式留待 P3 A/B 数据评审决定。

---

## 11. 风险登记册

| 风险 | 影响 | 缓解 |
|---|---|---|
| GLM Anthropic 端点对 SDK 高级特性支持未知（结构化输出、caching、subagent、长会话） | 决策可靠性 / 成本 | P0 spike 前置并写成能力矩阵（第 5 章）；结构化输出默认 tool-forcing + Pydantic 校验；缓存不可用则靠第 8 章摘要压缩控成本 |
| claude-agent-sdk 依赖捆绑的 Claude Code CLI 运行时（Node.js），Windows / Docker 部署面变大 | 可部署性 | Dockerfile 固化运行时版本；`agent_runtime/client.py` 设计为薄适配层——极端情况下可降级为 `anthropic` SDK 手写工具循环而不动上层 |
| 上下文 / 调用成本上升（多轮工具循环 vs 现状单发 1400 tokens） | 成本 | 每轮会话重置 + 摘要传递；critic 用 fast 档；hooks 强制 max_api_calls 并把 token 记账进 `RunMetrics` |
| GLM 模型 agentic 能力不足导致工具滥用 / 死循环 | 质量 | PreToolUse 去重与配额拦截；max_turns 上限；决策点级规则 fallback 保证表现下限不低于现状（现状即纯规则） |
| 双引擎期间规则逻辑两份漂移 | 维护性 | real_loop 规则函数抽取为 `intel/rules.py` 共享模块，sdk_loop 的 fallback 直接复用同一实现 |
| 评估金标主观性 | 结论可信度 | 双人标注 + 异源模型 LLM-judge；标注指南随 `tests/eval_goals.json` 固化 |

---

## 12. 附录

### 12.1 决策点 → Schema → Fallback 对照表

| 决策点 | 输出 Schema（现有，保留） | Fallback 规则（迁入 `intel/rules.py`） |
|---|---|---|
| 行动选择 | `ActionDecision` 相关输出模型 | 固定动作序列 |
| 收益评估 | `YieldAssessment` 输出模型 | 计数直接计算 novelty/noise/dup |
| 覆盖分析 | `CoverageAnalysisOutput` | `detect_topics()` 与 target_topics 差集 |
| 语义扩展 | 扩展词输出模型 | topic→terms 硬编码映射 |
| 策略改写 | `RewriteDecisionOutput` | 高 ROI gap → `_non_repeating_gap_query` |
| 完整性判断 | `CompletenessDecisionOutput` | 预算 / 收益递减 / 覆盖阈值规则 |

### 12.2 环境变量变更清单

| 变量 | 状态 | 说明 |
|---|---|---|
| `INTEL_ENGINE` | **新增**（P1） | `rules` \| `sdk`，P3 达标后默认切 `sdk` |
| `INTEL_SDK_PROVIDER` | **新增**（已实现） | `deepseek` \| `glm`；未设置时自动探测（DEEPSEEK_API_KEY 优先） |
| `DEEPSEEK_API_KEY` / `DEEPSEEK_MODEL` / `DEEPSEEK_FAST_MODEL` | **新增**（已实现） | DeepSeek Anthropic 兼容端点（默认 deepseek-v4-pro / deepseek-v4-flash） |
| `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` | **新增**（P0） | 显式覆盖 provider 端点与凭证 |
| `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL` | **新增**（P0） | 模型档位映射 |
| `INTEL_ENABLE_AGENT_KICKOFF` | **废弃**（P4 删除） | 被 `INTEL_ENGINE` 取代 |
| `GLM_MODEL` / `GLM_FAST_MODEL` / `GLM_BASE_URL` | 保留 | base_kg、KG 适配层与相关性 2/3 层仍使用（OpenAI 兼容路径）；provider=glm 时 sdk 引擎模型档位也取自这两个变量 |
| `INTEL_SDK_MODEL` / `INTEL_SDK_FAST_MODEL` | **新增**（P1，已实现） | 覆盖 sdk 引擎 main/fast 档模型（默认回落当前 provider 的模型变量与内置默认值） |
| `INTEL_MIN_ROUNDS` | **新增**（P2，已实现） | 轮次终止决策的下限安全阀（默认 1） |
| `INTEL_RELEVANCE_ENABLED` | **新增**（P2，已实现） | 三层相关性过滤开关（默认开；无 GLM_API_KEY 时自动只剩规则层） |
| `INTEL_RELEVANCE_ACCEPT` / `INTEL_RELEVANCE_REJECT` / `INTEL_RELEVANCE_EMB_ACCEPT` / `INTEL_RELEVANCE_EMB_REJECT` | **新增**（P2，已实现） | 各层阈值（默认 0.75 / 0.20 / 0.62 / 0.42） |
| `INTEL_EMBEDDING_MODEL` / `INTEL_RELEVANCE_JUDGE_MODEL` | **新增**（P2，已实现） | 相关性第 2/3 层模型（默认 `embedding-3` / `GLM_FAST_MODEL`） |

### 12.3 参考链接

- claude-agent-sdk（PyPI，v0.2.99）：https://pypi.org/project/claude-agent-sdk/
- 智谱 Anthropic 兼容端点接入（Claude Code × GLM）：https://zhuanlan.zhihu.com/p/1993323826382139976 、https://segmentfault.com/a/1190000047552132
- 既有路线需求来源：仓库根目录 `CLAUDE.md`「方向一：情报采集的自主决策能力」
- 相关性三层过滤参考实现：`base_kg/pipeline/relevance.py`
