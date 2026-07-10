# SUFE SAADS CrewAI 项目进展说明

更新时间：2026-07-10（§7 追加 intel_agent 重构进展；§1–6 仍描述 legacy CrewAI/Web 主线，待整体改写）

## 1. 当前技术栈

- 核心编排：CrewAI `1.14.4`，项目类型为 Crew，Python 版本约束为 `>=3.10,<3.14`。
- 包管理与运行：`uv` / `pyproject.toml`，当前主入口仍为 `sufe_saads_crewai.main:run` 与 `run_with_trigger`。
- 情报采集：自研 `RealIntelRunController`，通过已注册真实源工具检索 NVD、CISA KEV、OSV、arXiv 等来源。
- 反思与检索决策：CrewAI agent 输出优先，失败时使用确定性 fallback；围绕 coverage gaps、yield、semantic expansion、query rewrite 决定是否继续下一轮。
- KG 生成：新增 CTINexus 适配层，依赖 `ctinexus==0.2.1`。默认采用论文中的关键设置：IE 2-shot、ET 8-shot、LP 2-shot、实体对齐阈值 `0.6`、embedding model `text-embedding-3-large`、demo permutation `asc`。KG 生成不在采集时自动执行，只在 Web 中选中情报后手动触发。
- Web 前端：新增 Gradio 控制台，用于设置搜索目标、初始 query、检索轮次、结果数、KG 开关、模型、temperature、base URL、embedding model 与实体对齐阈值。
- 部署：新增 Dockerfile 与 docker-compose，默认暴露 `8000`，将 `data/` 与 `ctinexus_output/` 作为持久化挂载目录。

## 2. 已实现情况

### 2.1 每条情报的小 KG 生成

新增模块：

- `src/sufe_saads_crewai/kg/eligibility.py`
- `src/sufe_saads_crewai/kg/prompting.py`
- `src/sufe_saads_crewai/kg/ctinexus_adapter.py`
- `src/sufe_saads_crewai/kg/feedback.py`
- `src/sufe_saads_crewai/schemas/kg.py`

实现流程：

1. 真实源检索完成后，`RealIntelRunController` 只负责将 `RawIntelItem` 合并到 blackboard 并保存，不自动生成 KG。
2. Web 原始情报表会对每条情报做 KG eligibility 判断。
3. 默认跳过 `arxiv_api`，因为 arXiv 更偏论文摘要，不是 CTINexus 原始 CTI 报告的最佳输入；Web 中可以手动忽略该排除规则。
4. 用户在 Web 中选中某条情报后，系统只把该 item 的 `raw_text` 原文作为 `text` 传给 CTINexus；如果 `raw_text` 为空，则传 `summary`。title、source、URI、metadata 都不进入 CTINexus 抽取文本，`source_uri` 也不会作为 `source_url` 传入 CTINexus，只在本项目记录中保留用于溯源。
5. 调用 CTINexus `process_cti_report()` 生成 item-level KG。
6. 每条情报写入独立 JSON，运行级别写入 `manifest.json`。
7. 手动生成后的 KG 记录会写回 run JSON 的 `blackboard.item_knowledge_graphs`，包含 KG 状态、输出路径、三元组数量、实体数量、预测关系数量与错误信息。

输出位置：

- 主运行 JSON：`data/intel_runs/<run_id>.json`
- KG manifest：`data/intel_runs/<run_id>_kg/manifest.json`
- 单条 KG JSON：`data/intel_runs/<run_id>_kg/<item_id>.json`
- 可视化 HTML：如果 CTINexus 返回 graph html，则复制到同一 KG 目录。

### 2.2 CTINexus 参数兼容

新增 `KgGenerationConfig`，支持：

- `enabled`
- `provider`
- `model`
- `embedding_model`
- `similarity_threshold`
- `max_input_chars`
- `min_relevance_score`
- `exclude_sources`
- `base_url`
- `api_key_env`
- `base_url_env`
- IE / ET / EA / LP 分阶段模型、shot、temperature 配置

适配器会桥接环境变量：

- 优先使用 `CTINEXUS_API_KEY` / `CTINEXUS_BASE_URL`
- 其次回退到 `OPENAI_API_KEY` / `OPENAI_BASE_URL`
- 再回退到 `GLM_API_KEY` / `GLM_BASE_URL`

### 2.3 crewai run 后的 JSON 返回能力

`run()` 与 `run_with_trigger()` 的摘要现在包含：

- `run_id`
- `rounds`
- `raw_items`
- `knowledge_graphs`
- `coverage_gaps_remaining`
- `saved_to`
- `kg_manifest_path`
- `last_action`

完整情报与 KG 记录仍保存在运行 JSON 的 `blackboard.raw_items` 与 `blackboard.item_knowledge_graphs` 中。

### 2.4 Web 控制台

新增入口：

- Python 模块：`python -m sufe_saads_crewai.web.app`
- pyproject script：`web`

当前 Web 功能：

- 设置搜索目标与初始 query。
- 设置最大轮数与每轮最大结果数。
- 开关 item KG 生成。
- 设置 CTINexus model、temperature、base URL、API key、embedding model、实体对齐阈值。
- 设置 IE / ET / LP few-shot 数量。
- 查看运行摘要、原始情报表、KG 记录表；采集完成后不会自动转 KG。
- 在原始情报表中查看 `kg_ready`、`kg_block_reason`、`text_chars`，用于判断每条情报为什么能或不能转 KG。
- 在 KG 页面通过 `KG-ready intelligence item` 下拉框选择 `kg_ready=true` 的情报项；不可转 KG 的情报不会出现在该下拉框中。选中后可查看预览，再手动触发单条情报 KG 生成，并写回 run JSON 与 KG manifest。
- 按 KG 行号加载单条 KG JSON。

### 2.5 Docker 部署骨架

新增：

- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `.env.example`

启动方式：

```bash
docker compose up --build
```

默认访问：

```text
http://localhost:8000
```

## 3. 计划中但尚未完成的部分

- 尚未把 CTINexus 的原生 Gradio 前端与本项目 Gradio 前端做 UI 级融合，目前只是能力级集成。
- 尚未将 CTINexus 的 prompt 模板直接复制进本项目；当前通过 `ctinexus` 包调用其内部模板，并在输入构造层加入 LLM 安全上下文。
- 尚未实现 KG 的人工反馈闭环 UI。底层已有 `TripletFeedbackRecord` 与 JSONL 追加/读取函数。
- 尚未把人工反馈反向注入 CTINexus demonstration set 或下一轮 extraction prompt。
- 尚未实现跨 item KG 合并，目前是每条情报一个小 KG，后续需要再做 run-level KG 或长期知识库。
- 尚未将 arXiv 论文走单独 academic extraction pipeline。当前默认跳过 arXiv 的 CTINexus KG 生成。
- 尚未增加生产级认证、任务队列、异步后台运行与多用户隔离。
- 尚未执行真实 CTINexus LLM 调用验证，因为需要可用 API key、base URL 与完整依赖同步。

## 4. 下一步计划

1. 跑通依赖同步：执行 `uv sync`，确认 `ctinexus==0.2.1`、Gradio 与 CrewAI 在同一环境内兼容。
2. 用 2 到 3 条 NVD/CISA/OSV 真实情报做小样本端到端测试，验证 KG JSON、manifest 与 HTML 图是否正确产生。
3. 增加 KG 质量检查：校验三元组 subject/relation/object 是否完整、是否出现 hallucination 标记、实体类型是否落在 MALOnt 或 LLM 安全扩展集合中。
4. 增加人工反馈页面：允许逐条接受、拒绝、修改 triplet，并写入 `triplet_feedback.jsonl`。
5. 将反馈用于下一轮 KG 生成：把已拒绝或修正的 triplet 转为 negative/positive examples，注入 CTINexus prompt 或 demonstration retrieval。
6. 实现 run-level KG 合并：把每条 item KG 汇总成一次运行的总图，并按 source_uri、CVE、产品、攻击技术做跨来源对齐。
7. 设计 arXiv 专用路径：论文保留摘要、方法、数据集、攻击类型、评估指标，生成 research KG，而不是直接套 CTI KG。
8. 将 Gradio 控制台升级为异步任务型前端：运行状态轮询、历史运行列表、KG HTML 预览、下载 JSON/CSV。
9. 完善 Docker 镜像：增加 healthcheck、非 root 用户、固定 lockfile 安装策略与部署文档。

## 5. 当前风险与注意事项

- CTINexus 本身依赖 LLM 与 embedding API，KG 生成失败不应影响情报采集主流程；当前实现会记录 failed record 并继续运行。
- 如果使用 OpenAI-compatible 自定义模型服务，KG 适配层会在 CTINexus 调用 LiteLLM 时把裸模型名自动规范为 `openai/<model>`，例如 `glm-4.7` 会转为 `openai/glm-4.7`。
- Dockerfile 当前选择在线 `pip install .`，适合快速部署；生产环境建议在同步依赖后补充 lockfile 级安装。
- Web UI 会在当前进程设置 `CTINEXUS_API_KEY` 与 `CTINEXUS_BASE_URL`，适合单用户本地部署；多用户部署需要改为任务级隔离。

## 6. 情报采集智能体后续路线

情报采集智能体的下一阶段路线（迁移 Claude Agent SDK、四个自主决策能力、相关性三层过滤、评估基线与分阶段实施计划）见 [INTEL_AGENT_SDK_ROADMAP.md](INTEL_AGENT_SDK_ROADMAP.md)（2026-06-12）。

### 6.1 路线实施进展（2026-06-13）

P0-P3 的代码与评估资产已落地，详见 ROADMAP 第 10 章状态标注。摘要：

- **P0 spike（验收通过）**：claude-agent-sdk `0.2.99` 已装入 `agentsdk` dependency group；spike 脚本在 `spikes/agent_sdk_glm/`。SDK 端点已多 provider 化（`INTEL_SDK_PROVIDER=deepseek|glm`，`agent_runtime/client.py`）。**DeepSeek Anthropic 兼容端点（`https://api.deepseek.com/anthropic`，deepseek-v4-pro / deepseek-v4-flash）全矩阵实测达标**：工具调用 100%（≥95% 达标线）、tool-forcing 结构化决策解析 100%（≥90% 达标线）、多轮/长会话稳定；subagent、prompt caching、json_schema output_format 三项不达标但均有既定降级方案且不影响混合架构（详见 ROADMAP 第 5 章）。GLM 端点因 Coding Plan 订阅到期保留为备选（429/1309，同账号 OpenAI 兼容路径正常）。
- **P1 骨架**：`agent_runtime/`（SDK 工厂、`structured_decision` tool-forcing + Pydantic 校验 + fallback 契约、PreToolUse/PostToolUse hooks）、`tools_mcp/source_server.py`（4 个 typed `@tool`，高级算子直接暴露）、`intel/rules.py`（real_loop 全部确定性规则抽为共享模块，双引擎共用）、`intel/sdk_loop.py`（SDK 主控制器，三层 fallback、遥测落盘 `engine_telemetry`）、`INTEL_ENGINE=rules|sdk` 工厂开关（默认 rules，`main.py` 与 Web 均经 `create_intel_controller`）。
- **P2 四能力**：源选择（`intel/bandit.py` UCB1 + agent 否决，状态持久化 `data/bandit_state.json`）、检索词自由生成（`CollectionPlanDecision`，代码侧参数白名单校验）、高级检索算子（NVD CWE/CVSS/时间窗/KEV、arXiv 布尔与 cat:、OSV ecosystem/purl）、轮次终止（边际收益特征 + `min_rounds`/`max_rounds` 安全阀）；三层相关性过滤 `intel/relevance.py`（规则→embedding→flash LLM，JSONL 缓存，`metadata.relevance.method` 落盘）；上下文摘要 `intel/context.py`（≤2-3K tokens，禁 dump 原文）。
- **P3 评估资产**：基准任务集 `tests/eval_goals.json`（7 个冻结目标）；A/B 协议脚本 `scripts/eval_ab.py`（已含第 9 章效率/可靠性指标 + 高级参数占比 `advanced_params` + 终止偏差 `stop_round`，rules 与 sdk 引擎均已冒烟跑通）；bandit 离线回放 `scripts/bandit_replay.py` —— **在 33 个历史 run / 617 轮上实测 bandit regret 1.063 < 轮询 regret 1.245，验收达标**。
- **测试**：新增 `test_intel_rules` / `test_sdk_loop` / `test_bandit` / `test_relevance` / `test_agent_runtime`（含 provider 解析）/ `test_engine_factory`，全套 77 用例通过；SDK 引擎的决策路径与 fallback 路径均有确定性单测（fake runner，不耗 API）。

**下一步（P3 收尾）**：① 按 `tests/eval_goals.json` 跑完整 A/B（`uv run python scripts/eval_ab.py`，7 目标 × 2 引擎 × 3 重复，消耗真实配额）与人工抽检；② 达标后把 `INTEL_ENGINE` 默认切 `sdk`（P3 验收）；③ 评审通过后执行 P4 移除 CrewAI。SDK 引擎当前为"结构化决策 + 控制器执行"的混合模式；DeepSeek 端点工具调用可靠性 100% 已在技术上解锁完全 agentic 采集会话（`tools_mcp`/hooks 就绪），是否切换待 A/B 数据评审。

## 7. backend/intel_agent 重构进展（2026-07-10）

情报采集主线已迁移到自包含模块 `backend/intel_agent/`（Claude Agent SDK + loop-engineering + Playbook 自演化）。完整纪要见 [SESSION_2026-07-10_intel_agent_maturity.md](SESSION_2026-07-10_intel_agent_maturity.md)。

### 7.1 已交付（采集引擎）

- **引擎与 CLI**：`uv run intel-agent full|incremental|latest`；全量/增量；rules fallback。
- **真实采集验证**：bootstrap 示例——多轮、数百条去重情报、源 API 预算内运行。
- **`--verbose`**：`observability.py` → 控制台 + `data/intel_agent/traces/<run_id>.jsonl`；`on_event` 供 UI。
- **MongoDB 历史库**：`mongo_store.py` + `store.default_store()`；`runs` + `items`（`item_id` 全局去重）；查询 API 供 Database 面板。
- **Docker 批处理**：`Dockerfile.intel_agent` + compose `intel-agent`（`profiles: ["intel"]`）。

### 7.2 统一交付（同日：ctinexus_kg × Gradio × Docker）

- **`backend/ctinexus_kg`**：自包含 item KG；`generate_for_run`；失败隔离；0 import intel_agent。
- **`backend/console`**：Collect（实时轨迹）/ Trace replay / Knowledge Graphs / **Database**（查询 + CSV）。
- **统一镜像**：根 `Dockerfile` + `docker compose up mongo web`；`IS_SANDBOX=1` 修复 root 下 Claude Code 拒绝 bypassPermissions。
- **冒烟**：`scripts/smoke_pipeline.py`；测试含 `backend/console/tests`。

### 7.3 尚未完成

- `docs/intel_agent_design.md`、ROADMAP Phase 4 全面改写、A/B 脚本对接新引擎。
- Mongo 生产鉴权；playbook 人工审核 UI；item KG ↔ base KG 融合。
- 若仓库仍含 legacy `src/` 采集路径，可归档删除（以当前分支为准）。
