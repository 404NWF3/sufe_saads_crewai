# CLAUDE.md

本文件为 Claude Code 在本仓库工作时的项目指南。claude agent sdk 框架的编码规范、API 模式与命令速查请遵循根目录 `AGENTS.md`（尤其是"写 claude agent sdk 代码前先核对已安装版本与官方文档"的要求），本文件不重复其内容，只补充项目自身的背景、约定与发展路线。、

在开发 Claude agent sdk 项目的时候要注意查阅：https://code.claude.com/docs/en/agent-sdk/overview

## 项目定位

构建一个**聚焦大语言模型（LLM）安全的情报采集与知识图谱构建智能体**。系统分两条主线：

1. **情报采集**：自动从真实安全数据源（NVD、CISA KEV、OSV、arXiv）采集 LLM/AI 安全相关情报（prompt injection、jailbreak、RAG poisoning、agent tool abuse、模型供应链等主题），并进行相关性判断、覆盖度分析与多轮检索反思。
2. **知识图谱构建**：基于 CTINexus 为单条情报生成 item 级小 KG；最终目标是融合为一张覆盖 LLM 安全领域的**全局大知识图谱**（见下文路线图）。

## 技术栈与运行

- Python `>=3.10,<3.14`，包管理一律用 `uv`（`uv sync` / `uv add`）。
- CTINexus `0.2.1`、Gradio 5.x、Claude Agent SDK（`claude-agent-sdk`）、可选 MongoDB（`pymongo`）。
- 常用入口（`pyproject.toml [project.scripts]`）：
  - **`uv run intel-agent full` / `incremental` / `latest`** — `backend/intel_agent/` 采集引擎；加 `--verbose` 落 `data/intel_agent/traces/<run_id>.jsonl`。
  - **`uv run web`** — `backend/console/` Gradio：Collect / Trace / KG / **Database**。
- 测试：`uv run pytest backend/intel_agent/tests backend/ctinexus_kg/tests backend/console/tests -q`；冒烟 `uv run python scripts/smoke_pipeline.py`。
- 依赖同步：`uv sync --group agentsdk --group intelagent --group ctinexuskg --group web --group dev`。
- Docker：`docker compose up -d --build mongo web`（统一镜像）；批处理：`docker compose run --rm intel-agent full --verbose`（`Dockerfile.intel_agent`，`profiles:["intel"]`）。镜像以 root 跑时需 **`IS_SANDBOX=1`**（compose/Dockerfile 已设），否则 Claude Code 拒绝 `bypassPermissions` 并退化 rules fallback。
- 环境变量见 `.env.example`；KG API key 回退：`CTINEXUS_*` → `OPENAI_*` → `GLM_*`。
- **架构禁令**：`intel_agent` 与 `ctinexus_kg` **禁止互相 import**；交接仅通过 `run_id` + item DTO / 持久化产物。UI 编排只在 `backend/console`。

## 代码结构要点

```
backend/
├── common/               # 共享常量（仅 topics：Core / Extended）
├── intel_agent/          # SDK 采集引擎（0 import ctinexus_kg / src）
├── ctinexus_kg/          # item 级 KG（0 import intel_agent / src）
└── console/              # Gradio：采集 + verbose + KG + Database
```

> **主线（2026-07）**：采集与构图解耦。`intel_agent` 只采集并持久化；`ctinexus_kg` 只消费
> 已落库条目生成 item KG；`console` 负责 UI、TraceSink 实时轨迹与数据库浏览。详见各包 README。
> `base_kg/`（Neo4j 基底图）仍为独立方向，不接入本流水线。

```
backend/intel_agent/               # 自包含 SDK 情报采集引擎
├── schemas.py / topics.py / analysis.py
├── sources.py / relevance.py
├── persistence.py / mongo_store.py / store.py   # list_run_summaries / query_items
├── observability.py               # TraceSink：console + JSONL + on_event 回调
├── runtime/ / memory/ / tools/ / hooks.py
├── agent/ / engine/ / cli.py
└── tests/

backend/ctinexus_kg/               # 自包含 CTINexus item-KG
├── schemas.py / topics.py / eligibility.py / prompting.py
├── ctinexus_adapter.py / pipeline.py / feedback.py
└── tests/

backend/console/                   # Gradio 统一控制台
├── app.py / db_browser.py
└── tests/
```

数据与输出约定：

- 采集结果：`data/intel_runs/<run_id>.json` + `latest.json`（未开 Mongo 时）；或 MongoDB `intel_agent.runs` / `items`。
- **MongoDB（可选）**：`INTEL_MONGO_URI` 或 `INTEL_MONGO_ENABLED=1`。`runs` 每任务一份；`items` 以 `item_id` 作 `_id` 全局去重（`run_ids` 溯源）。宿主机/DBeaver：`localhost:27018`（compose 映射，避开本机 mongod 27017）、库 `intel_agent`、无鉴权；容器内：`mongodb://mongo:27017`。数据在命名卷 `mongo_data`，勿再 bind-mount `data/mongo`。全量 CSV：宿主机用 `mongoexport`（勿在 mongosh 内跑 `docker`）；或 Gradio Database / `data/exports/`。
- **verbose 追踪**：`data/intel_agent/traces/<run_id>.jsonl`。
- item 级 KG：`data/intel_runs/<run_id>_kg/<item_id>.json` + `manifest.json`；可视化 HTML 在 `ctinexus_output/`。
- CSV 导出：`data/exports/`（Database 面板或 `mongoexport`）。
- **base KG 源语料**：`data/kg-source/`（中英混合 PDF）。
- KG 只把 item 的 `raw_text`（空则 `summary`）传给 CTINexus；`source_uri` 仅作溯源。

详细进展见 `docs/PROJECT_PROGRESS.md`；会话纪要见 `docs/SESSION_2026-07-10_intel_agent_maturity.md`。

## 发展路线图

以下是两个明确的改进方向，做相关功能设计与实现时以此为准。

### 方向一：情报采集的自主决策能力

当前采集智能体已初步可用，但检索策略基本是预设的（固定源 + 模板化 query + 用户指定轮数）。目标是让智能体在采集过程中**自主决策**，具体包括四个能力：

1. **源选择决策**：根据搜索目标和各源的历史收益（novelty、duplicate ratio、noise ratio 已在 blackboard 中记录）自主决定本轮从哪些源采集，而不是每轮全源轮询。
2. **检索词决策**：自主生成与改写检索词，而不仅是围绕 coverage gap 的模板化 rewrite。
3. **高级检索策略**：融入各源的高级检索语法（如 NVD 的 CPE/CWE 过滤、arXiv 的字段限定与布尔组合、时间窗口过滤），让智能体能选择并组合这些算子。
4. **轮次决策**：由智能体根据边际收益（每轮新增量、覆盖度变化）自主判断是否继续下一轮，替代固定 `max_rounds` 上限（上限可保留为安全阀）。

实现提示：决策逻辑应延续现有"CrewAI agent 输出优先、确定性 fallback 兜底"的模式（见 `intel/real_loop.py`），决策依据（每轮指标）已基本齐备于 blackboard，重点是把这些信号喂给决策 agent 并扩展源工具的高级检索参数。

### 方向二：从单条小 KG 到全局大知识图谱

当前 KG 是单条情报的孤立子图。最终目标是一张完整的 LLM 安全领域大图，**分两步走**：

#### 第一步：top-down 构建 base KG（当前重点，骨架已落地）

**状态（2026-06-12）**：独立模块 `base_kg/` 已实现并通过冒烟验证——机器可读 schema v0.2（`base_kg/schema/llm_security_schema.json`）、四个抽取 prompt、corpus→extract→load→evaluate 流水线、Neo4j Docker 服务（`docker compose up -d neo4j`）。该模块**不接入** `sufe_saads_crewai` 包，依赖装在 `basekg` dependency group。尚未跑真实 LLM 抽取实验。用法与 schema 改进记录见 `base_kg/README.md`。

参考论文《Automated knowledge extraction from marine accident reports using large language models: Graph construction and evaluation》（根目录 PDF）的方法论，在 `data/kg-source` 语料上构建领域基底图。论文 pipeline 的关键环节：

1. **语料与分块**：每篇报告/文献作为一个 chunk，保持单案例上下文完整，避免跨文档语义干扰。
2. **schema 引导抽取**（top-down）：schema 以 JSON 格式同时供人读与供 LLM prompt 使用；抽取分解为三个 LLM 子任务依次执行——**NER →实体标准化 → 关系抽取**，每步用 one-shot/chain-of-thought prompt，关系类型严格受 schema 约束。
3. **嵌入存储**：抽取文本经 embedding 模型向量化入库，支撑后续评估与融合。
4. **双视角质量评估**：
   - *结构复杂度*：实体冗余（embedding 聚类找变体/同义词）、关系冗余、自环（hallucination 信号）等指标；
   - *语义准确性*：从 KG 子图重构原文，用 bi-encoder 句级最大相似度的均值衡量重构精度，作为无需人工标注的全局语义保真度指标。

**Schema 现状**：初版设计见根目录 `LLM_Security_KG_Schema_Table1.docx`（5W1H 六维：Who / When / Where / What / Why-How / Result-Impact）。当前生效版本是 **v0.2 机器可读 JSON**（`base_kg/schema/llm_security_schema.json`，27 实体类型 / 30 关系），相对 docx 的修订（属性与类型分离、命名统一、关系显式 domain/range、攻击/防御/影响收敛为枚举等）记录在 `base_kg/README.md`。继续迭代时直接改 JSON——prompt 渲染与三元组校验自动跟随；注意保持层次清晰与关系命名一致性（论文指出 LLM 易混淆相近关系如时间/空间锚定）。

#### 第二步：item 级 KG 融合进 base KG

把采集流水线持续产出的单条情报 KG 融合进 base KG，得到动态生长的完整大图。这需要设计精巧的融合算法，核心问题包括：

- **实体对齐**：item KG 实体（CTINexus 输出，MALOnt 风格类型）与 base KG 实体（5W1H schema 类型）之间的映射与匹配，可复用 embedding 相似度 + 阈值（现有 entity alignment threshold 机制可参考），辅以 CVE ID、产品名、攻击技术名等强标识符做精确锚定。
- **schema 映射**：两套类型体系（CTINexus/MALOnt vs. 自研 5W1H schema）需要一张显式映射表或归一化层。
- **冲突与去重**：同一事实多源出现时的合并策略、置信度记录、来源溯源（保留 `source_uri` 级 provenance）。
- **质量门控**：融合前复用第一步的评估指标（冗余、自环、重构精度）过滤低质子图；人工反馈机制（`kg/feedback.py`）可作为融合质量的修正信号。

## 工作约定

- 文档与注释延续仓库现状：面向用户的文档（README、docs/）用中文，代码标识符与日志用英文。
- KG 生成失败不得影响情报采集主流程——记录 failed record 并继续，这是既有设计原则。
- 新增 Pydantic 模型放在 `schemas/` 下并补充 `tests/test_schemas.py`。
- 改动 CrewAI 相关代码前，按 `AGENTS.md` 要求核对已安装版本（`1.14.4`）与官方文档，不要凭训练数据中的旧 API 写代码。

# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.