# CLAUDE.md

本文件为 Claude Code 在本仓库工作时的项目指南。CrewAI 框架的编码规范、API 模式与命令速查请遵循根目录 `AGENTS.md`（尤其是"写 CrewAI 代码前先核对已安装版本与官方文档"的要求），本文件不重复其内容，只补充项目自身的背景、约定与发展路线。

## 项目定位

构建一个**聚焦大语言模型（LLM）安全的情报采集与知识图谱构建智能体**。系统分两条主线：

1. **情报采集**：自动从真实安全数据源（NVD、CISA KEV、OSV、arXiv）采集 LLM/AI 安全相关情报（prompt injection、jailbreak、RAG poisoning、agent tool abuse、模型供应链等主题），并进行相关性判断、覆盖度分析与多轮检索反思。
2. **知识图谱构建**：基于 CTINexus 为单条情报生成 item 级小 KG；最终目标是融合为一张覆盖 LLM 安全领域的**全局大知识图谱**（见下文路线图）。

## 技术栈与运行

- Python `>=3.10,<3.14`，包管理一律用 `uv`（`uv sync` / `uv add`）。
- CrewAI `1.14.4`（项目类型 crew）、CTINexus `0.2.1`、Gradio 5.x。
- 常用入口（定义在 `pyproject.toml [project.scripts]`）：
  - `uv run web` — 启动 Gradio 控制台（默认 8000 端口）
  - `uv run run_crew` 或 `crewai run` — 命令行情报采集（旧 CrewAI 引擎，legacy）
  - `uv run latest_intel` — 查看最近一次采集结果
  - **`uv run intel-agent full` / `uv run intel-agent incremental` / `uv run intel-agent latest`** —
    新的自包含 Claude Agent SDK 情报采集引擎（`backend/intel_agent/`，见下文「情报采集重构」）。
    加 `--verbose` 实时打印模型文本/工具调用并落 `data/intel_agent/traces/<run_id>.jsonl`。
- 测试：`uv run pytest tests/`（旧包）与 `uv run pytest backend/intel_agent/tests`（新引擎，离线，当前约 29 项）。修改 intel/kg/schemas/web 模块后请跑对应测试文件。
- 依赖同步（新引擎）：`uv sync --group agentsdk --group intelagent`（含 `claude-agent-sdk`、`pydantic`、`pymongo`）。
- Docker 部署：
  - Web（旧引擎）：`docker compose up --build`，挂载 `./data` 与 `./ctinexus_output`。
  - intel_agent + MongoDB：`docker compose up -d mongo` 起库；`docker compose run --rm intel-agent full --verbose` 跑一次采集（镜像 `Dockerfile.intel_agent`，`profiles:["intel"]`，容器内自动用 `mongodb://mongo:27017`）。
- 环境变量见 `.env.example`；KG 适配层 API key 回退顺序：`CTINEXUS_*` → `OPENAI_*` → `GLM_*`。

## 代码结构要点

```
src/sufe_saads_crewai/
├── intel/real_loop.py        # RealIntelRunController：真实源多轮采集主控制器
├── intel/adaptive_loop.py    # 自适应采集循环
├── kg/ctinexus_adapter.py    # CTINexus 适配层（item 级 KG 生成）
├── kg/eligibility.py         # kg_ready 判断（来源排除、相关度阈值、主题匹配）
├── kg/feedback.py            # triplet 人工反馈记录（JSONL，闭环尚未接通）
├── schemas/                  # Pydantic 模型（intel、kg、coverage、persistence 等）
├── tools/registered_source_tools.py  # NVD / CISA KEV / OSV / arXiv 源工具
├── web/app.py                # Gradio 控制台
├── config/{agents,tasks}.yaml
└── crew.py / main.py
```

> **情报采集重构（2026-07，重要）**：情报采集主线已迁移到全新的**自包含**模块
> `backend/intel_agent/`，以 **Claude Agent SDK** 为核心（loop-engineering + self-evolving），
> **对 `src/sufe_saads_crewai` 零依赖**（自带 schema、源客户端、三层相关性、持久化、技巧库）。
> 老的 `src/sufe_saads_crewai/intel/`（`real_loop.py` / `adaptive_loop.py` / `sdk_loop.py` 等）、
> `crew.py`、`config/*.yaml`、`tools/registered_source_tools.py` 均视为 **legacy**：可随时删除而不影响
> 新引擎运行；写新功能一律进 `backend/intel_agent/`，不要再改老 intel 模块。KG（`kg/`）、Web
> （`web/`）、`base_kg/` 暂保留但不被新引擎依赖。模块结构、两种采集模式与调参见
> `backend/intel_agent/README.md`。

```
backend/intel_agent/               # 自包含 SDK 情报采集引擎（0 import src/）
├── schemas.py / topics.py / analysis.py   # 自带模型、话题、确定性分析层
├── sources.py                     # NVD / arXiv / CISA KEV / OSV 客户端（含重试）
├── relevance.py                   # 三层相关性：rule → embedding → flash LLM
├── persistence.py                 # JSON 存储：data/intel_runs/<run_id>.json + latest.json
├── mongo_store.py + store.py       # MongoDB 历史库（runs + 全局去重 items）+ 存储工厂
├── observability.py               # --verbose 追踪（控制台 + JSONL transcript）
├── runtime/                       # provider 解析、options、tool-forcing 结构化决策
├── memory/                        # 自演化技巧库 Playbook（upsert/衰减/召回/harvest）
├── tools/ + hooks.py              # 轮内 @tool（源搜索/召回/记录/收尾）+ 审计钩子
├── agent/                         # 每轮一个 SDK 会话 + 终止 critic
├── engine/                        # 采集模式(full/incremental) + 编排 controller + digest + fallback
├── cli.py                         # intel-agent full / incremental / latest
└── tests/                         # 离线单测（注入 fake runner/embedder）
```

数据与输出约定：

- 采集结果：`data/intel_runs/<run_id>.json`（含 `blackboard.raw_items`、`query_history`、`coverage_gaps`、`reflection_notes`、`item_knowledge_graphs`）与 `latest.json`。
- **intel_agent 历史库（MongoDB，可选）**：设置 `INTEL_MONGO_URI`（或 `INTEL_MONGO_ENABLED=1`）后，`backend/intel_agent` 落库到 MongoDB——`runs` 集合每次采集任务一份文档，`items` 集合以 `item_id` 作 `_id` 做全局去重（同一情报永不重复入库，多轮出现只 upsert 并把 run 追加到 `run_ids` 溯源数组）。未配置时回退到上面的 JSON 文件（离线/测试零依赖）。`docker compose up -d mongo` 起本地库；宿主机/DBeaver 连 `localhost:27017`、库名 `intel_agent`、无鉴权；容器内用 `mongodb://mongo:27017`。
- **intel_agent verbose 追踪**：`--verbose` 会实时打印模型文本/工具调用，并把完整事件流写到 `data/intel_agent/traces/<run_id>.jsonl`。
- item 级 KG：`data/intel_runs/<run_id>_kg/<item_id>.json` + `manifest.json`；可视化 HTML 在 `ctinexus_output/`。
- **base KG 源语料**：`data/kg-source/`，约 470 篇 PDF，分五类——`arxiv/`（322 篇）、`ICML/`（100 篇）、`OWASP/`（10 篇，LLM Top 10 系列）、`其他/`（NIST AI RMF 等 3 篇）、`知网/`（34 篇中文文献）。注意语料是中英混合的，pipeline 设计需考虑双语处理。
- KG 生成只把 item 的 `raw_text`（为空则 `summary`）传给 CTINexus，title/source/URI/metadata 一律不进入抽取文本，`source_uri` 仅留在本项目记录中用于溯源。

详细的当前进展与已知风险见 `docs/PROJECT_PROGRESS.md`；**2026-07-10 intel_agent 验证/可观测性/Mongo/Docker 会话纪要**见 `docs/SESSION_2026-07-10_intel_agent_maturity.md`。

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