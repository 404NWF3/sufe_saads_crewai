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
  - `uv run run_crew` 或 `crewai run` — 命令行情报采集
  - `uv run latest_intel` — 查看最近一次采集结果
- 测试：`uv run pytest tests/`。修改 intel/kg/schemas/web 模块后请跑对应测试文件。
- Docker 部署：`docker compose up --build`，挂载 `./data` 与 `./ctinexus_output`。
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

数据与输出约定：

- 采集结果：`data/intel_runs/<run_id>.json`（含 `blackboard.raw_items`、`query_history`、`coverage_gaps`、`reflection_notes`、`item_knowledge_graphs`）与 `latest.json`。
- item 级 KG：`data/intel_runs/<run_id>_kg/<item_id>.json` + `manifest.json`；可视化 HTML 在 `ctinexus_output/`。
- **base KG 源语料**：`data/kg-source/`，约 470 篇 PDF，分五类——`arxiv/`（322 篇）、`ICML/`（100 篇）、`OWASP/`（10 篇，LLM Top 10 系列）、`其他/`（NIST AI RMF 等 3 篇）、`知网/`（34 篇中文文献）。注意语料是中英混合的，pipeline 设计需考虑双语处理。
- KG 生成只把 item 的 `raw_text`（为空则 `summary`）传给 CTINexus，title/source/URI/metadata 一律不进入抽取文本，`source_uri` 仅留在本项目记录中用于溯源。

详细的当前进展与已知风险见 `docs/PROJECT_PROGRESS.md`。

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
