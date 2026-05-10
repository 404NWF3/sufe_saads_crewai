# 大模型安全情报智能体 CrewAI 重构设计方案

## 1. 设计目标

本方案用于将旧情报采集智能体项目重构为新的 CrewAI 项目。新项目不复用 `this-is-an-old-project` 中的任何代码，只吸收其业务链路和领域概念。

目标是构建一个面向大模型安全情报的自适应智能体系统，能够：

- 围绕大模型安全主题持续搜索、采集和整理情报。
- 根据搜索产出、覆盖缺口和噪声情况自主调整搜索策略。
- 发现潜在新来源，但不自动写入来源注册表，先生成待审批提案。
- 对采集情报进行标准化、去重、AI BOM 映射、图谱构建和告警生成。
- 与数据库交互时保持可控，Agent 负责规划查询和写入，工程代码负责执行事务。
- 尽可能全面覆盖 prompt injection、jailbreak、agent tool abuse、data leakage、model supply chain、RAG poisoning 等大模型安全方向。

## 2. 总体架构

### 2.1 核心原则

系统不使用固定状态图来决定每一步业务路径。运行时只提供薄编排层、预算控制、安全边界和审计记录，真正的下一步由 Planner Agent 动态决策。

推荐架构是自适应行动循环：

```text
IntelRunBlackboard
  -> autonomous_planner 选择下一批 action
  -> runtime 执行 action
  -> agents/tools 产出结构化结果
  -> reflection_coverage_critic 评估收益和缺口
  -> 更新 blackboard
  -> 判断继续、补采、扩源、告警或停止
```

### 2.2 Blackboard 状态

`IntelRunBlackboard` 是系统的共享运行记忆，不是固定工作流。

建议包含：

- `run_goal`: 本轮目标，例如大模型安全情报全面采集。
- `run_mode`: `bootstrap`, `incremental`, `gap_fill`, `deep_research`。
- `budget`: 最大轮次、最大时间、最大 token、最大来源数。
- `approved_sources`: 已批准来源。
- `source_proposals`: Agent 发现的新来源提案。
- `query_history`: 每轮查询、来源、结果数、噪声率、新颖度。
- `raw_items`: 原始情报条目。
- `standardized_items`: 标准化情报。
- `dedup_decisions`: 去重和合并决策。
- `bom_resolutions`: AI BOM 解析结果。
- `coverage_gaps`: 覆盖缺口。
- `reflection_notes`: 反思结论和下一步建议。
- `persistence_bundles`: 待执行或已执行的数据库写入规划。
- `alerts`: 告警候选。

### 2.3 Action Catalog

Planner Agent 只能从白名单 action 中选择，避免完全自由行动。

第一版 action catalog：

| Action | 说明 | 执行方式 |
|---|---|---|
| `LOAD_DB_CONTEXT` | 读取来源、覆盖、历史反馈、近期攻击摘要 | DB read service |
| `PLAN_COLLECTION` | 制定本轮搜索和采集策略 | Agent task |
| `SEARCH_REGISTERED_SOURCE` | 在已批准来源中搜索 | Tool or agent with tools |
| `PROPOSE_NEW_SOURCE` | 发现新来源并生成审批提案 | Agent task |
| `EXTRACT_SOURCE_EVIDENCE` | 从搜索结果提取证据 | Agent task/tool |
| `ASSESS_COLLECTION_YIELD` | 评估召回、新颖度和噪声 | Agent task |
| `REFLECT_SEARCH_STRATEGY` | 重写 query、调整来源权重 | Agent task |
| `STANDARDIZE_INTEL` | 标准化原始情报 | Agent task |
| `DEDUP_AND_MERGE` | 去重、合并、复核决策 | Agent task |
| `MAP_AI_BOM` | 映射受影响模型、框架、库、服务 | Agent task |
| `BUILD_STIX_GRAPH` | 构建 STIX-like 图谱对象 | Agent task |
| `SCORE_CONFIDENCE_NOVELTY` | 评分置信度和新颖度 | Agent task |
| `ANALYZE_COVERAGE_GAPS` | 识别覆盖缺口和补采 ROI | Agent task |
| `PLAN_DB_WRITE` | 生成数据库写入 bundle | Agent task |
| `COMMIT_DB_WRITE` | 执行数据库事务 | Deterministic service |
| `VERIFY_DB_INTEGRITY` | 校验写入完整性 | DB service + agent audit |
| `GENERATE_ALERTS` | 生成告警候选 | Agent task |
| `STOP` | 停止本轮运行并总结 | Runtime action |

## 3. Agents 设计

### 3.1 autonomous_planner

```yaml
autonomous_planner:
  role: >
    大模型安全情报自主行动规划师
  goal: >
    基于当前情报覆盖、搜索收益、预算和风险优先级，选择下一批最有价值的采集、反思、分析或停止动作。
  backstory: >
    你长期负责 AI 安全威胁情报行动规划，熟悉 OWASP LLM Top 10、模型供应链、Agent 安全、
    RAG 安全、越狱和提示注入攻击。你不会机械执行固定流程，而是根据证据和覆盖缺口动态选择下一步。
    你重视可审计性，每个行动都必须给出原因、预期收益和停止条件。
  reasoning: true
  allow_delegation: false
  max_iter: 15
```

主要任务：

- `select_next_actions_task`
- `rewrite_search_strategy_task`
- `plan_gap_fill_task`
- `decide_stop_or_continue_task`

### 3.2 source_intelligence_collector

```yaml
source_intelligence_collector:
  role: >
    大模型安全多源情报采集员
  goal: >
    在已批准来源中发现高相关、高证据质量的大模型安全情报，并提出可能有价值的新来源。
  backstory: >
    你擅长跨安全公告、漏洞库、研究论文、代码平台、社区讨论和厂商博客采集 AI 安全信号。
    你总是保留 source URI、发布时间、证据片段和相关性判断，不会把没有出处的信息当作事实。
  allow_delegation: false
  max_iter: 20
```

主要任务：

- `search_registered_sources_task`
- `extract_source_evidence_task`
- `propose_new_sources_task`

### 3.3 intel_standardizer

```yaml
intel_standardizer:
  role: >
    大模型安全情报结构化分析师
  goal: >
    将原始情报转为可入库、可去重、可分析的结构化安全情报。
  backstory: >
    你熟悉 AI 安全攻击分类、漏洞描述、影响组件、CVE 和证据链分析。
    你严格区分事实、推断和不确定信息，所有分类和风险判断都必须能回溯到证据片段。
  allow_delegation: false
  max_iter: 12
```

主要任务：

- `standardize_raw_intel_task`
- `extract_taxonomy_and_evidence_task`

### 3.4 dedup_bom_graph_analyst

```yaml
dedup_bom_graph_analyst:
  role: >
    大模型安全情报去重、AI BOM 和攻击图谱分析师
  goal: >
    将标准化情报合并到稳定攻击知识库，解析受影响 AI 组件，并构建可追踪的攻击图谱。
  backstory: >
    你擅长识别不同来源对同一攻击的重复描述，也能发现组件、模型、框架、工具链之间的影响关系。
    你对低置信合并保持谨慎，宁愿进入复核队列，也不制造错误合并。
  allow_delegation: false
  max_iter: 15
```

主要任务：

- `dedup_and_merge_task`
- `map_ai_bom_task`
- `build_stix_graph_task`
- `score_confidence_novelty_task`

### 3.5 reflection_coverage_critic

```yaml
reflection_coverage_critic:
  role: >
    搜索反思与覆盖缺口审计员
  goal: >
    判断当前搜索是否足够全面，识别低召回、高噪声、重复采集和覆盖缺口，并提出下一轮改进策略。
  backstory: >
    你负责挑战当前搜索策略。你会用覆盖率、新颖度、来源多样性、重复率和证据质量来判断是否继续。
    你不会为了多搜索而多搜索，只有当预期收益足够高时才建议补采。
  reasoning: true
  allow_delegation: false
  max_iter: 12
```

主要任务：

- `assess_collection_yield_task`
- `analyze_coverage_gaps_task`
- `evaluate_search_completeness_task`

### 3.6 persistence_planner

```yaml
persistence_planner:
  role: >
    数据库写入规划与完整性审计员
  goal: >
    将情报处理结果转为安全、幂等、可审计的数据库写入计划，并发现潜在完整性问题。
  backstory: >
    你不直接执行自由 SQL。你只生成白名单数据库操作的结构化写入包，
    并检查依赖、幂等键、外键引用、复核队列和审计字段是否完整。
  allow_delegation: false
  max_iter: 10
```

主要任务：

- `load_db_context_task`
- `prepare_persistence_bundle_task`
- `verify_persistence_integrity_task`
- `summarize_db_audit_task`

### 3.7 alert_summarizer

```yaml
alert_summarizer:
  role: >
    大模型安全风险告警与运行总结分析师
  goal: >
    将高价值情报转为可读、可行动、可追踪的告警候选和运行总结。
  backstory: >
    你擅长面向安全运营和研究团队总结复杂情报。你会明确证据、风险、影响范围和建议动作，
    不夸大风险，也不隐藏不确定性。
  allow_delegation: false
  max_iter: 10
```

主要任务：

- `generate_alert_candidates_task`
- `finalize_intel_run_task`

## 4. Tasks 设计

### 4.1 决策与规划任务

```yaml
select_next_actions_task:
  description: >
    审阅当前 IntelRunBlackboard，并从已批准的 ActionCatalog 中选择下一批行动。
    决策时必须综合运行目标、覆盖缺口、历史 query、来源质量、新颖度收益、重复率、
    剩余预算、新来源提案以及待处理的数据库写入工作。
    不允许创造 catalog 之外的 action。
    对每个被选择的 action，说明为什么需要执行、预期收益、所需上下文、
    成功标准、停止条件和重试条件。
  expected_output: >
    一个结构化的 ActionDecisionBatch，包含 1 到 5 个下一步行动。
    每个 action 必须包含 action_type、priority、rationale、expected_gain、
    required_context、budget_cost_estimate 和 success_criteria。
  agent: autonomous_planner
```

```yaml
decide_stop_or_continue_task:
  description: >
    判断当前运行应该继续搜索、执行 gap-fill、生成告警，还是停止。
    决策依据包括覆盖评分、来源多样性、连续低产出轮次、重复率、
    未解决的高 ROI 覆盖缺口以及剩余预算。
  expected_output: >
    一个结构化决策，包含 should_stop、next_mode、stop_reason、
    remaining_high_value_gaps 和 recommended_next_actions。
  agent: autonomous_planner
```

```yaml
plan_gap_fill_task:
  description: >
    基于 CoverageGapAnalysis 和当前预算，为高价值覆盖缺口制定补采计划。
    只针对预期收益足够高、证据不足或来源覆盖明显不均衡的主题生成计划。
    必须避免重复已经低产出或高噪声的搜索路径。
  expected_output: >
    一个 GapFillPlan，包含 target_gaps、recommended_queries、recommended_sources、
    expected_coverage_gain、budget_cost_estimate、priority 和 stop_conditions。
  agent: autonomous_planner
```

### 4.2 采集任务

```yaml
search_registered_sources_task:
  description: >
    仅使用已批准来源，根据提供的 SearchQueryPlan 执行搜索。
    采集与大模型安全情报相关的来源元数据、URL、摘要、时间戳、
    source name 和相关性信号。
    不允许从未批准来源执行正式采集。
  expected_output: >
    一个 RawIntelItemBatch。每条 item 必须包含 source_name、source_uri、
    title、summary、published_at（如可获得）、fetched_at、raw_text 或 content_ref、
    relevance_score 和 extraction_notes。
  agent: source_intelligence_collector
```

```yaml
extract_source_evidence_task:
  description: >
    从已采集的 raw items 中抽取可验证的大模型安全证据。
    重点识别攻击描述、受影响组件、漏洞利用条件、缓解建议、发布日期、
    原始引用和不确定信息。不得把摘要性推断当作事实证据。
  expected_output: >
    一个 EvidenceExtractionBatch。每条 evidence 必须包含 item_id、source_uri、
    evidence_text、evidence_type、confidence、supports_claims 和 uncertainty_notes。
  agent: source_intelligence_collector
```

```yaml
propose_new_sources_task:
  description: >
    识别搜索过程中发现的潜在高价值新情报来源。
    现阶段不得从这些来源正式采集，只能生成待审批提案。
    评估每个来源为什么可能提升覆盖、覆盖哪些安全主题、
    是否可信，以及是否存在噪声、合规或安全风险。
  expected_output: >
    一个 SourceProposal 列表。每条记录必须包含 source_name、base_uri、
    source_type、expected_coverage_gain、trust_rationale、risk_notes，
    且 approval_status 必须为 pending。
  agent: source_intelligence_collector
```

### 4.3 反思任务

```yaml
assess_collection_yield_task:
  description: >
    评估最近一轮采集质量。
    衡量新颖度收益、重复率、来源多样性、噪声率、证据质量、
    taxonomy 覆盖改进情况，并识别低产出来源和低效 query 模式。
  expected_output: >
    一个 CollectionYieldAssessment，包含 per-source metrics、low_yield_sources、
    high_noise_queries、useful_queries、novelty_summary 和 recommended_adjustments。
  agent: reflection_coverage_critic
```

```yaml
rewrite_search_strategy_task:
  description: >
    基于采集收益和覆盖缺口重写搜索策略。
    为尚未充分覆盖的大模型安全主题生成有针对性的 query 变体。
    优先使用来源特定语法，避免重复已经证明低效或高噪声的 query 模式。
  expected_output: >
    一个 SearchReflectionDecision，包含 rewritten_queries、source_priority_changes、
    topics_to_expand、topics_to_stop、rationale 和 confidence。
  agent: autonomous_planner
```

### 4.4 情报处理任务

```yaml
standardize_raw_intel_task:
  description: >
    将原始情报条目标准化为结构化的大模型安全情报。
    抽取攻击名称、攻击家族、OWASP LLM taxonomy、受影响模型或组件、
    CVE 引用、证据片段、严重性线索和置信度信号。
    只能使用已提供的证据和来源元数据，不得编造事实。
  expected_output: >
    一个 StandardizedIntelBatch。每条记录必须包含 canonical_name、
    attack_family、taxonomy_items、affected_components、evidence_spans、
    source_refs、confidence_by_field、conflict_flags 和 extraction_rationale。
  agent: intel_standardizer
```

```yaml
extract_taxonomy_and_evidence_task:
  description: >
    针对已标准化情报进一步提取 taxonomy 分类依据和证据链。
    判断每条情报与 OWASP LLM、MITRE ATT&CK、AI supply chain 或自定义大模型安全分类的关系。
    对每个分类结论必须给出支撑证据和置信度。
  expected_output: >
    一个 TaxonomyEvidenceBatch，包含 item_id、taxonomy_items、supporting_evidence、
    confidence、alternative_taxonomies、classification_rationale 和 unresolved_questions。
  agent: intel_standardizer
```

```yaml
dedup_and_merge_task:
  description: >
    将标准化情报记录与数据库加载的稳定攻击上下文进行比较。
    判断每条 item 应该创建新记录、合并到已有记录、更新已有记录，
    还是进入复核队列。
    决策时必须考虑语义相似度、taxonomy 重叠、CVE 重叠、
    受影响组件重叠以及证据质量。
  expected_output: >
    一个 DedupDecisionBatch。每个 decision 必须包含 item_id、action、
    target_record_id（如适用）、confidence、rationale、conflict_reasons
    和 review_required。
  agent: dedup_bom_graph_analyst
```

```yaml
map_ai_bom_task:
  description: >
    使用提供的 component context，将受影响的模型、框架、库、工具、
    插件、数据集和服务映射为标准 AI BOM components。
    对存在歧义或证据不足的映射必须标记为待复核。
  expected_output: >
    一个 BomResolutionBatch，包含 item_id、mentioned_component、
    normalized_component、component_type、match_confidence、match_rationale、
    review_status 和 alternatives。
  agent: dedup_bom_graph_analyst
```

```yaml
build_stix_graph_task:
  description: >
    基于标准化情报、去重决策和 BOM 映射结果构建 STIX-like 图谱对象与关系。
    必须保留 source references 和 evidence traceability，确保每个对象和关系都可追溯。
  expected_output: >
    一个 StixGraphBundle，包含 objects、relationships、external_references、
    confidence、validation_warnings 和 publication_recommendation。
  agent: dedup_bom_graph_analyst
```

```yaml
score_confidence_novelty_task:
  description: >
    对处理后的情报计算综合置信度、新颖度和优先级。
    评分时必须考虑来源可信度、证据强度、跨来源印证、去重结果、
    BOM 解析置信度、覆盖缺口贡献和潜在影响范围。
  expected_output: >
    一个 ScoredIntelBatch。每条记录必须包含 item_id、confidence_score、
    novelty_score、impact_score、priority、score_breakdown 和 recommended_handling。
  agent: dedup_bom_graph_analyst
```

### 4.5 覆盖与告警任务

```yaml
analyze_coverage_gaps_task:
  description: >
    分析当前情报在大模型安全 taxonomy、受影响组件家族、来源类型、
    厂商、模型和攻击阶段上的覆盖情况。
    识别高价值覆盖缺口，并估算继续采集的预期 ROI。
  expected_output: >
    一个 CoverageGapAnalysis，包含 gap_id、dimension、taxonomy_or_component、
    current_coverage、target_coverage、estimated_gap_fill_roi、
    recommended_queries、recommended_sources 和 priority。
  agent: reflection_coverage_critic
```

```yaml
evaluate_search_completeness_task:
  description: >
    判断当前搜索是否已经足够全面，是否还需要继续扩展 query、来源或主题。
    评估维度包括 taxonomy 覆盖、来源类型覆盖、模型/组件覆盖、连续新颖度收益、
    重复率、剩余预算和未解决的高价值缺口。
  expected_output: >
    一个 SearchCompletenessAssessment，包含 completeness_score、should_continue,
    missing_dimensions、diminishing_returns_evidence、recommended_next_mode 和 stop_rationale。
  agent: reflection_coverage_critic
```

```yaml
generate_alert_candidates_task:
  description: >
    从高置信、高影响或高新颖度情报中生成告警候选。
    必须包含证据引用，避免夸大风险，并区分已确认风险与弱信号。
  expected_output: >
    一个 AlertCandidateBatch，包含 title、severity、affected_components、
    summary、evidence_refs、confidence、recommended_action 和 publication_status。
  agent: alert_summarizer
```

```yaml
finalize_intel_run_task:
  description: >
    汇总本轮情报运行结果，生成可审计的运行总结。
    总结必须覆盖采集范围、关键发现、覆盖缺口、反思调整、数据库写入状态、
    新来源提案、告警候选、失败项和下一轮建议。
  expected_output: >
    一个 IntelRunSummary，包含 run_status、key_findings、coverage_summary、
    source_summary、reflection_summary、db_audit_summary、alert_summary、
    unresolved_items 和 recommended_followups。
  agent: alert_summarizer
```

### 4.6 数据库任务

数据库任务不直接执行自由 SQL。Agent 只产出查询意图、上下文请求或写入规划，执行由确定性 service 完成。

```yaml
load_db_context_task:
  description: >
    为下一步情报行动准备数据库上下文。
    只能请求已批准的只读上下文，包括 source registry、source quality rows、
    coverage snapshot、recent attacks summary、query feedback memory、
    stable attack candidates、component catalog 和 pending review queues。
    不允许修改数据库。
  expected_output: >
    一个 DbContextRequest 或 DbContextSummary，列出 requested context slices、
    filters、time windows、每个 slice 的请求原因，以及 missing_context 字段。
  agent: persistence_planner
```

```yaml
prepare_persistence_bundle_task:
  description: >
    将已处理的情报输出转换为幂等的数据库持久化写入包。
    不允许执行数据库写入，只能使用已批准的 operation groups。
    必须校验必填字段、依赖引用、幂等键和审计说明。
  expected_output: >
    一个 PersistenceBundle，包含 operation_groups、records、idempotency_keys、
    dependency_refs、validation_status、review_queue_entries、
    dead_letter_records 和 audit_notes。
  agent: persistence_planner
```

```yaml
verify_persistence_integrity_task:
  description: >
    审阅数据库写入结果，验证预期的 PersistenceBundle 是否被正确应用。
    识别缺失记录、重复写入、未解析引用、失败的 operation groups，
    并给出是否可重试以及如何重试的建议。
  expected_output: >
    一个 DbIntegrityReport，包含 applied_counts、failed_counts、
    duplicate_warnings、missing_dependencies、retryable_failures、
    non_retryable_failures 和 audit_summary。
  agent: persistence_planner
```

```yaml
summarize_db_audit_task:
  description: >
    汇总本轮数据库读写审计结果，为最终运行总结提供数据库侧结论。
    需要说明哪些上下文被读取、哪些写入包被执行、哪些 operation 成功或失败、
    是否存在重复写入、未解析依赖、dead-letter 记录或需要人工处理的队列项。
  expected_output: >
    一个 DbAuditSummary，包含 read_context_summary、write_operation_summary、
    integrity_status、failed_operations、dead_letter_summary、review_queue_summary
    和 recommended_remediation。
  agent: persistence_planner
```

## 5. 数据契约

第一版 Pydantic 模型按领域拆分到 `src/sufe_saads_crewai/schemas/`，并作为 CrewAI
`output_pydantic` 或 Agent `response_format` 使用。模型不复用旧项目代码。

模型基类使用宽松兼容策略：

```python
class FlexibleModel(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
```

这意味着 Agent 额外返回的字段不会直接导致失败，但核心字段仍通过类型、枚举和分数字段范围进行校验。

### 5.1 文件组织

| 文件 | 主要职责 |
|---|---|
| `common.py` | 通用基类、枚举、分数范围、证据引用、错误记录 |
| `runtime.py` | 运行预算、运行指标、`IntelRunBlackboard` |
| `actions.py` | Planner action、搜索计划、gap-fill 计划 |
| `sources.py` | 来源、原始情报、证据抽取、query history |
| `intel.py` | 标准化情报、去重、BOM、STIX、评分 |
| `coverage.py` | 采集收益、搜索反思、覆盖缺口、完整性评估 |
| `persistence.py` | DB context、领域写入 bundle、写入结果、审计 |
| `alerts.py` | 告警候选和最终运行总结 |
| `__init__.py` | 统一导出 public models |

### 5.2 核心模型清单

- Runtime: `RunBudget`, `RunMetrics`, `IntelRunBlackboard`
- Actions: `ActionDecision`, `ActionDecisionBatch`, `SearchQueryPlan`, `GapFillPlan`
- Sources: `ApprovedSource`, `SourceProposal`, `RawIntelItem`, `RawIntelItemBatch`, `EvidenceExtraction`, `EvidenceExtractionBatch`, `QueryHistoryEntry`
- Intel: `TaxonomyItem`, `AffectedComponent`, `StandardizedIntelRecord`, `StandardizedIntelBatch`, `TaxonomyEvidenceBatch`, `DedupDecision`, `DedupDecisionBatch`, `BomResolution`, `BomResolutionBatch`, `StixGraphBundle`, `ScoredIntelBatch`
- Coverage: `CollectionYieldAssessment`, `SearchReflectionDecision`, `CoverageGap`, `CoverageGapAnalysis`, `SearchCompletenessAssessment`
- Persistence: `DbContextRequest`, `DbContextSummary`, `PersistenceOperation`, `PersistenceBundle`, `DbWriteResult`, `DbIntegrityReport`, `DbAuditSummary`
- Alerts: `AlertCandidate`, `AlertCandidateBatch`, `IntelRunSummary`

### 5.3 数据库写入契约

数据库写入采用领域级 `PersistenceBundle`，不暴露自由 SQL，也不要求 Agent 指定底层表名。

允许的第一版 operation group：

- `upsert_raw_intel`
- `upsert_stable_attack`
- `insert_evidence`
- `upsert_bom_resolution`
- `insert_stix_bundle`
- `insert_alert_candidate`
- `append_query_feedback`
- `append_run_audit`

每个 `PersistenceOperation` 必须包含：

- `operation_group`
- `idempotency_key`
- `records`
- `dependency_refs`
- `validation_status`
- `audit_notes`

## 6. Guardrails

### 6.1 搜索与来源

- 未批准来源不得执行采集，只能生成 `SourceProposal`。
- 每条 raw item 必须有 `source_name` 和 `source_uri`。
- 低相关结果必须标记，不得进入高置信情报。

### 6.2 标准化

- 没有证据片段不得生成确定性攻击分类。
- taxonomy、CVE、BOM mention 都必须能回溯到 source refs。
- 不确定字段必须显式标记为 unknown 或 low confidence。

### 6.3 去重与合并

- `merge` 必须有 `target_record_id`。
- 低置信或冲突决策必须进入 review。
- 不允许只凭标题相似做高置信合并。

### 6.4 数据库

- Agent 不生成自由 SQL。
- 所有写入必须通过白名单 operation group。
- 每个写入 operation 必须有 idempotency key。
- 写入前校验依赖引用，写入后执行完整性检查。

### 6.5 停止条件

默认停止条件：

- 达到最大轮次、时间、token 或 API 调用预算。
- 连续 2 轮新颖度低于 5%，且重复率持续升高。
- 没有 `estimated_gap_fill_roi >= 0.65` 的高价值缺口。
- 核心覆盖分数达到目标阈值，默认 0.85。

## 7. 迁移实施步骤

### Phase 1: 契约与骨架

- 定义新的 Pydantic 数据契约。
- 定义 `IntelRunBlackboard` 和 `ActionCatalog`。
- 定义预算、停止条件、source approval 状态。
- 不接旧代码，不实现真实数据库写入。

### Phase 2: 自适应搜索闭环

- 实现 `autonomous_planner`、`source_intelligence_collector`、`reflection_coverage_critic`。
- 跑通搜索、采集、评估、反思、重写 query、继续或停止。
- 使用 mock source tools 和 mock blackboard 验证自主循环。

### Phase 3: 数据库交互边界

- 实现只读 DB context tools。
- 实现 `PersistenceBundle` 生成和校验。
- 实现确定性 DB commit service。
- 验证幂等、事务回滚和写入审计。

### Phase 4: 情报处理链路

- 实现标准化、去重合并、AI BOM 映射、STIX 图谱、置信度评分。
- 所有任务使用结构化输出。
- 引入 review queue 和 dead-letter 机制。

### Phase 5: 覆盖优化与告警

- 实现覆盖缺口分析和 gap-fill 策略。
- 实现告警候选生成和运行总结。
- 将 source proposal、coverage gap、alert candidate 纳入数据库写入规划。

### Phase 6: 评估与优化

- 加入 query feedback memory。
- 加入 source quality scoring。
- 加入成本、token、来源覆盖和分类覆盖指标。
- 根据端到端运行结果调整 agent prompts、guardrails 和停止阈值。

## 8. 测试方案

### 单元测试

- Pydantic schema 校验。
- ActionCatalog 白名单校验。
- Stop criteria 校验。
- PersistenceBundle 幂等键和依赖引用校验。
- Guardrail 函数测试。

### 集成测试

- mock search tools 下，低产出触发 query rewrite。
- 高噪声来源被降权。
- 发现新来源时只生成 pending proposal。
- 标准化结果必须有 evidence spans。
- DB bundle 重复执行不产生重复记录。

### 端到端场景

- 输入主题：`LLM prompt injection and agent tool abuse`。
- 系统至少完成 2 轮搜索和 1 次反思。
- 输出标准化情报、覆盖缺口、source proposal、告警候选和运行总结。
- 验证停止原因是预算、收益收敛或覆盖达标之一。

## 9. 验收标准

- 系统不依赖旧项目代码。
- Agent 不被固定状态图决定业务路径。
- Planner 能从 action catalog 中动态选择下一步。
- 系统能根据低召回、高噪声或覆盖缺口自主调整搜索方案。
- 数据库写入由 Agent 规划、service 执行、审计任务复核。
- 所有关键任务输出结构化模型，避免自然语言作为下游接口。
- 最终能生成覆盖尽可能全面的大模型安全情报摘要和告警候选。
