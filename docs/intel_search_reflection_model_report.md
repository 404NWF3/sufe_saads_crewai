# 当前项目情报搜索与反思决策过程建模报告

报告日期：2026-05-13  
项目路径：`e:/sufe_saads_crewai`  
分析对象：`sufe_saads_crewai` 当前 CrewAI 情报搜索项目  
依赖版本：`crewai[tools]==1.14.4`

## 1. 执行摘要

当前项目实现的是一个面向大模型安全情报的自适应搜索与反思决策系统。它不是单轮搜索脚本，也不是简单的顺序 Crew，而是一个以 `IntelRunBlackboard` 为中心的闭环控制系统：系统持续选择查询、拆分来源策略、采集结构化情报、评估收益、识别覆盖缺口、扩展语义、重写查询，并在预算、覆盖率、边际收益和重复率约束下决定继续或停止。

从系统工程角度看，该项目可被描述为一个有限预算下的序贯情报控制问题：

$$
\begin{aligned}
\max \quad & \sum_t U(S_t,a_t,x_t)-\lambda\cdot\mathrm{Cost}_t \\
\text{s.t.}\quad & a_t\in\mathrm{ActionCatalog} \\
& \mathrm{source}_t\in\mathrm{ApprovedSources} \\
& \mathrm{output}_t\in\mathrm{PydanticSchemas} \\
& \mathrm{budget}_t\le\mathrm{BudgetMax}
\end{aligned}
$$

其中，`S_t` 是第 `t` 轮黑板状态，`a_t` 是计划动作，`x_t` 是采集到的情报证据，`U` 是由覆盖增益、新颖度、证据质量、来源可信度和重复惩罚共同构成的效用函数。

最近一次真实运行 `data/intel_runs/real-a3b17f1b.json` 的画像如下：

| 指标 | 数值 |
|---|---:|
| 运行状态 | succeeded |
| 采集轮数 | 50 |
| 原始情报条目 | 851 |
| 动作记录数 | 201 |
| 反思记录数 | 50 |
| 停止原因 | Round hard limit reached |
| 剩余覆盖缺口 | `agent tool abuse`, `rag poisoning` |

这说明系统已经具备持续反思能力，但最近一次运行不是因为覆盖完全或边际收益自然收敛而停止，而是因为达到了轮数硬上限。

## 2. 代码证据与核心模块

本报告基于以下项目文件：

| 模块 | 路径 | 职责 |
|---|---|---|
| 真实情报闭环控制器 | `src/sufe_saads_crewai/intel/real_loop.py` | 搜索、采集、评估、反思、停止的主控制逻辑 |
| 确定性 mock 闭环 | `src/sufe_saads_crewai/intel/adaptive_loop.py` | 用 mock 源验证自主循环 |
| CrewAI 定义 | `src/sufe_saads_crewai/crew.py` | planner、collector、critic 三类 Agent 与 Task |
| 运行入口 | `src/sufe_saads_crewai/main.py` | 配置 GLM 运行时并启动真实情报循环 |
| 动作与查询 schema | `src/sufe_saads_crewai/schemas/actions.py` | `ActionDecision`, `SearchQueryPlan` |
| 来源与原始情报 schema | `src/sufe_saads_crewai/schemas/sources.py` | `RawIntelItem`, `RawIntelItemBatch`, `QueryHistoryEntry` |
| 覆盖与反思 schema | `src/sufe_saads_crewai/schemas/coverage.py` | `CollectionYieldAssessment`, `CoverageGapAnalysis`, `SearchReflectionDecision` |
| 黑板与预算 schema | `src/sufe_saads_crewai/schemas/runtime.py` | `IntelRunBlackboard`, `RunBudget`, `RunMetrics` |
| 真实来源工具 | `src/sufe_saads_crewai/tools/registered_source_tools.py` | NVD、arXiv、CISA KEV、OSV.dev API |
| 主题检测 | `src/sufe_saads_crewai/topic_utils.py` | 目标安全主题与关键词检测 |

系统的主要运行入口是 `RealIntelRunController.run()`。`SufeSaadsCrewai` 定义了三个核心 Agent：

| Agent | 模型角色 | 主要职能 |
|---|---|---|
| `autonomous_planner` | 自主行动规划师 | 选择下一步动作、扩展语义、重写查询 |
| `source_intelligence_collector` | 多源情报采集员 | 通过已批准来源采集结构化情报 |
| `reflection_coverage_critic` | 搜索反思与覆盖审计员 | 评估收益、覆盖缺口和完整性 |

需要注意的是，真实运行控制器具有确定性兜底路径。Planner 和 Critic 可以通过 `Agent.kickoff()` 参与结构化决策，但如果 LLM 输出失败或环境开关未启用，系统会退回到代码内置策略。Collector Agent 也不是默认唯一采集路径，真实来源采集通常可由 `RegisteredApiSourceSearchTool` 直接执行。

## 3. 总体闭环机制

每一轮真实情报循环可抽象为以下管线：

The control loop can be summarized as $S_t\rightarrow q_t\rightarrow A_t\rightarrow X_t\rightarrow C_t\rightarrow Y_t\rightarrow W_{t+1}\rightarrow G_{t+1}\rightarrow E_t\rightarrow R_t\rightarrow Q_{t+1}$: select frontier query, select actions, decompose source-specific specs, collect, merge, assess yield, update source scores, analyze gaps, expand semantics, rewrite strategy, evaluate completeness, and update the next query frontier.

形式化表示为：

$$
S_{t+1}=F(S_t,q_t,A_t,X_t,C_t,Y_t,G_t,E_t,R_t)
$$

其中：

$$
S_t=(B_t,Q_t,H_t,I_t,G_t,W_t,L_t,M_t)
$$

各变量含义如下：

| 符号 | 项目字段 | 含义 |
|---|---|---|
| `B_t` | `IntelRunBlackboard` | 全局运行黑板 |
| `Q_t` | `query_frontier` | 候选查询前沿 |
| `H_t` | `query_history` | 查询历史与收益指标 |
| `I_t` | `raw_items` | 已采集原始情报集合 |
| `G_t` | `coverage_gaps` | 当前覆盖缺口集合 |
| `W_t` | `source_scores` | 来源质量与优先级权重 |
| `L_t` | `source_low_yield_streaks` | 来源连续低收益次数 |
| `M_t` | `RunMetrics` | 运行成本、轮次、API 调用等指标 |

## 4. 查询前沿选择模型

系统维护一个查询前沿 `Q_t`，其中每个元素是 `SearchQueryPlan`：

$$
q=(\mathrm{query\_text},\mathrm{source\_names},\mathrm{target\_topics},\mathrm{query\_intent},\mathrm{max\_results},\mathrm{priority},\mathrm{round\_index},\mathrm{expected\_coverage\_gain})
$$

在每轮中，系统从尚未执行的查询中选择优先级最高者。源码中的排序准则可以表示为：

$$
q_t=\arg\max_{q\in Q_t\setminus D_t}\left(\operatorname{rank}(\mathrm{priority}_q),\mathrm{expected\_coverage\_gain}_q,-\mathrm{round\_index}_q\right)
$$

其中：

$$
\operatorname{rank}(\mathrm{low})=0,\quad\operatorname{rank}(\mathrm{medium})=1,\quad\operatorname{rank}(\mathrm{high})=2,\quad\operatorname{rank}(\mathrm{critical})=3
$$

`D_t` 是已经执行过的查询集合。系统通过标准化后的查询文本、来源集合、目标主题和查询意图生成 hash key，避免重复执行同一查询计划。

这个机制的意义是：

1. 优先处理高优先级和高覆盖收益查询。
2. 避免重复查询浪费预算。
3. 保留多个候选查询，使 Planner 和 Critic 可以共同影响下一轮搜索方向。

## 5. 多源情报搜索建模

### 5.1 来源集合

真实来源集合为：

$$
S=\{\mathrm{nvd\_cve\_api},\mathrm{arxiv\_api},\mathrm{cisa\_kev\_json},\mathrm{osv\_dev\_api}\}
$$

每个来源具有不同的信息结构和检索语义：

| 来源 | 类型 | 最适合检索的问题 |
|---|---|---|
| NVD CVE API | 漏洞库 | CVE、产品、CWE、CVSS、KEV 相关漏洞 |
| arXiv API | 论文库 | Prompt injection、jailbreak、RAG poisoning 等研究主题 |
| CISA KEV JSON | 已利用漏洞目录 | 已在野利用漏洞、厂商产品、CVE |
| OSV.dev API | 开源生态漏洞库 | PyPI、npm、GHSA、package、PURL |

### 5.2 主题空间

系统关注的大模型安全主题集合为：

$$
T=\{\text{prompt injection},\text{jailbreak},\text{agent tool abuse},\text{data leakage},\text{model supply chain},\text{rag poisoning}\}
$$

### 5.3 查询分解函数

系统不会把同一个自然语言 query 机械地发送给所有来源，而是通过来源语义函数生成不同的 `SourceQuerySpec`：

$$
\Phi_s(q_t,G_t,E_t)\rightarrow X_{t,s}
$$

其中：

$$
X_{t,s}=\{x_{t,s,1},x_{t,s,2},\ldots,x_{t,s,k}\}
$$

每个来源的策略可描述为：

$$
\begin{aligned}
X_{t,\mathrm{NVD}} &= \operatorname{keywordSearch}(\mathrm{term})\cup\operatorname{productCWE}(\mathrm{product},\mathrm{cwe})\cup\operatorname{hasKev}(\mathrm{product})\cup\operatorname{exactMatch}(\mathrm{phrase}) \\
X_{t,\mathrm{arXiv}} &= \left(\operatorname{all}(\mathrm{term}_1)\lor\cdots\lor\operatorname{all}(\mathrm{term}_k)\right)\land(\mathrm{cat}=\mathrm{cs.CR}\lor\mathrm{cat}=\mathrm{cs.AI}\lor\mathrm{cat}=\mathrm{cs.CL}) \\
X_{t,\mathrm{CISA}} &= \operatorname{keyword}(\mathrm{product/vendor/vulnerability\_type})\cup\operatorname{cve\_id}(\mathrm{cve}) \\
X_{t,\mathrm{OSV}} &= \operatorname{ecosystemPackage}(\mathrm{ecosystem},\mathrm{package})\cup\operatorname{purl}(\mathrm{purl})\cup\operatorname{vuln\_id}(\mathrm{GHSA/CVE/PYSEC/RUSTSEC})
\end{aligned}
$$

这种设计把通用安全目标映射为来源可理解的检索语言，是项目搜索质量的核心。

## 6. 来源预算与优先级模型

系统为每个来源维护动态权重：

$$
W_t=\{w_{t,s}\mid s\in S\}
$$

以及低收益连续次数：

$$
L_t=\{l_{t,s}\mid s\in S\}
$$

来源排序准则为：

$$
\operatorname{order}(s)=(w_{t,s},-l_{t,s},\mathrm{source\_name})
$$

即优先选择得分高、低收益连续次数少的来源。

对某一来源，假设可用查询数为 `a_s`，则允许执行的查询预算 `k_s` 为：

$$
k_s=\begin{cases}
a_s,&a_s\le1\\
1,&l_s\ge3\\
\max(1,\lfloor0.5a_s\rfloor),&w_s<0.75\lor l_s\ge2\\
\min(a_s,\lceil1.25a_s\rceil),&w_s\ge1.25\\
a_s,&\text{otherwise}
\end{cases}
$$

每条查询的最大结果数也会乘以预算系数：

$$
m_s=\begin{cases}
1.5,&w_s\ge1.25\land l_s=0\\
0.25,&l_s\ge3\\
0.5,&w_s<0.75\lor l_s\ge2\\
1.0,&\text{otherwise}
\end{cases}
$$

因此，每个 source query 的有效结果上限为：

$$
\mathrm{max\_results}'=\left\lceil\mathrm{max\_results}\cdot m_s\right\rceil
$$

这构成了一个简化的多臂老虎机式调度策略：高收益来源获得更高采样预算，连续低收益来源被压缩预算。

## 7. 采集结果合并与收益指标

每轮采集得到一个 `RawIntelItemBatch`：

$$
C_t=(\mathrm{items}_t,\mathrm{source\_stats}_t,\mathrm{query\_plan}_t,\mathrm{batch\_notes}_t)
$$

系统将其合并进黑板，并计算：

$$
\begin{aligned}
n_t&=|\mathrm{items}_t|\\
u_t&=|\mathrm{new\_items}_t|\\
d_t&=|\mathrm{duplicate\_items}_t|\\
r_t&=|\mathrm{low\_relevance\_items}_t|
\end{aligned}
$$

对应的收益指标为：

$$
\begin{aligned}
\mathrm{novelty}_t&=\frac{u_t}{n_t}\\
\mathrm{duplicate}_t&=\frac{d_t}{n_t}\\
\mathrm{noise}_t&=\frac{r_t}{n_t}
\end{aligned}
$$

若 `n_t = 0`，上述指标按 0 处理。

这些指标被写入 `QueryHistoryEntry`，并成为后续反思、停止判断和来源打分的基础。

## 8. 来源分数更新模型

系统对每个来源计算证据质量：

$$
e_{t,s}=\operatorname{avg}_{i:\mathrm{source}(i)=s}\mathrm{relevance\_score}(i)
$$

然后以奖励和惩罚的形式更新来源分数：

$$
\begin{aligned}
\mathrm{reward}_{t,s}&=0.35\cdot\mathrm{novelty}_{t,s}+0.45\cdot\mathrm{evidence\_quality}_{t,s}\\
\mathrm{penalty}_{t,s}&=0.30\cdot\mathrm{result\_penalty}_{t,s}+0.30\cdot(1-\mathrm{evidence\_quality}_{t,s})+0.25\cdot\mathrm{duplicate}_{t,s}+0.15\cdot\mathrm{noise}_{t,s}\\
\Delta_{t,s}&=\operatorname{clip}(\mathrm{reward}_{t,s}-\mathrm{penalty}_{t,s},-0.35,0.35)\\
w_{t+1,s}&=\operatorname{clip}(w_{t,s}+\Delta_{t,s},0.1,2.0)
\end{aligned}
$$

其中：

$$
\mathrm{result\_penalty}=\begin{cases}
1.0,&\mathrm{result\_count}=0\\
0.4,&\mathrm{result\_count}<2\\
0.0,&\text{otherwise}
\end{cases}
$$

低收益连续次数更新规则为：

$$
l_{t+1,s}=\begin{cases}
l_{t,s}+1,&\mathrm{result\_count}=0\lor\mathrm{evidence\_quality}<0.4\lor\mathrm{duplicate\_ratio}\ge0.75\\
0,&\text{otherwise}
\end{cases}
$$

该机制使系统具备来源级别的自我调节能力。

## 9. 覆盖缺口分析模型

覆盖分析将已采集情报映射到目标主题空间 `T`：

$$
\mathrm{covered}_t=\{\tau\in T\mid\exists i\in I_t,\operatorname{detected}(\tau,i)\}
$$

整体覆盖分数为：

$$
\mathrm{coverage}_t=\frac{|\mathrm{covered}_t|}{|T|}
$$

未覆盖主题形成覆盖缺口：

$$
G_t=\{g_i\mid\tau_i\in T\setminus\mathrm{covered}_t\}
$$

每个缺口被建模为：

$$
g_i=(\mathrm{gap\_id}_i,\mathrm{dimension}_i,\mathrm{topic}_i,\mathrm{current\_coverage}_i,\mathrm{target\_coverage}_i,\mathrm{estimated\_gap\_fill\_roi}_i,\mathrm{priority}_i)
$$

高价值缺口集合为：

$$
G_{\mathrm{high}}(t)=\{g_i\in G_t\mid\mathrm{estimated\_gap\_fill\_roi}_i\ge\theta_{\mathrm{roi}}\lor\mathrm{priority}_i\in\{\mathrm{high},\mathrm{critical}\}\}
$$

默认阈值来自 `RunBudget`：

$$
\theta_{\mathrm{roi}}=0.55,\qquad\mathrm{target\_coverage\_score}=0.85
$$

## 10. 语义扩展模型

覆盖缺口不能直接等价于查询语句。系统通过语义扩展函数把缺口主题转译为不同来源的检索语言：

$$
E_t=\Psi(G_t,H_t,Y_t)
$$

对于每个缺口 `g_i` 和来源 `s`：

$$
\Psi(g_i,s)=(\mathrm{positive\_terms}_{i,s},\mathrm{negative\_terms}_{i,s},\mathrm{query\_templates}_{i,s},\mathrm{parameter\_hints}_{i,s})
$$

例如对 `agent tool abuse`：

- NVD: `code injection`, `command injection`, `arbitrary code execution`, `sandbox escape`, `LangChain`, `LlamaIndex`, `Jupyter`, `Ray`, `CWE-78`, `CWE-94`, `CWE-287`
- OSV: `langchain`, `llama-index`, `langflow`, `flowise`, `jupyter-server`, `ray`
- arXiv: `agentic AI security`, `tool-use agents`, `computer-use agents`, `indirect prompt injection`, `confused deputy`, `sandboxing LLM agents`
- CISA KEV: `code injection`, `command injection`, `remote code execution`, `authentication bypass`

这使系统能从“主题缺口”进入“来源特定搜索策略”，避免只做同义词扩展。

## 11. 反思决策模型

反思决策的输入为：

$$
R_{\mathrm{input}}(t)=(Y_t,G_t,H_t,W_t)
$$

输出为 `SearchReflectionDecision`：

$$
R_t=(\mathrm{rewritten\_queries}_t,\mathrm{source\_priority\_changes}_t,\mathrm{topics\_to\_expand}_t,\mathrm{topics\_to\_stop}_t,\mathrm{rationale}_t,\mathrm{confidence}_t)
$$

如果存在高价值缺口，则系统生成 gap-fill 查询：

$$
\mathrm{rewritten\_queries}_t=\begin{cases}
\operatorname{build\_gap\_query}(G_{\mathrm{high}}(t)),&|G_{\mathrm{high}}(t)|>0\\
\varnothing,&|G_{\mathrm{high}}(t)|=0
\end{cases}
$$

同时根据低收益来源生成优先级调整：

$$
\mathrm{source\_priority\_changes}_t=\{s\mapsto\mathrm{decrease}\mid s\in\mathrm{low\_yield\_sources}_t\}
$$

因此，反思不是单纯总结，而是直接改变下一轮搜索策略和来源预算的策略更新算子。

## 12. 下一轮查询前沿更新

系统将 Planner 改写查询与 Critic 推荐查询合并：

$$
\mathrm{Candidates}_t=\mathrm{rewritten\_queries}_t\cup\mathrm{critic\_recommended\_query}_t
$$

去重后按优先级排序。候选查询的优先级评分为：

$$
\operatorname{score}(q)=(\operatorname{not\_repeated}(q),\operatorname{critic\_recommended}(q)\land\operatorname{covers\_high\_roi\_gap}(q),\operatorname{count\_high\_roi\_gaps\_covered}(q),\operatorname{count\_all\_gaps\_covered}(q))
$$

因此，系统更偏好：

1. 未执行过的查询。
2. Critic 明确推荐且能覆盖高 ROI 缺口的查询。
3. 覆盖更多缺口的查询。

## 13. 停止条件模型

系统停止判断由策略规则和可选 Critic 结构化输出共同决定。核心规则可以写为：

$$
\mathrm{continue}_t=\mathrm{round\_ok}_t\land\mathrm{budget\_ok}_t\land\neg\mathrm{diminishing\_returns}_t\land(\mathrm{coverage}_t<\mathrm{target\_coverage\_score})\land(|G_{\mathrm{high}}(t)|>0)\land\neg\mathrm{persistent\_low\_yield}_t\land\mathrm{has\_next\_query}_t
$$

各条件定义如下：

- $\mathrm{round\_ok}_t: t+1<\mathrm{max\_rounds}$
- $\mathrm{budget\_ok}_t$: API/token/cost/time budget has not reached the warning ratio.
- $\mathrm{diminishing\_returns}_t$: in the latest $k$ rounds, $\mathrm{novelty}<\mathrm{min\_novelty\_delta}$ and $\mathrm{duplicate\_ratio}\ge\mathrm{max\_duplicate\_ratio}$.
- $\mathrm{persistent\_low\_yield}_t$: all sources are low-novelty, high-duplicate, or empty, and `query_history` length reaches `max_low_yield_rounds`.

默认参数：

$$
\mathrm{min\_novelty\_delta}=0.05,\quad\mathrm{max\_duplicate\_ratio}=0.6,\quad\mathrm{max\_low\_yield\_rounds}=2,\quad\mathrm{budget\_warning\_ratio}=0.9
$$

这是一种保守停止策略：只要仍有高价值缺口，且仍有下一轮查询，系统倾向于继续搜索，除非预算、覆盖、边际收益或低收益条件明确触发停止。

## 14. 实际运行数据解读

最近一次真实运行 `real-a3b17f1b` 的来源分布：

| 来源 | 条目数 |
|---|---:|
| NVD CVE API | 634 |
| CISA KEV JSON | 96 |
| OSV.dev API | 81 |
| arXiv API | 40 |

主题命中分布：

| 主题 | 命中数 |
|---|---:|
| prompt injection | 61 |
| jailbreak | 27 |
| model supply chain | 13 |
| data leakage | 5 |
| agent tool abuse | 0 |
| rag poisoning | 0 |

最终来源分数：

| 来源 | source_score | low_yield_streak |
|---|---:|---:|
| NVD CVE API | 1.4323 | 5 |
| arXiv API | 1.1663 | 3 |
| OSV.dev API | 0.8050 | 4 |
| CISA KEV JSON | 0.1000 | 17 |

运行结果说明：

1. NVD 是主导来源，占 634 条，说明漏洞库检索贡献最大。
2. CISA KEV 连续低收益次数达到 17，系统已将其分数压到下界 0.1。
3. OSV 和 arXiv 仍有价值，但在后期也出现连续低收益。
4. `agent tool abuse` 与 `rag poisoning` 仍被视为缺口，说明关键词型覆盖检测对语义变体的识别能力有限。
5. 最后停止原因为轮数上限，而非覆盖完成，说明系统在“高 ROI 缺口仍存在”的情况下倾向持续搜索。

后期部分轮次出现 `duplicate_ratio = 1.0`，这意味着新增查询已经大量返回重复信息。系统虽然记录了重复率并调整来源预算，但因为仍存在高价值缺口，最终继续运行到硬上限。

## 15. 系统优势

### 15.1 黑板状态可审计

`IntelRunBlackboard` 保留了查询历史、来源分数、覆盖缺口、反思记录和动作历史。每次运行都可以回溯：

$\mathrm{query}\rightarrow\mathrm{source\ specs}\rightarrow\mathrm{raw\ items}\rightarrow\mathrm{yield}\rightarrow\mathrm{gaps}\rightarrow\mathrm{reflection}\rightarrow\mathrm{next\ query}$

这对安全情报系统很重要，因为情报结论必须能解释来源和路径。

### 15.2 来源语义适配强

系统明确区分 NVD、arXiv、CISA KEV 和 OSV.dev 的检索方式。尤其是 NVD 不被当作通用语义搜索引擎，而是通过 CVE、产品、CWE、CVSS、KEV、exact match 等参数化方式使用。

### 15.3 反思结果进入控制回路

反思不是自然语言点评，而是结构化影响：

- rewrite query
- adjust source score
- expand terms
- stop topics
- continue or stop

这使系统具备真正的闭环自适应能力。

### 15.4 Schema 约束降低下游不确定性

关键输出均通过 Pydantic 模型约束，包括 `PlannerDecisionOutput`、`CollectionBatchOutput`、`CoverageAnalysisOutput`、`RewriteDecisionOutput`、`CompletenessDecisionOutput` 等。这比自由文本串联更适合做长期情报系统。

## 16. 主要风险与不足

### 16.1 覆盖检测仍偏关键词

当前 `detect_topics()` 依赖主题关键词匹配。例如 `agent tool abuse` 只检测：

`agent tool`, `tool abuse`, `plugin abuse`, `function calling`

如果结果中出现的是 `unsafe tool execution`、`MCP server compromise`、`confused deputy`、`computer-use agent attack`，系统可能已经采集到相关材料，却仍判断为未覆盖。

建议将覆盖函数从二元关键词命中升级为：

$$
\mathrm{coverage\_score}(\mathrm{topic},\mathrm{item})=\alpha\cdot\mathrm{keyword\_match}+\beta\cdot\mathrm{semantic\_similarity}+\gamma\cdot\mathrm{LLM\_taxonomy\_score}+\delta\cdot\mathrm{source\_metadata\_signal}
$$

### 16.2 低收益停止条件较保守

当前 `persistent_low_yield_t` 接近“所有来源均低收益”才触发。实际运行中，即使多个来源连续低收益，只要仍有部分来源没有满足严格低收益条件，系统仍可能继续运行。

可以增加边际覆盖收益停止项：

$$
\Delta\mathrm{coverage}_{t-k:t}=0\land\operatorname{avg\_duplicate}_{t-k:t}\ge0.8\land\mathrm{no\_new\_semantic\_route}\Longrightarrow\mathrm{STOP}
$$

### 16.3 Action history 未完全表达内部执行

真实运行的动作记录中有搜索、覆盖分析、语义扩展、反思和停止，但收益评估虽然实际执行，却不一定作为 `ASSESS_COLLECTION_YIELD` 明确出现在 action history 中。这会降低审计链条的完整性。

建议将每轮收益评估也作为显式 action 写入：

Proposed explicit action: `ASSESS_COLLECTION_YIELD`; input: `latest_batch`; output: `CollectionYieldAssessment`; metrics: `novelty`, `duplicate`, `noise`, `evidence_quality`.

### 16.4 配置文件存在中文编码展示风险

`agents.yaml` 和部分 `tasks.yaml` 的中文在当前终端输出中出现编码异常。虽然运行时仍可能正常读取，但这会影响协作、审计和 prompt 维护。

建议统一确认：

- `file encoding = UTF-8`
- `editor encoding = UTF-8`
- `terminal code page = UTF-8`

并对 Agent/Task 配置做一次无损重写或校验。

## 17. 建议的数学化改进方向

### 17.1 引入覆盖矩阵

当前覆盖主要是主题级集合。建议改为来源-主题覆盖矩阵：

$$
C_t\in\mathbb{R}^{|T|\times|S|},\qquad C_t[i,j]=\text{coverage score of topic }i\text{ from source }j
$$

整体覆盖可定义为：

$$
\mathrm{coverage}_i=1-\prod_j\left(1-C_t[i,j]\cdot\mathrm{trust}_j\right)
$$

这样可以区分“某主题由单一来源覆盖”和“某主题被多来源交叉验证”。

### 17.2 引入期望信息增益

下一轮查询不只按 priority 和 gap count 排序，也可以按期望信息增益：

$$
\mathrm{EIG}(q)=\mathbb{E}\left[H(G_t)-H(G_{t+1})\mid q\right]
$$

实际工程中可近似为：

$$
\mathrm{EIG}(q)=\sum_{g\in G_{\mathrm{high}}}P(q\ \mathrm{covers}\ g)\cdot\mathrm{ROI}(g)\cdot\left(1-\mathrm{current\_coverage}(g)\right)\cdot\mathrm{source\_reliability}(q)
$$

### 17.3 引入边际效用停止

每轮效用可定义为：

$$
U_t=\alpha\cdot\Delta\mathrm{coverage}_t+\beta\cdot\mathrm{novelty}_t+\gamma\cdot\mathrm{evidence\_quality}_t-\mu\cdot\mathrm{duplicate}_t-\nu\cdot\mathrm{noise}_t-\lambda\cdot\mathrm{cost}_t
$$

停止条件可以增加：

$$
\operatorname{avg}(U_{t-k:t})<\varepsilon\Longrightarrow\mathrm{STOP}
$$

这会比单纯轮数上限更符合情报搜索的经济性。

### 17.4 引入语义归因覆盖

对每条情报 `item`，让系统输出主题归因概率：

$$
p(\mathrm{topic}\mid\mathrm{item})\in[0,1]
$$

则某主题覆盖可定义为：

$$
\mathrm{coverage}(\mathrm{topic}_i)=1-\prod_{\mathrm{item}\in I_t}\left(1-p(\mathrm{topic}_i\mid\mathrm{item})\cdot\mathrm{relevance}(\mathrm{item})\right)
$$

这样可以避免关键词未命中导致的假缺口。

## 18. 结论

当前项目已经具备一个专业情报系统的核心形态：它有受控来源、结构化 schema、可审计黑板、动态来源评分、覆盖缺口分析、语义扩展和查询重写。其本质是一个有限预算下的自适应情报搜索控制系统。

从数学上看，该过程可概括为：

$$
S_{t+1}=F\left(S_t,\pi_{\mathrm{planner}}(S_t),\operatorname{collect}(\Phi(S_t)),\operatorname{critic}(S_t)\right)
$$

其中：

- $\pi_{\mathrm{planner}}$: chooses actions and queries from goals, gaps, budget, and historical yield.
- $\Phi$: translates general security topics into source-specific queries.
- $\operatorname{collect}$: executes approved-source collection and returns structured evidence.
- $\operatorname{critic}$: evaluates novelty, noise, duplication, coverage, and stop conditions.

最重要的下一步不是增加更多搜索轮数，而是提高覆盖判断的语义能力，并让停止准则更关注边际信息增益。这样系统才能从“能持续搜索”进一步升级为“知道何时继续、何时换策略、何时停止”的成熟情报决策系统。
