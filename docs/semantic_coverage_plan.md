# 覆盖判断语义能力提升方案

## 目标

当前情报循环已经能按固定主题统计覆盖，但如果证据没有直接写出标准主题名，容易漏判。例如“corpus poisoning”应当补足 `rag poisoning`，“pickle deserialization in model weights”应当补足 `model supply chain`。本方案把覆盖判断从“标准关键词命中”升级为“语义证据评分”。

## 设计

1. **主题语义画像**：为每个目标主题维护 aliases、attack indicators、evidence types，覆盖标准名、常见论文术语、漏洞库描述词和厂商公告用语。
2. **语义匹配评分**：标准别名命中、行为指标命中、显式 metadata topic、item relevance 共同形成 0-1 覆盖分数。
3. **部分覆盖缺口**：缺口不再只有 0/1。低于 0.65 的主题仍保留为 gap，并记录 current_coverage、semantic_terms、source_hints，帮助下一轮补采。
4. **来源适配查询**：每个 gap 携带 NVD、OSV、arXiv、CISA KEV 的 source-specific term hints，避免把同一个宽泛 query 扔给所有来源。
5. **负面噪声控制**：语义扩展任务明确要求输出 negative terms，降低普通 AI 新闻、泛泛产品讨论和无证据内容的噪声。

## 运行时效果

- `detect_topic_matches()` 返回主题、分数、命中别名、命中行为指标和证据类型。
- `topic_coverage_scores()` 汇总所有 raw item 的语义覆盖分数。
- `ReflectionCoverageCriticRuntime.analyze_coverage_gaps()` 使用分数生成 gap、ROI 和 source hints。
- CrewAI task prompt 要求 LLM 审计员按同一套语义标准解释覆盖判断。

## 后续可扩展

- 将 `TOPIC_SEMANTIC_PROFILES` 外置为 YAML，支持非代码化更新。
- 接入 embedding/reranker，对相似但无显式别名的证据做二阶段召回。
- 为每个来源统计“语义误报类型”，自动生成 source-specific negative terms。
