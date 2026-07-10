# backend/ctinexus_kg — self-contained item-level KG via CTINexus

采集（`intel_agent`）与构图（本模块）**零双向依赖**。采集落库后，由 `backend/console` 或脚本把
`run_id` + items 交给 `pipeline.generate_for_run` / `generate_for_item`。

## 用法

```python
from ctinexus_kg import KgGenerationConfig, generate_for_run, list_kg_ready

records = generate_for_run(run_id, items, config=KgGenerationConfig(), process_func=None)
# process_func=None → 调用已安装的 ctinexus.process_cti_report
# 单测可注入 fake process_func，不耗配额
```

产物：`data/intel_runs/<run_id>_kg/<item_id>.json` + `manifest.json`。

KG 失败只记 `failed` / manifest，**不回滚**采集侧 `raw_items`。

## 依赖

```bash
uv sync --group ctinexuskg
# 或统一控制台：
uv sync --group web
```

环境变量：`CTINEXUS_API_KEY` / `CTINEXUS_BASE_URL`（及可选 `CTINEXUS_MODEL` /
`CTINEXUS_EMBEDDING_MODEL`），回退 `GLM_*` → `OPENAI_*`。默认模型 **`glm-4.7`** /
**`embedding-3`**（`KgGenerationConfig.from_env()`）。Gradio 不展示模型选择器。

生成成功后，控制台会把子图 JSON upsert 到存储的 `knowledge_graphs`（Mongo 集合，或
`data/intel_agent/knowledge_graphs/`），并在 Database 页可浏览。

## 测试

```bash
uv run pytest backend/ctinexus_kg/tests -q
```

## 边界

- 禁止 import `intel_agent` / `sufe_saads_crewai`。
- 入参用结构兼容 DTO（`coerce_raw_item`），不共享可变状态。
