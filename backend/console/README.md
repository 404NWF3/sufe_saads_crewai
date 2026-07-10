# backend/console — Gradio 统一控制台

编排 **intel_agent** 采集与 **ctinexus_kg** 构图，二者互不 import；本包是唯一同时依赖两侧的 UI 层。

## 页签

| Tab | 作用 |
|-----|------|
| **Collect** | `full` / `incremental` 采集；`TraceSink.on_event` 实时 verbose；Load latest（经 `default_store()`） |
| **Trace replay** | 回放 `data/intel_agent/traces/<run_id>.jsonl` |
| **Knowledge Graphs** | 从持久化情报生成 item KG（模型取自 `.env` 的 GLM/CTINEXUS，无 UI 选型）；结果写入 `knowledge_graphs` |
| **Database** | 浏览 **runs** / **items** / **KG records**；CSV → `data/exports/` |
| **Memory** | 浏览 **playbook** 检索技巧与 **relevance_cache** embedding 记录；可下载 CSV |

## 启动

```bash
uv sync --group web --group intelagent --group ctinexuskg --group agentsdk
uv run web
# http://0.0.0.0:8000
```

Docker：

```bash
docker compose up -d --build mongo web
```

容器需 `IS_SANDBOX=1`（compose 已设），否则 Claude Code 在 root 下拒绝 agentic loop，会退化为 rules fallback。

## 模块

```
backend/console/
├── app.py              # Gradio Blocks
├── db_browser.py       # Database 面板：查询 + CSV
├── kg_panel.py         # Knowledge Graphs：DB 条目 + env 配置 + 落库
├── memory_browser.py   # Memory 面板：playbook + relevance_cache
└── tests/
```

存储一律走 `intel_agent.store.default_store()`（Mongo 优先，否则 JSON）。

## 测试

```bash
uv run pytest backend/console/tests -q
```
