# LLM Security Intel Pipeline

松耦合流水线：**intel_agent**（采集）→ 持久化（JSON / MongoDB）→ **ctinexus_kg**（item 级 KG）→ **Gradio console**（编排 + 实时 verbose + 数据库面板）。

```text
backend/intel_agent/     # Claude Agent SDK 采集（0 依赖 ctinexus_kg）
backend/ctinexus_kg/     # CTINexus 构图（0 依赖 intel_agent）
backend/console/         # Gradio：采集 / 轨迹 / KG / Database
```

## 快速开始

```bash
uv sync --group agentsdk --group intelagent --group ctinexuskg --group web --group dev
# 配置 .env：DEEPSEEK_* 或 GLM_*、可选 INTEL_MONGO_URI、CTINEXUS_*

uv run intel-agent full --verbose
uv run web                          # http://0.0.0.0:8000

# Docker（web + mongo）
docker compose up -d --build mongo web
```

Gradio 页签：**Collect** · **Trace replay** · **Knowledge Graphs**（从库中情报构图，模型取 `.env` 的 glm-4.7 / embedding-3，子图写入 Mongo `knowledge_graphs`）· **Database**（runs/items/KG 记录 + CSV）· **Memory**（playbook + relevance cache）。

## 测试与冒烟

```bash
uv run pytest backend/intel_agent/tests backend/ctinexus_kg/tests backend/console/tests -q
uv run python scripts/smoke_pipeline.py
```

## MongoDB 读写与导出

宿主机连接：`localhost:27017`，库名 `intel_agent`，无鉴权。容器内互连：`mongodb://mongo:27017`。

```bash
# 交互查询（在宿主机 PowerShell / bash，不要在 mongosh 提示符里跑 docker）
docker exec -it sufe_saads_crewai-mongo-1 mongosh intel_agent

# 全量导出 CSV（在宿主机执行）
mkdir -p data/exports   # PowerShell: New-Item -ItemType Directory -Force data\exports
docker exec sufe_saads_crewai-mongo-1 mongoexport \
  --db=intel_agent --collection=items --type=csv \
  --fields=_id,item_id,source_name,title,summary,relevance_score,topics,published_at,source_uri,first_seen_at,last_seen_at,first_run_id,last_run_id,run_ids \
  > data/exports/items_all.csv
```

也可在 Gradio **Database** 页按条件查询并下载 CSV（写入 `data/exports/`）。

## Docker 注意：`IS_SANDBOX`

统一镜像以 root 运行时，Claude Code 会拒绝 `bypassPermissions`。compose / Dockerfile 已设 `IS_SANDBOX=1`；改代码后需 `docker compose up -d --build web`。

## 验收门控

详见 `docs/SESSION_2026-07-10_intel_agent_maturity.md`：

- `rg sufe_saads_crewai backend/ctinexus_kg` → 0
- `rg ctinexus_kg backend/intel_agent` → 0（文档除外）
- KG 失败不回滚采集 `raw_items`
- Gradio Collect 实时 TraceSink；Database 可读 Mongo / JSON

更多：`backend/intel_agent/README.md`、`backend/ctinexus_kg/README.md`、`backend/console/README.md`。
