# 会话纪要：intel_agent 验证、可观测性与 MongoDB 落库（2026-07-10）

本文档记录本轮对话中的目标、交付物与遗留项，便于后续开发接续。对应代码均在 `backend/intel_agent/`。

---

## 1. 会话目标

本轮会话承接上一轮已实现的 `backend/intel_agent` 自包含引擎，重点从「代码写完」推进到「可运行、可观测、可沉淀」：

1. **修复并跑通离线单测**，确认分析层与 controller 集成正确。
2. **在真实环境跑通全量采集**（`intel-agent full`），理解 CLI 输出含义。
3. **补齐运行时可观测性**：能看清模型 loop、工具调用与 critic 决策。
4. **历史数据持久化**：每次 agent 检索任务写入数据库，情报全局去重。
5. **Docker 打包**：`intel_agent` + MongoDB 一键部署与运行。
6. **运维侧连接方式**：宿主机 / DBeaver 如何连 Docker 中的 MongoDB。

---

## 2. 已完成内容

### 2.1 测试修复与验证

| 项 | 说明 |
|---|---|
| `test_quota_open_gaps_and_coverage` 修复 | 根因：`make_item` 默认 `raw_text` 含 `"jailbreak"`，`detect_topics()` 误判覆盖度。为 fixture 增加 `summary`/`raw_text` 覆盖，coverage 测试使用话题干净文本。 |
| 单测通过 | 用户确认：`21 passed` → 加 `--verbose` 后 `24 passed`；加 Mongo 存储后预期 `29 passed`（含 `test_mongo_store.py`、`test_observability.py`）。 |

### 2.2 真实采集冒烟

用户成功执行：

```bash
uv run intel-agent full --max-rounds 4 --max-api-calls 20
```

典型结果（一次 bootstrap 运行）：

- `rounds: 2`（未跑满上限，因 API 预算用尽）
- `items collected: 255`
- `api calls used: 20`
- `open coverage gaps: ['agent tool abuse']`（6 话题中 5 个已达配额 `INTEL_COVERAGE_QUOTA=3`）

CLI 启动时的 `claude.ai connectors are disabled` 为 SDK 子进程信息性警告（使用 `ANTHROPIC_AUTH_TOKEN` 走 DeepSeek/GLM 端点时的预期行为），非错误。

### 2.3 `--verbose` 可观测性

新增 `backend/intel_agent/observability.py`（`TraceSink`），并接入 `agent/loop.py`、`engine/controller.py`、`cli.py`：

- **控制台**：每轮 `round_start`、模型 `assistant_text`/`thinking`、`tool_call`/`tool_result`、`session_end`、`round_summary`、`critic`。
- **落盘**：`data/intel_agent/traces/<run_id>.jsonl`（JSONL 事件流，可事后回放）。

用法：

```bash
uv run intel-agent full --verbose
uv run intel-agent incremental --focus jailbreak --window-days 7 -v
```

### 2.4 MongoDB 历史库与全局去重

| 文件 | 职责 |
|---|---|
| `mongo_store.py` | `MongoIntelRunStore`：`runs` + `items` 两集合；`build_run_document` / `build_item_update` 纯函数可单测。 |
| `store.py` | `default_store()`：`INTEL_MONGO_URI` 或 `INTEL_MONGO_ENABLED=1` 时用 Mongo，否则回退 `JsonIntelRunStore`。 |
| `engine/controller.py` / `cli.py` | 统一经 `default_store()` 读写，不再写死 JSON。 |

**数据模型**：

- **`runs`**：每次采集任务一份文档（完整 blackboard；`raw_text` 不重复存，控体积）。
- **`items`**：`_id = item_id`（`nvd:cve-...` / `arxiv:...` 等自然键），**物理级去重**；重复出现 upsert，`run_ids` 溯源数组追加，`last_seen_at` 刷新。

依赖：`pyproject.toml` → `intelagent` 组增加 `pymongo`；`dev` 组增加 `mongomock`（离线测跨轮去重）。

用户已在 `.env` 配置：

```ini
INTEL_MONGO_URI=mongodb://localhost:27017
INTEL_MONGO_DB=intel_agent
```

### 2.5 Docker 打包

| 文件 | 说明 |
|---|---|
| `Dockerfile.intel_agent` | Python 3.12 + Node + `@anthropic-ai/claude-code` CLI + 三依赖；只拷 `backend/intel_agent`；入口 `python -m intel_agent.cli`。 |
| `docker-compose.yml` | `mongo`（mongo:7，卷 `./data/mongo`）；`intel-agent`（`profiles: ["intel"]`，覆盖 `INTEL_MONGO_URI=mongodb://mongo:27017`，`depends_on: mongo healthy`）。 |
| `Dockerfile`（主） | 补 `COPY backend`（`pyproject` wheel packages 含 `intel_agent`，避免 hatchling 构建失败）。 |

常用命令：

```bash
docker compose up -d mongo
docker compose run --rm intel-agent full --verbose
docker compose run --rm intel-agent latest
```

### 2.6 文档与规范更新

- `backend/intel_agent/README.md`：Mongo 历史库、Docker、`--verbose` 章节。
- `.env.example`：`INTEL_MONGO_*` 注释说明。
- `.cursor/rules/intel_agent.mdc`：存储抽象、`mongomock` 测试约定。
- `CLAUDE.md` / `AGENTS.md`：intel_agent 目录结构、Mongo、verbose、Docker 入口（本轮再次对齐）。

### 2.7 Playbook 自演化（上一轮已有，本轮运行验证）

首次全量运行后 `data/intel_agent/playbook.jsonl` 已沉淀 7 条技巧（如 osv `langchain`、arxiv 布尔检索等），`reward`/`verified` 状态正常。

---

## 3. 如何查看本轮产物（速查）

| 想看什么 | 去哪里 |
|---|---|
| 最近一次采集摘要 | `uv run intel-agent latest` 或 Mongo `runs` 最新文档 |
| 全量 255 条情报与话题 | `data/intel_runs/<run_id>.json` → `blackboard.raw_items`，或 Mongo `items` |
| Agent loop / 工具调用 | 加 `--verbose` 或读 `data/intel_agent/traces/<run_id>.jsonl` |
| 沉淀的检索技巧 | `data/intel_agent/playbook.jsonl` |
| 全局去重情报库 | Mongo `intel_agent.items`（DBeaver：`localhost:27017`，库 `intel_agent`，无鉴权） |
| 每次任务完整黑板 | Mongo `intel_agent.runs` |

**连接 MongoDB（DBeaver）**：Host `localhost`，Port `27017`，Database `intel_agent`，Authentication `None`。容器内互连用 `mongodb://mongo:27017`。

---

## 4. 尚未完成 / 后续建议

### 4.1 文档与设计

- [ ] `docs/intel_agent_design.md`（详细架构设计稿，上一轮计划未写）
- [ ] `docs/INTEL_AGENT_SDK_ROADMAP.md` Phase 4 章节更新
- [ ] `docs/PROJECT_PROGRESS.md` 全面改写（仍停留在 2026-06-13 旧 CrewAI 主线描述）

### 4.2 工程与质量

- [ ] 用户本地确认 `29 passed`（Mongo 单测加入后；助手环境 pytest 偶发卡死）
- [ ] `agent-sdk-verifier-py` 运行时审查（静态已完成）
- [ ] `code-simplifier` 子 agent 跑一轮简化
- [ ] MongoDB **鉴权**（生产/外网暴露时建议加 `MONGO_INITDB_ROOT_*`）

### 4.3 功能集成

- [ ] **Gradio Web** 读路径仍指向 JSON `latest.json`，未接 Mongo `default_store()`——Web 上看不到仅落 Mongo 的运行
- [ ] `scripts/eval_ab.py`：新引擎 vs 旧 `sdk_loop` A/B
- [ ] incremental watermark 在 Mongo-only 模式下的 watermark 来源（当前 `load_all_blackboards` 已支持 Mongo，需端到端验证）
- [ ] 删除或归档 legacy `src/sufe_saads_crewai/intel/`（用户长期目标：后端只留 `backend/intel_agent`）

### 4.4 路线图（CLAUDE.md 方向一/二，未在本轮实现）

- [ ] 源选择 / 检索词 / 高级算子 / 轮次 **自主决策**深化（当前已有 agent loop + playbook，但预算撞线仍会早停）
- [ ] item 级 KG 与 base KG 融合
- [ ] Phase 5：Web 引擎切换、增量表单、playbook 人工审核面板

---

## 5. 本轮关键文件清单

```
backend/intel_agent/
├── observability.py          # 新增：TraceSink
├── mongo_store.py            # 新增：MongoIntelRunStore
├── store.py                  # 新增：default_store()
├── agent/loop.py             # verbose 事件 emit
├── engine/controller.py      # trace + default_store
├── cli.py                    # --verbose / -v
├── tests/test_observability.py
├── tests/test_mongo_store.py
└── tests/conftest.py         # make_item 文本覆盖
tests/test_analysis.py        # coverage 测试 fixture 修正

Dockerfile.intel_agent        # 新增
docker-compose.yml            # mongo + intel-agent 服务
.env.example                  # INTEL_MONGO_*
```

---

## 6. 建议的下一步（优先级）

1. `docker compose run --rm intel-agent full --verbose` 确认数据写入 Mongo `runs`/`items`。
2. `uv run pytest backend/intel_agent/tests -q` 确认 29 passed。
3. 用 DBeaver 浏览 `items` 按 `topics` / `source_name` 聚合，评估 `agent tool abuse` 缺口。
4. 若要以 Web 为主入口：改 `web/app.py` 使用 `intel_agent.store.default_store()`。
5. 补 `docs/intel_agent_design.md` 与更新 `PROJECT_PROGRESS.md`。
