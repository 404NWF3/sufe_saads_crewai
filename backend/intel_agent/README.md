# backend/intel_agent

以 **Claude Agent SDK** 为核心、loop-engineering + self-evolving 的 LLM 安全情报采集智能体。

本模块是**完全自包含**的：不 import 任何 `src/sufe_saads_crewai` 代码，自带 schema、源客户端、三层相关性过滤、持久化与自演化技巧库。老 `src/` 后端可随时删除而不影响本模块运行。

## 设计总览

```
backend/intel_agent/
├── schemas.py          # 自包含 Pydantic 模型（RawIntelItem / Blackboard / 决策输出…）
├── topics.py           # LLM 安全目标话题 + 文本工具
├── sources.py          # NVD / arXiv / CISA KEV / OSV 源客户端（含重试）
├── relevance.py        # 三层相关性过滤：rule → embedding → flash LLM
├── analysis.py         # 确定性分析层：合并/覆盖配额/停滞检测/fallback 组词
├── persistence.py      # JSON 存储：data/intel_runs/<run_id>.json + latest.json
├── mongo_store.py      # MongoDB 历史库：runs 集合 + 全局去重 items 集合（_id=item_id）
├── store.py            # 存储工厂：配置了 Mongo 走 Mongo，否则回退 JSON
├── observability.py    # --verbose 追踪：控制台 + data/intel_agent/traces/<run_id>.jsonl
├── runtime/            # SDK provider 解析、options 构建、tool-forcing 结构化决策
├── memory/             # 自演化技巧库 Playbook（upsert/衰减/召回/harvest）
├── tools/              # 轮内 @tool：源搜索 + recall/record + submit_round_summary
├── hooks.py            # 预算/去重的审计层（tool handler 才是权威控制面）
├── agent/              # 每轮一个 SDK 会话（agentic loop）+ 终止 critic
├── engine/             # 采集模式、轮次编排 controller、上下文 digest、rules fallback
├── cli.py              # intel-agent full / incremental / latest
└── tests/              # 离线单测（注入 fake runner/embedder，无需联网）
```

### 核心思路

- **agentic loop**：每轮由智能体在 SDK 原生 tool loop 里**自己调用**源工具（组合 NVD 的
  CWE/CVSS/时间窗、arXiv 字段与布尔、OSV 生态/包等高级算子），观察产出再决定下一步。
- **self-evolving**：高产出的算子组合被 harvest 成**自然语言技巧**写入 Playbook，下次运行前
  按语义相似度 + 历史收益召回注入上下文；持续不产出的技巧会衰减、废弃。
- **loop-engineering**：控制器负责预算、去重、相关性标注、覆盖配额与停滞检测；终止由
  critic（tool-forcing 决策）判断边际收益，并叠加 max_rounds/stall/coverage 安全阀。
- **三层 fallback**：SDK 不可用 → 确定性 rules 轮次；结构化决策失败 → 规则兜底；相关性
  在线过滤失败 → 退回规则分。KG/情报主流程互不阻断。

## 两种采集模式

- **full（全量）**：覆盖全部目标话题，尽量多收 LLM 安全情报、尽量少纳入无关内容。
  ```bash
  uv run intel-agent full --max-rounds 6 --max-api-calls 40
  ```
- **incremental（增量）**：按话题 + 时间窗采集；下界默认取历史 watermark（既有运行的最新
  `published_at`），只追真正的新情报。
  ```bash
  uv run intel-agent incremental --focus "agent tool abuse" --window-days 1
  uv run intel-agent incremental --focus jailbreak --since 2026-07-01
  ```
- 查看最近一次结果：`uv run intel-agent latest`

## 运行前提

```bash
uv sync --group agentsdk --group intelagent   # claude-agent-sdk + pydantic + pymongo
```
在 `.env` 配置 Anthropic 兼容端点（DeepSeek 或 GLM Coding Plan），见根目录 `.env.example`
中 `INTEL_SDK_PROVIDER` / `DEEPSEEK_*` / `GLM_*` 与 `backend/intel_agent` 段的调参项。
未配置密钥时会自动降级为**确定性 rules 采集**，仍可产出结果。

## 测试

```bash
uv run pytest backend/intel_agent/tests -q
```
全部离线（注入 fake SDK runner / embedder），不联网、不需要密钥。

## 数据产物

- 运行结果：`data/intel_runs/<run_id>.json` + `latest.json`（未开 Mongo 时）。
- 技巧库：`data/intel_agent/playbook.jsonl`
- 相关性缓存：`data/intel_agent/relevance_cache.jsonl`
- verbose 追踪（`--verbose`）：`data/intel_agent/traces/<run_id>.jsonl`
- CSV 导出（Gradio Database / `mongoexport`）：`data/exports/`

## 历史库（MongoDB，可选）

把每次采集任务沉淀进数据库，并保证情报不重复：

```bash
docker compose up -d mongo                     # 起本地 MongoDB
# .env 里设置（见 .env.example）：
#   INTEL_MONGO_URI=mongodb://localhost:27017
#   INTEL_MONGO_DB=intel_agent
uv run intel-agent full --verbose              # 自动落库 MongoDB
uv run intel-agent latest                      # 从当前存储读取最近一次
```

- `runs` 集合：每次采集任务一份文档（完整 blackboard，item 的 `raw_text` 移到 items 里以控体积）。
- `items` 集合：**以 `item_id` 作 `_id` 的全局去重库**。同一情报无论被多少轮采到，都只存一份；重复出现 upsert 并把 run 追加进 `run_ids`，刷新 `last_seen_at`。
- 查询 API（供 Gradio Database）：`list_run_summaries` / `query_items` / `distinct_sources` / `run_count`（JSON store 有对等实现）。
- 未配置 `INTEL_MONGO_*` 时回退 JSON，离线/测试零依赖。

### 连接与导出

| 场景 | 做法 |
|------|------|
| DBeaver / 插件 | Host `localhost`，Port `27017`，库 `intel_agent`，无鉴权（**不要**用 Host=`mongo`） |
| 容器内交互 | `docker exec -it sufe_saads_crewai-mongo-1 mongosh intel_agent` |
| 全量 CSV | 在**宿主机** PowerShell/bash 跑 `mongoexport`（见根 `README.md`）；**不要**在 `mongosh>` 提示符里贴 `docker` 命令 |
| UI | Gradio **Database** 页签：过滤查询 + 下载 CSV → `data/exports/` |

## Docker

### 统一控制台（推荐）

```bash
docker compose up -d --build mongo web    # Gradio :8000 + Mongo
```

统一镜像（`Dockerfile`）含 intel_agent + ctinexus_kg + Gradio + Node/`claude` CLI。compose 设置 `IS_SANDBOX=1`：Claude Code 禁止 root 下 `bypassPermissions`，无此变量会 `ProcessError` 并退化 rules fallback。

### 批处理采集（profile）

```bash
docker compose up -d mongo
docker compose run --rm intel-agent full --verbose
docker compose run --rm intel-agent incremental --focus jailbreak --window-days 7
```

- 容器内 Mongo URI 由 compose 覆盖为 `mongodb://mongo:27017`；宿主机 `uv run` 用 `.env` 的 `localhost`。
- `intel-agent` 挂 `profiles: ["intel"]`，普通 `up` 不会启动它。

## 与 ctinexus_kg / Gradio 的边界

- **禁止**本包 import `ctinexus_kg`；构图由 `backend/console` 在采集结束后调用。
- `TraceSink.on_event` 供 Gradio 实时订阅；CLI `--verbose` 行为不变。
- UI：`uv run web`（`backend/console`）— Collect / Trace / KG / Database。

## 文档

- 本 README · `backend/ctinexus_kg/README.md` · `backend/console/README.md`
- 会话纪要：`docs/SESSION_2026-07-10_intel_agent_maturity.md`
- 进展：`docs/PROJECT_PROGRESS.md`
