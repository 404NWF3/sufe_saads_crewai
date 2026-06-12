# base_kg — LLM 安全 base KG 构建流水线（top-down）

本目录是**独立于 `sufe_saads_crewai` 包**的 base KG 构建模块，参考论文《Automated knowledge extraction from marine accident reports using large language models》（仓库根目录 PDF）的 top-down 方法论，在 `data/kg-source` 语料（约 470 篇中英文 PDF）上构建 LLM 安全领域基底知识图谱，存入 Neo4j。

后续（路线图第二步）再设计算法把采集流水线产出的 CTINexus item 级小 KG 融合进这张 base KG，本目录不涉及该部分。

## 流水线结构

```
PDF 语料 ──corpus──> corpus.jsonl（每篇文档一个 chunk，保持单案例上下文完整）
            │
            ├──extract──> 三阶段 LLM 抽取（每阶段独立 one-shot prompt）
            │               1. NER（schema 约束的实体+属性识别）
            │               2. 实体标准化（规范名、合并变体、枚举值归一）
            │               3. 关系抽取（SPO，程序化校验 domain/range/自环）
            │             → output/extractions/<doc_id>.json
            │
            ├──load─────> Neo4j（MERGE 入库，节点键 = 类型::规范名，幂等，带溯源）
            │
            └──evaluate─> 双视角质量评估 → output/evaluation.json
                            结构复杂度：实体冗余（embedding 聚类）、关系冗余、自环、度统计
                            语义准确性：子图重构原文 + 句级最大余弦相似度均值
```

## 文件说明

| 路径 | 说明 |
|---|---|
| `schema/llm_security_schema.json` | 机器可读 schema（5W1H，27 实体类型 / 30 关系），LLM prompt 与程序校验共用 |
| `prompts/*.txt` | NER / 实体标准化 / 关系抽取 / 文本重构四个 one-shot prompt 模板，占位符为 `[[NAME]]` |
| `pipeline/config.py` | 环境变量配置（`BASEKG_*` → `OPENAI_*` → `GLM_*` 回退） |
| `pipeline/corpus.py` | PDF → 单文档 chunk（pypdf，语言检测，字符上限 24k） |
| `pipeline/extract.py` | 三阶段抽取 + 三元组 schema 校验（非法三元组进 `dropped_triplets` 留作评估信号） |
| `pipeline/neo4j_store.py` | Neo4j 入库（关系/标签名白名单校验后注入 Cypher） |
| `pipeline/evaluate.py` | 论文式双视角评估 |
| `pipeline/run_pipeline.py` | CLI 入口 |

## 使用方法

### 1. 启动 Neo4j

```bash
docker compose up -d neo4j
```

浏览器控制台 `http://localhost:7474`，Bolt 端口 `7687`，默认账号 `neo4j / basekg-dev-2026`（可在 `.env` 中用 `NEO4J_USER` / `NEO4J_PASSWORD` 覆盖，**修改密码需先删除 `data/neo4j/` 卷再重建容器**）。

### 2. 配置环境变量

`.env` 中至少需要一个可用的 OpenAI-compatible LLM（参见 `.env.example` 的 `BASEKG_*` 段）。抽取与评估都需要 chat 模型；实体冗余评估与重构精度还需要 embedding 模型。

### 3. 分阶段运行（从仓库根目录）

```bash
uv sync --group basekg

# 阶段一：构建语料（纯本地，不调 LLM）
uv run python -m base_kg.pipeline.run_pipeline corpus            # 全量
uv run python -m base_kg.pipeline.run_pipeline corpus --limit 5  # 小样本

# 阶段二：LLM 三阶段抽取（每篇 3 次 chat 调用；已抽取的文档自动跳过）
uv run python -m base_kg.pipeline.run_pipeline extract --limit 5

# 阶段三：入库 Neo4j（幂等，可重复执行）
uv run python -m base_kg.pipeline.run_pipeline load

# 阶段四：质量评估（--skip-accuracy 跳过较贵的重构评估）
uv run python -m base_kg.pipeline.run_pipeline evaluate --skip-accuracy

# 或一键串联
uv run python -m base_kg.pipeline.run_pipeline all --limit 5
```

输出均在 `base_kg/output/`（已 gitignore）。

## Schema v0.2 相对 docx Table 1 的改进

原始设计见 `LLM_Security_KG_Schema_Table1.docx`。v0.2（`schema/llm_security_schema.json`）的主要修订：

1. **属性与实体类型分离**：docx 中 "Entity Types" 列实际混入了属性（如 `AttackerType`、`ModelID`），现规范为 27 个实体类型，属性挂在类型之下，含类型/枚举值/描述。
2. **命名统一**：实体类型 PascalCase 唯一规范名（如 `LLM System` → `LLMSystem`），消除关系表中 `IndirectPI`、`LLMService` 等别名引用。
3. **关系显式约束**：30 个关系全部声明 domain/range 与类别（static / dynamic / causal / temporal / spatial / structural / defensive / adversarial）。时间锚（`occursIn`、`during`）与空间锚（`injectedInto`）明确区分并写入抽取规则——论文指出这是 LLM 最易混淆的关系类型。
4. **类型收敛**：16 种攻击收敛为 `AttackTechnique.techniqueName` 枚举、11 种防御收敛为 `DefenseMechanism.defenseType` 枚举、6 类影响收敛为 `SecurityImpact.impactType` 枚举，缩小 LLM 的选择空间以提高抽取一致性；同时区分抽象技术类（AttackTechnique）与具体事件（AttackEvent），用 `usesTechnique` 关联。
5. **补缺**：docx 中 Victim 概念没有任何关系，新增 `affects`；新增 `Tool` 实体与 `invokes` / `hosts` / `constrains` 关系链。
6. **溯源内建**：全局 provenance 属性（`sourceDoc`、`sourceCategory`、`mentionText`），每个实体/三元组必须带支撑文本片段——这同时是反 hallucination 约束和后续 KG 融合的对齐依据。
7. **外部对齐**：`taxonomy_alignment` 把攻击技术映射到 OWASP LLM Top 10 2025 与 MITRE ATLAS ID。

Schema 迭代时改 JSON 即可，prompt 渲染（`schema_loader.py`）与三元组校验会自动跟随；改动实体类型/关系名后需注意 Neo4j 中历史标签不会自动迁移。

## 设计要点

- **校验左移**：LLM 输出的三元组先经程序化 domain/range/自环校验，非法的不入库但保留在 `dropped_triplets` 中，自环率是论文中的 hallucination 信号之一。
- **幂等入库**：节点键为 `类型::小写规范名`，重复运行 load 不会产生重复节点/关系；同一实体跨文档出现时 `sourceDocs` 累积，天然支持跨文档实体汇聚。
- **失败隔离**：单篇 PDF 解析失败或单篇抽取失败只记日志跳过，不中断整体运行（与主项目"KG 失败不影响采集"原则一致）。
- **评估口径**：重构精度对原文句子做 max-cosine 再取均值，对句序与改写不敏感（bi-encoder 思路），原文句子数截断上限 `max_eval_sentences=120` 以控制 embedding 费用。

## 当前状态（2026-06-12）

已完成并验证：模块导入、schema 交叉引用校验、中英文 PDF 语料构建冒烟（2 篇英文 + 1 篇中文）、Neo4j 容器部署、连接/约束/合成数据幂等入库。**尚未执行**：真实 LLM 抽取与评估实验（需要可用 API key，建议先 `--limit 5` 小样本验证再放量）。
