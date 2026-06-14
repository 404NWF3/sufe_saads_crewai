# IEEE 论文：自主 LLM 安全情报采集智能体架构

本目录是情报采集智能体子系统的 IEEE 风格会议论文（IEEEtran, conference, 两栏）。论文写**新的覆盖优先 SDK 架构**（depth-quota 覆盖阀 + 边际信息/停滞终止）并记录**最新一轮完整 A/B 实验**（9 目标）。

## 文件

- `main.tex` — 论文正文（`\documentclass[conference]{IEEEtran}`）。含架构 TikZ 图（分层架构、三层 fallback）、单轮算法伪代码，以及 §IX 实验部分的 3 张 pgfplots 科研图（(图3) 覆盖完整度 + 效率分组柱状、(图4) 覆盖—效率权衡散点、(图5) 边际信息 g_t 逐轮衰减曲线）+ 全宽结果表 Table II（9 目标）。
- `references.bib` — 参考文献（仅保留可核验的权威文献与一手数据源）。
- `main.pdf` — 已编译产物（9 页，含最新 A/B 结果）。

## 实验结论（A/B，goals_version 2026-06-13.2，已写入 §IX）

数据源：`data/eval/report.json`（**9 目标**含 2 个多主题目标 IJA/SRD × 2 引擎 × 3 重复，活源真实配额）。**主指标=覆盖完整度（depth-quota K=3）**：

- **覆盖完整度（头条胜势）**：sdk 在 6/9 目标达 1.00（基线 4/9），**任一目标都不低于基线**，均值 0.69→0.95（**+38%**）；难目标 ATA 1.00 vs 0.00、RAG 1.00 vs 0.50、SRD 0.78 vs 0.33、BROAD/IJA 0.89 vs 0.67。
- **效率（代价，诚实）**：relevant/call 均值 **−8%**（PI/JB/DL 胜，覆盖阀逼着追稀疏主题的目标上输）；items/call **+60%**，topics **+34%**。
- **终止质量**：sdk 9/9 停在事后最优轮（偏差 0），基线均值偏差 0.22；**停滞阀全程未触发**（stall_rate=0，作为潜在保护阀）。
- **可靠性**：436 次活体结构化决策成功率 **97.7%**（426/436）、fallback 2.3%。
- **方差**：覆盖优先后明显收敛——覆盖 stdev 6/9 目标为 0，效率 stdev 7 目标 ≤0.35（IJA 离群 ±1.33）。
- **代价**：墙钟约一个数量级（rules ~20–112s；sdk ~200–1950s）。

所有数字经脚本对 `report.json` 核验一致。bandit 离线回放（regret 1.063 vs 1.245）与端点能力矩阵（工具调用/决策解析 100%）作为子系统验证保留。

## 编译

需要 TeX Live（含 `IEEEtran`、`tikz`、`algpseudocode`、`booktabs`、`hyperref`）与 `pdflatex` + `bibtex`：

```bash
pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
```

或 `latexmk -pdf main.tex`。当前在 TeX Live 2026 上零 undefined reference、无显著 overfull box。

## 论文与代码的对应关系（溯源）

| 论文小节 | 代码 / 文档来源 |
|---|---|
| 引擎工厂、`INTEL_ENGINE` | `src/sufe_saads_crewai/intel/engine.py` |
| 混合控制器、单轮七步、四决策 | `src/sufe_saads_crewai/intel/sdk_loop.py` |
| 结构化决策引擎、tool-forcing、fallback 契约 | `src/sufe_saads_crewai/agent_runtime/structured.py` |
| 四个 typed MCP 源工具与算子 | `src/sufe_saads_crewai/tools_mcp/source_server.py` |
| UCB1 bandit、reward、离线回放 | `src/sufe_saads_crewai/intel/bandit.py` |
| 三层相关性过滤 | `src/sufe_saads_crewai/intel/relevance.py` |
| 上下文摘要（≤2-3K tokens） | `src/sufe_saads_crewai/intel/context.py` |
| 共享确定性规则（baseline + fallback） | `src/sufe_saads_crewai/intel/rules.py` |
| depth-quota 覆盖度量 / 边际信息 g_t / 停滞判定 | `src/sufe_saads_crewai/intel/rules.py`（`coverage_completeness` / `round_information_gain` / `is_search_stalled`） |
| 覆盖阀 + 停滞阀 + 优先级阶梯 | `src/sufe_saads_crewai/intel/sdk_loop.py`（`_decide_termination`） |
| 覆盖/停滞/新指标进 eval 报告 | `scripts/eval_ab.py`（`coverage_completeness`/`new_relevant_per_call`/`stall_rate`） |
| 预算/去重 hooks | `src/sufe_saads_crewai/agent_runtime/hooks.py` |
| provider 抽象（DeepSeek/GLM） | `src/sufe_saads_crewai/agent_runtime/client.py` |
| 评估协议、bandit regret 1.063 vs 1.245、端点矩阵 100% | `docs/INTEL_AGENT_SDK_ROADMAP.md` §5,§9,§10.1；`docs/PROJECT_PROGRESS.md` §6.1 |

## 待办（投稿前）

- 人工 precision 抽检（每配置 50 条、双标注 + 异源 LLM-judge）以坐实 efficiency 比较——这是 §IX threats 列出的最高价值缺口。
- 人工核验 `references.bib` 每条目（尤其 `cheng2024ctinexus` 的 arXiv 编号与作者列表）后再投稿。
- 填入真实作者与单位。
- 可选：GLM provider 续费后重跑 A/B 做 provider 对照。
