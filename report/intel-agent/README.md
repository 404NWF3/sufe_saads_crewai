# 会议论文：LLM 安全情报采集混合控制智能体

目录：`report/intel-agent/`  
模板：`IEEEtran` conference（中文正文需 **XeLaTeX** 或 **LuaLaTeX** + `ctex`）

## Paper Configuration Record（已确认）

| 参数 | 值 |
|------|-----|
| 论文类型 | Conference Paper |
| 建议投稿会场 | **ACM AISec**（Workshop on Artificial Intelligence and Security，与 CCS 合办；与 LLM 安全 / agentic 系统最契合） |
| 备选 | IEEE EuroS&P Workshops；或期刊加长版投 *Computers & Security* |
| 引用格式 | IEEE |
| 正文语言 | 中文（含英文 Abstract） |
| 输出 | LaTeX → 本目录 |
| 模式 | full |
| RQ 侧重 | (a) 混合控制面与可审计预算；(b) 无 RL 下 UCB + Playbook |

> 说明：AISec 相机就绪通常要求 **ACM acmart** 英文稿。当前交付为中文 IEEEtran 工作稿，便于组内评审；投 AISec 前需英译并换模板。

## 文件

| 文件 | 说明 |
|------|------|
| `main.tex` | 正文 |
| `references.bib` | 参考文献（含 DOI / 官方 URL，可核验） |
| `README.md` | 本说明 |

## 与旧稿 `report/main.tex` 的区别

| | `report/`（旧） | `report/intel-agent/`（本稿） |
|--|----------------|------------------------------|
| 代码基线 | 早期 `src/.../sdk_loop` | 当前 `backend/intel_agent` |
| 叙事重心 | 覆盖优先终止 + 九目标 A/B | 混合控制面 + UCB 审批门 + Playbook |
| 实验主张 | 完整 live A/B 覆盖率数字 | **仅**子系统证据（UCB regret、端点矩阵、冒烟）；不夸大未完成的 A/B |

## 编译

```bash
cd report/intel-agent
xelatex -interaction=nonstopmode main.tex
bibtex main
xelatex -interaction=nonstopmode main.tex
xelatex -interaction=nonstopmode main.tex
```

依赖：TeX Live + `ctex`、`IEEEtran`、`tikz`、`algorithm`/`algpseudocode`、`booktabs`。

## 投稿前待办

- [ ] 填入真实作者、单位、致谢与资助
- [ ] 人工复核 `references.bib` 每条 DOI/页码
- [ ] 完成同预算 A/B + 人工精确率后扩写 §评估
- [ ] 若投 AISec：英译 + 改 `acmart`
