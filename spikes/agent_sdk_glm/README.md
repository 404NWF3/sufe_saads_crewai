# P0 Spike：claude-agent-sdk × Anthropic 兼容端点（DeepSeek / GLM）

对应 `docs/INTEL_AGENT_SDK_ROADMAP.md` 第 5 章能力矩阵的验证脚本。**独立于 `sufe_saads_crewai` 包**，依赖装在 `agentsdk` dependency group（`uv sync --group agentsdk`）。

provider 选择与 `agent_runtime/client.py` 一致：`INTEL_SDK_PROVIDER=deepseek|glm`，未设置时自动探测（`.env` 有 `DEEPSEEK_API_KEY` 先用 DeepSeek，否则 GLM）。结果按 provider 写入 `results.<provider>.json`。

## 脚本

| 脚本 | 用途 |
|---|---|
| `run_matrix.py` | 跑全部能力矩阵验证项，结果写入 `results.<provider>.json`（可 `--only basic_query_main,tool_calls` 选择子集，`--n 20` 控制次数） |
| `debug_connect.py` | 单次连通性探针，打印每条 SDK 消息与 CLI stderr（`python debug_connect.py <model>`） |
| `probe_keys.py` | 用裸 HTTP 逐个测试 `.env` 中 GLM_API_KEY(_1..9) 在 GLM Anthropic 端点的可用性，不经过 CLI |

运行（仓库根目录）：

```bash
uv run --group agentsdk python spikes/agent_sdk_glm/run_matrix.py
```

## 2026-06-13 实测结论

### DeepSeek（`https://api.deepseek.com/anthropic`）——P0 验收通过

端点仅支持两个模型名：`deepseek-v4-pro`（reasoning，输出 thinking block，main 档）与 `deepseek-v4-flash`（fast 档）。全矩阵结果见 `results.deepseek.json`：

| 验证项 | 结果 |
|---|---|
| 基础连通 main/fast | 通过（4.1s / 1.7s） |
| 多轮会话 5 轮 | 通过 5/5 |
| `@tool` MCP 工具调用 ×20 | **通过 100%**（达标线 ≥95%） |
| tool-forcing 结构化决策 ×20 | **通过 100%**（达标线 ≥90%；单决策约 9s） |
| hooks 拦截/回写 | 通过 |
| 长会话 10 轮 | 通过 10/10 |
| subagent（Task 工具） | 不达标：模型自答未调 Task → 引擎本就用独立决策调用实现 critic |
| prompt caching | 不达标：usage cache 字段恒为 0 → 按设计靠上下文摘要压缩控成本 |
| output_format(json_schema) | 不达标：max_turns 耗尽报错 → 维持 tool-forcing 默认（实测 100%） |

### GLM（`https://open.bigmodel.cn/api/anthropic`）——被订阅阻塞（备选）

对 `.env` 中全部 4 个 GLM key 一律返回：

```
HTTP 429 {"type":"error","error":{"type":"rate_limit_error","code":"1309",
"message":"[1309][您的GLM Coding Plan套餐已到期，暂无法使用，前往官方续费即可恢复 https://bigmodel.cn/claude-code]"}}
```

对照验证：同账号 **OpenAI 兼容端点**（`/api/paas/v4`，按量计费）仍然可用（GLM_API_KEY_2/_3 实测 200；主 key 与 _1 偶发 1305 模型过载限流）。说明账号本身有效，仅 Anthropic 端点绑定的 Coding Plan 订阅到期。续费后 `INTEL_SDK_PROVIDER=glm` 重跑本目录脚本即可回填 `results.glm.json` 对比。

### 端点无关的技术验证（已通过）

- claude-agent-sdk **0.2.99** 在 Windows 下安装与启动正常，捆绑 CLI 可拉起子进程并完成 init 握手（`debug_connect.py` 能收到 `SystemMessage(subtype='init')`，模型映射、`permission_mode`、`setting_sources=[]` 均生效）；
- CLI 自带 10 次指数退避重试，持续 429 时由 SDK 抛出异常——与 `agent_runtime/structured.py` 的"失败返回 None 走规则 fallback"契约兼容。
