# 固定全量测试数据

本目录保存 2026-10-26 从项目原有 AgentRange 语料生成器导出的一次固定快照，种子为 `1337`。共 5,200 条：正常样本 5,120 条、攻击样本 80 条，覆盖 11 个场景。源代码版本和源文件摘要记录在 `manifest.json`，数据导出后不再依赖原生成器。

| 文件 | 内容 |
| --- | --- |
| `events.jsonl.gz` | 按原始顺序保存全部事件，gzip 解压后每行一个 JSON 对象 |
| `context.json` | 原始 Skill 文本、MCP 工具描述及可见性、24 个 HTTP 测试请求样本 |
| `manifest.json` | 版本、来源、种子、样本数、场景分布、文件字节数与 SHA-256 |

事件保留原始 `instance_id`、`t`、`kind`、`scenario`、`actor`、`input`、`trajectory`、`malicious` 和 `evidence`。标签用于测试评分，不作为检测输入。文本中的命令、地址、工具描述和注入指令都是待检数据，加载器只解析数据，不执行它们。

从仓库根目录运行：

```bash
make corpus-check PYTHON="$PWD/.venv/bin/python"
make test-corpus PYTHON="$PWD/.venv/bin/python"
.venv/bin/python agentguard/tools/replay_test_corpus.py \
  --out .test-results/offline-corpus.json
```

完整性校验检查两个数据文件的 SHA-256 和字节数，以及事件唯一性、顺序、标签和场景分布。`test-corpus` 检查全部 5,200 条数据的本地请求判定，并验证数据被修改时校验失败。`replay_test_corpus.py` 可用 `--scenario C2-B --limit 10` 筛选输入；默认使用全部样本。

也可在控制台“评测与指标 → 评测任务 → 新建评测”中选择“靶场离线数据集”。该套件默认全量 5,200 条，支持场景筛选、回放条数、进度、取消和历史报告；运行前执行同样的完整性校验。下载的 JSON 报告包含本次全部样本、数据版本与文件摘要，页面详情显示最近 100 条。需要评测 worker 在线，检测过程不访问靶场、模型服务或网关接口。

离线回归使用独立的内置规则副本及快照中的身份、Skill 权限和工具清单，对声明的工具请求调用当前检测引擎。代码和上传样本调用纯检测函数。首次 ASK/DENY 后停止检查该事件的后续轮次，不执行工具、不伪造返回、不推进已执行行为序列，也不写入在线审计、规则命中统计、训练记录或模型。

该快照用于固定合成语料的回归。它不包含真实业务后端或工具执行结果，不能复现完整业务、网络隔离、真实副作用、启动 Beacon 或部署性能验收。报告中的这些覆盖项固定为未验证。历史靶场验收结果不由本数据集改写。
