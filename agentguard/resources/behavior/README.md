# 团队共享的行为基线资源

本目录随 Git 分发，供团队离线导入候选模型、训练和复核。安装项目 Python 依赖后即可使用，不需要 Hugging Face 登录、原始会话或 Git LFS。

## 包含的资源

| 资源 | 内容 |
| --- | --- |
| 默认内置基线 | `agentguard/detection/baseline/transitions.json` 为三阶递归插值，使用 2,983 个 SWE-chat 训练会话＋49 个内置会话，K=20、先验证据=5、训练侧 1% 触发预算对应阈值 11.33；本包记录 SHA-256 |
| 原始一阶回滚 | `agentguard/detection/baseline/transitions.legacy.json`，控制台版本 `builtin-legacy`；保留原模型与评分公式 |
| 6 个候选模型 | 263、1,000、2,983 个外部训练会话，各有原始计数与来源平衡两种版本；模型文件保留原版本与评估信息 |
| 符号训练数据 | 2,983 个训练会话、525 个仓库分组、269,850 个有效步骤 |
| 验证数据 | 37 个会话、26 个仓库分组、3,188 个有效步骤 |
| 独立测试集登记 | 保留 100 个测试会话的计数、内容哈希与仓库分组哈希；不分发测试步骤，运行时训练无法读取它们 |
| 评估报告 | `evaluation.json` 保留原来的候选评估结果，指标口径为异常触发率 |

数据仅有行为符号、执行状态、序列边界和哈希标识。压缩包展开后约 33 MiB，Git 中约 1.1 MiB；不包含原始提示词、代码、命令参数、工具返回、设备凭证或本机运行时数据库。

6 个历史候选的原评估均为 `reject`，没有达到当时既定启用标准；它们及 `evaluation.json` 保留的是原始一阶内置参考下的历史结果。新的三阶默认模型由用户明确选择替换，模型中保留了实际评估及未完成独立验收的状态。导入命令本身不改写 `active.json`、本地会话或默认模型。SWE-chat 的真实开发会话没有逐调用人工安全标签，异常触发率不能称为误报率。

## 校验与本地导入

在仓库根目录执行：

```bash
make behavior-assets-check
make behavior-assets
```

第二条命令默认导入到 `agentguard/data/benign/team-behavior/`，该目录受现有 Git 忽略规则保护。也可以指定本地服务正在使用的行为数据目录：

```bash
python3 agentguard/tools/behavior_assets.py install --directory /path/to/behavior
```

服务需通过 `AG_BEHAVIOR_DIR` 使用同一目录。导入会先验证 SHA-256、模型版本、符号结构和训练/验证/测试仓库分组隔离；相同内容可重复导入，不同内容的同名版本会报错。导入现有服务的数据目录后，刷新控制台“行为基线”，即可查看候选模型和数据源。启用候选需要在控制台单独操作。

训练时选择 `swechat-quality-20261017` 数据源；可设训练会话上限为 263、1,000 或 2,983。训练集按原固定顺序截取，验证集不变。6 个历史模型包含当时的训练参数、提取器代码哈希和原始数据分区哈希；用当前代码重新训练会产生新候选版本，历史评估不代表新模型的验收结果。

## Docker 使用

新构建的 AgentGuard 镜像包含本共享包。使用当前 Compose 默认行为数据目录导入：

```bash
docker compose -f docker-compose.agentguard.yml build agentguard
docker compose -f docker-compose.agentguard.yml up -d --no-deps agentguard
docker compose -f docker-compose.agentguard.yml exec -T agentguard \
  python tools/behavior_assets.py install --directory /app/data/agent-devices/behavior
```

导入命令只登记候选模型和符号数据，不切换当前基线。若部署自定义了 `AG_BEHAVIOR_DIR`，将最后一条命令的目标目录改为实际配置值。

## 来源与版本

来源为 [SALT-NLP/SWE-chat](https://huggingface.co/datasets/SALT-NLP/SWE-chat)，冻结版本 `202b071f18e03c79df5a7287565ce2ebc5ee7756`；特征版本 3、序列语义版本 2、清洗策略 `swechat-quality/2`。许可与修改说明见 [NOTICE.md](NOTICE.md)。如需原始数据，请从上游按其访问条件获取。

`bundle.json` 记录每个资源的大小、SHA-256、候选版本和训练会话数量；数据自己的 `manifest.json` 记录解压后内容哈希、固定分区及保留测试组。Windows 检出采用 LF，避免换行转换破坏校验。
