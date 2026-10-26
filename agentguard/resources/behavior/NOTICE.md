# 数据来源与许可

Contains information derived from SALT-NLP/SWE-chat, made available by the Social And Language Technology Lab under the Open Data Commons Attribution License (ODC-BY) v1.0.

- Source: https://huggingface.co/datasets/SALT-NLP/SWE-chat
- Frozen source revision: `202b071f18e03c79df5a7287565ce2ebc5ee7756`
- License identifier: `ODC-BY-1.0`
- License text and URI: https://opendatacommons.org/licenses/by/1-0/

该来源与许可说明适用于本目录 SWE-chat 衍生的符号数据库、候选基线及评估结果，也适用于 `agentguard/detection/baseline/transitions.json` 中由同一符号训练分区与内置语料训练得到的三阶默认模型；不改变仓库其他代码的许可。

AgentGuard 对来源数据执行了质量清洗、行为符号提取、序列边界保留、会话/仓库标识哈希化、训练/验证/测试分组隔离和 gzip 压缩。共享包仅保留训练和验证符号，保留测试集的统计与哈希，不包含原始会话内容。候选模型由这些符号与仓库内的内置开发语料训练得到。

复制或再分发本目录资源时请保留本来源说明和许可链接。上游原始数据仍按其访问条件获取。
