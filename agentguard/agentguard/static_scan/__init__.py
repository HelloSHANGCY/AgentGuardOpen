"""Agent 资产风险静态识别模块。

与运行时防护完全独立：只读取授权目录快照，绝不导入、执行待检内容。
入口：
- CLI：``python -m agentguard.static_scan.cli``
- worker：``python -m agentguard.static_scan.worker``
- API：``agentguard.static_scan.api.build_static_api``
"""

STATIC_SCAN_VERSION = "0.1.0"
