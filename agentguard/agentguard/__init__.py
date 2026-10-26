"""AgentGuard 运行时异常监控与阻断 · 初版。

组件：
- MCP Security Gateway：/mcp/{server} 强制代理，副作用发生前完成 ALLOW/ASK/DENY 决策；
- 统一事件/决策/攻击链存储与查询 API、SSE、Web 控制台。

目录（依赖方向自上而下，core 不依赖任何其他子包）：
- main.py / api.py / admin.py / config.py / models.py：应用组装、查询 API、管理鉴权、配置与数据模型；
- core/：无状态判定原语（规范化、能力展开、工具映射、终端快速判定），原样同步到终端客户端；
- detection/：确定性决策引擎、行为基线、数据流溯源、污点与意图识别；
- llm/：大模型调用客户端、危险审批与异步研判；
- rules/：特征规则库（rulepacks/）、管理接口、规则建议与回放；
- gateway/：MCP 强制代理、工具清单、共享调用检查器；
- storage/：运行时事件/决策存储、SQLite 持久化、任务上下文；
- agents/：各 Agent 的 Hook 适配、设备注册与接入；static_scan/：Agent 资产静态扫描；
- evaluation.py：通用 Hook 夹具评测 worker；testing/：固定离线语料与回归入口。

Web 控制台前端在包外的 agentguard/console（Vite 构建产物 dist 随仓库提交，镜像只复制 dist）。
"""

__version__ = "0.1.0"
