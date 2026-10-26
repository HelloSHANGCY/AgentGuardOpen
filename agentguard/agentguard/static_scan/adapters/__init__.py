"""框架与资产适配器：只读取事实，不做规则判定。"""

from .application import ApplicationAdapter
from .claude_code import ClaudeCodeAdapter
from .compose import ComposeAdapter
from .framework import FrameworkAdapter
from .langflow import LangflowAdapter
from .mcp import MCPAdapter
from .skill import SkillAdapter

# 顺序即依赖顺序：skill/framework/mcp 先建资产，application/langflow 再建立关系。
DEFAULT_ADAPTERS = (
    FrameworkAdapter,
    SkillAdapter,
    MCPAdapter,
    ComposeAdapter,
    ApplicationAdapter,
    LangflowAdapter,
    ClaudeCodeAdapter,   # 依赖 skill/mcp 资产建立加载与连接关系
)

__all__ = [
    "DEFAULT_ADAPTERS", "ClaudeCodeAdapter", "ComposeAdapter", "FrameworkAdapter", "LangflowAdapter",
    "MCPAdapter", "ApplicationAdapter", "SkillAdapter",
]
