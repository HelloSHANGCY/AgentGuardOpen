"""确定性规则：配置基线、Skill/MCP 疑似恶意行为、代码数据流、供应链。"""

from .registry import RULES, evaluate_all

__all__ = ["RULES", "evaluate_all"]
