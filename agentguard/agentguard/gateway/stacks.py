"""真实运行时栈帧采集（T02 审计证据）。

事件里的 stack 只记录采集点的实际调用帧，统一结构：
{"source", "module", "file", "function", "line"}。
source 区分证据来源：
- app：应用侧 Hook 上报（由业务应用采集）；
- gateway：网关自身栈；
- guard：入口/出口 Guard 自身栈。
禁止把预设调用路径当作实际函数栈展示。采集限制深度并跳过框架/库内部帧，
控制单次开销（最多检查固定数量的帧）。
"""

import os
import sys

MAX_STACK_DEPTH = 8
MAX_FRAMES_EXAMINED = 48
SKIP_MODULE_PREFIXES = (
    "fastapi", "starlette", "anyio", "uvicorn", "asyncio",
    "threading", "concurrent", "importlib", "runpy", "click", "__main__",
)


def capture_stack(source: str = "gateway", max_depth: int = MAX_STACK_DEPTH,
                  skip: tuple = ()) -> list[dict]:
    """从调用点向上采集真实栈帧，根→叶返回；深度与检查量均有上限。"""
    frames: list[dict] = []
    skip_prefixes = tuple(SKIP_MODULE_PREFIXES) + tuple(skip)
    frame = sys._getframe(1)
    examined = 0
    while frame is not None and len(frames) < max_depth and examined < MAX_FRAMES_EXAMINED:
        examined += 1
        module = str(frame.f_globals.get("__name__", ""))
        if not any(module == prefix or module.startswith(prefix + ".") for prefix in skip_prefixes):
            frames.append({
                "source": str(source),
                "module": module,
                "file": os.path.basename(frame.f_code.co_filename),
                "function": frame.f_code.co_name,
                "line": int(frame.f_lineno),
            })
        frame = frame.f_back
    frames.reverse()
    return frames


def normalize_stack(stack, default_source: str = "app") -> list[dict]:
    """兼容历史字符串栈帧：字符串转成无行号的帧记录，不冒充真实行号。"""
    frames: list[dict] = []
    for item in stack or []:
        if isinstance(item, dict):
            try:
                line = int(item.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            frames.append({
                "source": str(item.get("source") or default_source),
                "module": str(item.get("module") or ""),
                "file": str(item.get("file") or ""),
                "function": str(item.get("function") or item.get("name") or ""),
                "line": line,
            })
        elif item:
            frames.append({"source": str(default_source), "module": "", "file": "",
                           "function": str(item), "line": 0})
    return frames
