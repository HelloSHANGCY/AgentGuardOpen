"""Agent 内置工具 → 能力展开（通用 Agent 接入设计 §5.2）。

只依赖标准库与 normalize / capability：服务端适配器与终端客户端（endpoint/，本地快速判定）
共用同一份映射，保证两侧对同一次调用展开出相同的能力列表。
"""

from __future__ import annotations

import json
import re

from . import capability as C
from .normalize import normalize_path, resolve_path

# Claude Code：只读或纯 Agent 内部状态的内置工具。
READONLY_TOOLS = {"TodoWrite", "TodoRead", "ExitPlanMode", "EnterPlanMode", "AskUserQuestion",
                  "BashOutput", "KillShell", "KillBash", "ListMcpResourcesTool", "SlashCommand", "Skill",
                  "ToolSearch"}
CODEX_READONLY_TOOLS = {"update_plan", "request_user_input", "list_mcp_resources", "list_mcp_resource_templates"}

PATCH_FILE_RE = re.compile(r"^\*\*\* (Add File|Update File|Delete File|Move to): (.+)$")
# Codex 偶尔经 shell 调用 apply_patch（heredoc 形式），补丁正文同样要展开成写入。
SHELL_PATCH_RE = re.compile(r"^\s*(apply_patch|applypatch)\b")


def parse_mcp_tool(name: str) -> tuple[str, str] | None:
    """`mcp__<server>__<tool>` → (server, tool)。"""
    if not name.startswith("mcp__"):
        return None
    parts = name.split("__", 2)
    if len(parts) != 3 or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def _path(value, cwd: str) -> str:
    return normalize_path(str(value or cwd or ""))


def classify_builtin(tool: str, tool_input: dict, cwd: str) -> list:
    """Claude Code 内置工具 → 能力展开。"""
    data = tool_input if isinstance(tool_input, dict) else {}
    if tool in ("Bash", "PowerShell"):
        return C.expand_command(str(data.get("command") or ""))
    if tool in ("Read", "NotebookRead"):
        return [C.NormalizedCall(C.FILE_READ, _path(data.get("file_path") or data.get("notebook_path"), cwd),
                                 origin=tool)]
    if tool in ("Glob", "Grep", "LS"):
        return [C.NormalizedCall(C.FILE_READ, _path(data.get("path"), cwd), origin=tool)]
    if tool == "Write":
        return [C.NormalizedCall(C.FILE_WRITE, _path(data.get("file_path"), cwd),
                                 content=str(data.get("content") or ""), origin=tool)]
    if tool in ("Edit", "MultiEdit"):
        content = data.get("new_string") or json.dumps(data.get("edits") or [], ensure_ascii=False)
        return [C.NormalizedCall(C.FILE_WRITE, _path(data.get("file_path"), cwd), content=str(content), origin=tool)]
    if tool == "NotebookEdit":
        return [C.NormalizedCall(C.FILE_WRITE, _path(data.get("notebook_path"), cwd),
                                 content=str(data.get("new_source") or ""), origin=tool)]
    if tool == "WebFetch":
        url = str(data.get("url") or "")
        return [C.NormalizedCall(C.NET_FETCH, url, content=f"{url}\n{data.get('prompt') or ''}", sink=True,
                                 origin=tool)]
    if tool == "WebSearch":
        return [C.NormalizedCall(C.NET_SEARCH, str(data.get("query") or ""), origin=tool)]
    if tool in ("Task", "Agent"):
        return [C.NormalizedCall(C.AGENT_SPAWN, str(data.get("subagent_type") or ""), origin=tool)]
    if tool in READONLY_TOOLS:
        return [C.NormalizedCall(C.READONLY, tool, origin=tool)]
    # 未知工具：按未建模处理，交给默认策略。
    return [C.NormalizedCall(C.MCP_CALL, tool, content=json.dumps(data, ensure_ascii=False, default=str),
                             origin=tool)]


def parse_patch(patch: str, cwd: str) -> list:
    """Codex apply_patch 补丁 → 每个目标文件一条 FILE_WRITE（新增 / 修改 / 删除 / 重命名目标）。"""
    calls, current = [], None
    for line in str(patch or "").splitlines():
        match = PATCH_FILE_RE.match(line.rstrip())
        if match:
            current = C.NormalizedCall(C.FILE_WRITE, resolve_path(match.group(2).strip(), cwd), origin="apply_patch")
            calls.append(current)
        elif current is not None and line.startswith("+"):
            current.content += line[1:] + "\n"
    return calls


def classify_codex(tool: str, tool_input: dict, cwd: str) -> list:
    """Codex：内置工具只有 Bash 与 apply_patch，其余名称按 Claude Code 兼容名称处理。"""
    data = tool_input if isinstance(tool_input, dict) else {}
    command = str(data.get("command") or "")
    if tool == "apply_patch":
        return parse_patch(command, cwd) or [C.NormalizedCall(C.FILE_WRITE, normalize_path(cwd or "."),
                                                              origin="apply_patch")]
    if tool == "Bash":
        calls = C.expand_command(command)
        if SHELL_PATCH_RE.match(command):
            calls += parse_patch(command, cwd)
        return calls
    if tool in CODEX_READONLY_TOOLS:
        return [C.NormalizedCall(C.READONLY, tool, origin=tool)]
    if tool == "view_image":
        return [C.NormalizedCall(C.FILE_READ, resolve_path(str(data.get("path") or ""), cwd), origin=tool)]
    if tool in ("spawn_agent", "spawn_subagent"):
        return [C.NormalizedCall(C.AGENT_SPAWN, str(data.get("agent_type") or data.get("name") or ""),
                                 origin=tool)]
    return classify_builtin(tool, data, cwd)


# Trae：Hook 层工具名（docs.trae.cn「Hook 配置详解」）之外，内部工具名也可能出现（llm_tool_name，或旧版
# 未映射的工具），一并识别。
TRAE_READONLY_TOOLS = {"AskUserQuestion", "TodoWrite", "Skill", "SkillRecommend", "GetDiagnostics",
                       "CheckCommandStatus", "StopCommand", "OpenPreview", "ExitPlanMode", "EnterPlanMode",
                       "update_plan", "request_user_input", "Knowledge"}
TRAE_EDIT_TOOLS = {"Edit", "MultiEdit", "SearchReplace", "ApplyPatch", "DeleteFile", "apply_patch"}
# traecli 曾把路径放在 command 里：`Edit /work/api/retry.go`。
TRAE_COMMAND_PATH_RE = re.compile(r"^(?:Edit|Write|Read|MultiEdit|DeleteFile)\s+(.+)$")


def _file_paths(data: dict, cwd: str) -> list[str]:
    paths = [data.get(key) for key in ("file_path", "filePath", "path", "target_file", "notebook_path")]
    for key in ("file_paths", "filePaths", "paths"):
        if isinstance(data.get(key), list):
            paths += data[key]
    match = TRAE_COMMAND_PATH_RE.match(str(data.get("command") or "").strip())
    if match:
        paths.append(match.group(1).strip().strip("'\""))
    return [resolve_path(str(path), cwd) for path in dict.fromkeys(paths) if path]


def classify_trae(tool: str, tool_input: dict, cwd: str) -> list:
    """Trae：命令执行为 RunCommand（{command, blocking, command_type, requires_approval}），文件工具与 Claude Code
    兼容（{file_path, content / old_string, new_string}）；Edit 还覆盖补丁、删除等内部工具。"""
    data = tool_input if isinstance(tool_input, dict) else {}
    if tool in ("RunCommand", "Bash", "PowerShell"):
        return C.expand_command(str(data.get("command") or ""))
    if tool in TRAE_READONLY_TOOLS:
        return [C.NormalizedCall(C.READONLY, tool, origin=tool)]
    if tool in ("Write", *TRAE_EDIT_TOOLS):
        patch = str(data.get("patch") or data.get("input") or data.get("command") or "")
        calls = parse_patch(patch, cwd) if "*** " in patch else []
        if calls:
            return calls
        content = data.get("content") if tool == "Write" else (
            data.get("new_string") or data.get("new_str") or data.get("edits") or data.get("replacements") or "")
        content = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False, default=str)
        paths = _file_paths(data, cwd) or [_path("", cwd)]
        return [C.NormalizedCall(C.FILE_WRITE, path, content=content or "", origin=tool) for path in paths]
    if tool == "Read":
        paths = _file_paths(data, cwd) or [_path("", cwd)]
        return [C.NormalizedCall(C.FILE_READ, path, origin=tool) for path in paths]
    if tool == "SearchCodebase":
        return [C.NormalizedCall(C.FILE_READ, _path(data.get("path") or data.get("target_directory"), cwd),
                                 origin=tool)]
    if tool == "Task":
        return [C.NormalizedCall(C.AGENT_SPAWN, str(data.get("subagent_type") or data.get("agent") or ""),
                                 origin=tool)]
    return classify_builtin(tool, data, cwd)


# Qoder：Hook 载荷里的 tool_name 是原生工具名（docs.qoder.com「Hooks」调试示例与 Qoder CN 1.106 实测），参数也是原生
# 格式；兼容名（Bash / Read / Write / Edit …）同样可能出现，统一映射后处理。
QODER_TOOL_ALIASES = {"run_in_terminal": "Bash", "read_file": "Read", "create_file": "Write", "search_replace": "Edit",
                      "edit_file": "Edit", "delete_file": "DeleteFile", "grep_code": "Grep", "search_file": "Glob",
                      "list_dir": "LS", "task": "Task", "Agent": "Task", "search_web": "WebSearch",
                      "fetch_content": "WebFetch", "todo_write": "TodoWrite"}
QODER_READONLY_TOOLS = {"TodoWrite", "AskUserQuestion", "ask_user_question", "get_terminal_output", "search_memory",
                        "update_memory", "switch_mode", "create_plan", "get_problems", "fetch_rules", "Skill",
                        "search_codebase", "search_symbol", "BashOutput", "ExitPlanMode", "EnterPlanMode"}


def _edit_content(data: dict) -> str:
    replacements = data.get("replacements") or data.get("edits")
    if isinstance(replacements, list):
        return "\n".join(str(item.get("new_text") or item.get("new_string") or "") if isinstance(item, dict)
                         else str(item) for item in replacements)
    return str(data.get("new_string") or data.get("code_edit") or data.get("new_str") or "")


def classify_qoder(tool: str, tool_input: dict, cwd: str) -> list:
    """Qoder：run_in_terminal {command, is_background}、read_file {file_path, start_line…}、create_file {file_path,
    content / file_content}、search_replace {file_path, replacements:[{original_text, new_text}]}、edit_file
    {file_path, code_edit}、delete_file、list_dir {relative_workspace_path} 等。"""
    data = tool_input if isinstance(tool_input, dict) else {}
    name = QODER_TOOL_ALIASES.get(tool, tool)
    if name in ("Bash", "PowerShell"):
        return C.expand_command(str(data.get("command") or ""))
    if name in QODER_READONLY_TOOLS:
        return [C.NormalizedCall(C.READONLY, tool, origin=tool)]
    if name in ("Write", "Edit", "MultiEdit", "DeleteFile"):
        content = str(data.get("content") or data.get("file_content") or "") if name == "Write" else _edit_content(data)
        paths = _file_paths(data, cwd) or [_path("", cwd)]
        return [C.NormalizedCall(C.FILE_WRITE, path, content=content, origin=tool) for path in paths]
    if name == "Read":
        paths = _file_paths(data, cwd) or [_path("", cwd)]
        return [C.NormalizedCall(C.FILE_READ, path, origin=tool) for path in paths]
    if name in ("Grep", "Glob", "LS"):
        target = next((data[key] for key in ("path", "relative_workspace_path", "dir_path", "directory",
                                             "target_directory") if data.get(key)), "")
        return [C.NormalizedCall(C.FILE_READ, resolve_path(str(target), cwd) if target else _path("", cwd),
                                 origin=tool)]
    if name == "Task":
        return [C.NormalizedCall(C.AGENT_SPAWN, str(data.get("subagent_type") or data.get("agent_type")
                                                    or data.get("name") or ""), origin=tool)]
    calls = classify_builtin(name, data, cwd)
    for call in calls:
        call.origin = tool
    return calls


# ZCode：内置工具与 Claude Code 同名同参（zcode.z.ai「Hooks」与内核 glm agent 0.13 实测：Bash / Read / Write / Edit /
# Glob / Grep / WebFetch / WebSearch / Agent / Skill / TodoWrite …），另有会话内部状态工具与定时任务、工作流。
ZCODE_READONLY_TOOLS = {"CronList", "CronDelete", "ReadSessionContext", "TaskOutput", "TaskStop", "SendMessage",
                        "RespondToCoordinator", "js_reset"}
# 定时任务与工作流到点后由 Agent 执行其中的提示词，届时每次工具调用仍经过 Hook。
ZCODE_SPAWN_TOOLS = {"CronCreate", "CronUpdate", "Workflow"}


def classify_zcode(tool: str, tool_input: dict, cwd: str) -> list:
    """ZCode：按 Claude Code 兼容名称处理；文件工具的相对路径（如 `src/index.ts`）先按 cwd 展开。"""
    data = tool_input if isinstance(tool_input, dict) else {}
    if tool in ZCODE_READONLY_TOOLS:
        return [C.NormalizedCall(C.READONLY, tool, origin=tool)]
    if tool in ZCODE_SPAWN_TOOLS:
        return [C.NormalizedCall(C.AGENT_SPAWN, tool, origin=tool)]
    if tool == "ApplyPatch":
        patch = str(data.get("patch") or data.get("input") or data.get("command") or "")
        return parse_patch(patch, cwd) or [C.NormalizedCall(C.FILE_WRITE, _path(data.get("file_path"), cwd),
                                                            origin=tool)]
    if tool in ("Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS"):
        data = {**data, **{key: resolve_path(str(data[key]), cwd) for key in ("file_path", "path") if data.get(key)}}
    return classify_builtin(tool, data, cwd)


# WorkBuddy（桌面端内嵌 CodeBuddy Code 内核）：内置工具与 Claude Code 同名同参（workbuddy.ai「CLI 参考」：Bash / Read /
# Write / Edit / MultiEdit / Glob / Grep / WebFetch / WebSearch / Task / Agent / Skill / NotebookEdit / TodoWrite …），
# 另有代码智能（LSP）、任务清单、定时任务与团队协作工具。
WORKBUDDY_READONLY_TOOLS = {"LSP", "SendMessage", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskOutput",
                            "TaskStop", "CronList", "CronDelete", "TeamDelete"}
# 定时任务到点后、团队成员创建后由 Agent 执行其中的提示词，届时每次工具调用仍经过 Hook。
WORKBUDDY_SPAWN_TOOLS = {"CronCreate", "TeamCreate"}


def classify_workbuddy(tool: str, tool_input: dict, cwd: str) -> list:
    """WorkBuddy：按 Claude Code 兼容名称处理；文件工具的相对路径先按 cwd 展开。"""
    data = tool_input if isinstance(tool_input, dict) else {}
    if tool in WORKBUDDY_READONLY_TOOLS:
        return [C.NormalizedCall(C.READONLY, tool, origin=tool)]
    if tool in WORKBUDDY_SPAWN_TOOLS:
        return [C.NormalizedCall(C.AGENT_SPAWN, tool, origin=tool)]
    if tool in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "LS"):
        data = {**data, **{key: resolve_path(str(data[key]), cwd) for key in ("file_path", "path", "notebook_path")
                           if data.get(key)}}
    return classify_builtin(tool, data, cwd)


# CodeBuddy IDE 将内部工具名转为 Read / Write / Edit / Bash 等，但保留原参数。
# filePath 来自官方 Hook 示例；new_str / target_directory / target_file 已核对 Windows CN 内核。
def classify_codebuddy(tool: str, tool_input: dict, cwd: str) -> list:
    data = dict(tool_input) if isinstance(tool_input, dict) else {}
    aliases = {"file_path": ("filePath",),
               "new_string": ("new_str", "newString"), "notebook_path": ("notebookPath",),
               "new_source": ("newSource",), "prompt": ("fetchInfo",)}
    if tool in ("Glob", "LS"):
        aliases["path"] = ("target_directory",)
    if tool == "Delete":
        aliases["file_path"] = ("target_file", "filePath")
    for target, sources in aliases.items():
        # IDE 原生字段优先，避免额外的 Claude 兼容字段掩盖实际访问目标。
        for source in sources:
            if source in data:
                data[target] = data[source]
                break
    for key in ("file_path", "path", "notebook_path"):
        if data.get(key):
            data[key] = resolve_path(str(data[key]), cwd)
    if tool == "Delete":
        return [C.NormalizedCall(C.FILE_WRITE, _path(data.get("file_path"), cwd), origin=tool)]
    return classify_builtin(tool, data, cwd)


CLASSIFIERS = {"claude-code": classify_builtin, "codex": classify_codex, "trae": classify_trae,
               "qoder": classify_qoder, "zcode": classify_zcode, "workbuddy": classify_workbuddy,
               "codebuddy": classify_codebuddy}


def classify(agent: str, tool: str, tool_input: dict, cwd: str) -> list:
    """内置工具调用的能力展开；MCP 工具（mcp__*）不在此处理。"""
    return CLASSIFIERS.get(agent, classify_builtin)(tool, tool_input, cwd)
