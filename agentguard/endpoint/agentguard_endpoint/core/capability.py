"""工具调用能力归一化（通用 Agent 接入设计 §5）。

引擎规则基于“能力 + 资源”而非具体 (server, tool)，使业务服务的 MCP 工具与
Claude Code 等通用 Agent 的内置工具共用同一套确定性规则：
- MCP 工具按 (server, tool) 查表，未建模的归为 MCP_CALL；
- 内置工具的映射由各 Agent 适配器负责（agents/），本模块只提供命令展开等公共能力；
- 一次调用可展开为多条子能力（如 `cat ~/.aws/credentials | curl -d @- URL`），
  每条子能力独立过规则，最终取最严格决策。
"""

from __future__ import annotations

import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass

from .normalize import DRIVE_RE, URL_RE, normalize_path

EXEC = "EXEC"
FILE_READ = "FILE_READ"
FILE_WRITE = "FILE_WRITE"
NET_FETCH = "NET_FETCH"
NET_SEARCH = "NET_SEARCH"
AGENT_SPAWN = "AGENT_SPAWN"
DATA_QUERY = "DATA_QUERY"
MCP_CALL = "MCP_CALL"
READONLY = "READONLY"

# 可产生副作用或把数据带出受控环境的能力：不可信来源触发时视为高风险。
HIGH_RISK_CAPABILITIES = {EXEC, FILE_WRITE, NET_FETCH}


@dataclass
class NormalizedCall:
    capability: str
    resource: str = ""       # 规范化路径 / 命令原文 / URL / "server/tool"
    content: str = ""        # 离开受控环境或写入的内容（R006 直检用）
    sink: bool = False       # 内容会离开受控环境（网络型 Sink）
    origin: str = ""         # 展开来源，例如 "bash:redirect"

    def as_dict(self) -> dict:
        return {"capability": self.capability, "resource": self.resource[:240],
                "sink": self.sink, "origin": self.origin}


# ---------- MCP 工具能力映射（按工具 schema 识别，不登记上游地址） ----------

# (server, tool) -> (capability, sink, 资源参数名)
MCP_CAPABILITIES = {
    ("shell-runner", "run"): (EXEC, True, "cmd"),
    ("notes-sync", "debug_exec"): (EXEC, True, "cmd"),
    # 沙箱执行无出网路径，不作为网络 Sink（与原 NETWORK_SINK_TOOLS 一致）。
    ("sandbox-exec", "run_test"): (EXEC, False, "cmd"),
    ("shell-runner", "read_file"): (FILE_READ, False, "path"),
    ("customer-db", "query"): (DATA_QUERY, False, "tenant"),
    ("notes-sync", "sync_note"): (NET_FETCH, True, ""),
    ("monitoring", "query_metric"): (READONLY, False, ""),
    ("knowledge", "search"): (READONLY, False, ""),
    ("gitlab", "get_pr"): (READONLY, False, ""),
    ("threat-intel", "lookup"): (READONLY, False, ""),
}


def classify_mcp(server: str, tool: str, arguments: dict) -> list[NormalizedCall]:
    """MCP 工具调用 → 能力；未建模工具为 MCP_CALL。Sink 内容为完整参数 JSON。"""
    entry = MCP_CAPABILITIES.get((server, tool))
    content = json.dumps(arguments or {}, ensure_ascii=False)
    if entry is None:
        return [NormalizedCall(MCP_CALL, f"{server}/{tool}", content=content, origin="mcp")]
    capability, sink, key = entry
    resource = str((arguments or {}).get(key, "")) if key else f"{server}/{tool}"
    if capability == FILE_READ:
        resource = normalize_path(resource)
    return [NormalizedCall(capability, resource, content=content, sink=sink, origin="mcp")]


# ---------- Shell 命令展开 ----------

# 命令段分隔：管道、顺序执行、换行，以及代码块与分组的括号——PowerShell 的 `if (...) { ... }`、
# `& { ... }`、`foreach (...) { ... }` 与 shell 的 `{ ...; }`、`( ... )` 中的命令同样逐段展开。
SEGMENT_SPLIT_RE = re.compile(r"\|\||&&|;|\||\r?\n|(?<!\$)[{(]|[})]")
# `${HOME}`、`${env:USERPROFILE}` 先改写为 `$HOME` / `$env:USERPROFILE`，避免花括号被当作代码块切开。
BRACED_VAR_RE = re.compile(r"\$\{(\w+(?::\w+)?)\}")
REDIRECT_RE = re.compile(r"(?<![<>&0-9])(?:[12]|&)?>>?\s*([^\s;|&<>()]+)")
INPUT_REDIRECT_RE = re.compile(r"(?<![<])<\s*([^\s;|&<>()]+)")
QUOTED_REDIRECT = "bash:quoted-redirect"
HEREDOC_RE = re.compile(r"(?<!<)<<(-?)\s*(\\?)(['\"]?)([A-Za-z_][\w.-]*)\3")
# 命令替换 `$(...)`（PowerShell 子表达式同形）与反引号：内层命令单独展开（不含嵌套括号的一层）。
SUBSTITUTION_RE = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
# 读取类命令：参数中非选项项即被读取的路径。
READ_COMMANDS = {
    "cat", "head", "tail", "less", "more", "base64", "xxd", "od", "strings", "hexdump",
    "source", ".", "tac", "nl", "sort", "uniq", "wc", "jq", "yq", "openssl", "gpg", "zip", "tar",
    # Windows（cmd / PowerShell，命令名按小写比较）
    "type", "get-content", "gc", "import-csv", "compress-archive",
}
GREP_COMMANDS = {"grep", "egrep", "rg", "ag", "findstr", "select-string", "sls"}
# 写入类命令：参数中的路径被修改（cp/mv/install 取最后一个参数为目标）。
WRITE_COMMANDS = {"tee", "touch", "truncate", "rm", "chmod", "chown", "ln", "mkdir", "rmdir", "unlink",
                  "set-content", "add-content", "out-file", "new-item", "ni", "remove-item", "ri", "del", "erase",
                  "rd", "md", "icacls", "attrib", "tee-object"}
DEST_COMMANDS = {"cp", "mv", "install", "rsync", "scp", "copy", "move", "xcopy", "copy-item", "cpi", "move-item",
                 "mi"}
NETWORK_COMMANDS = {
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync", "sftp", "ftp", "telnet",
    "socat", "http", "https", "aria2c", "lwp-download",
    "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-bitstransfer", "bitsadmin",
    "send-mailmessage", "test-netconnection",
}
# 再起一层 shell 执行内联命令：`powershell -Command "..."`、`cmd /c "..."`，内层命令同样展开。
SHELL_COMMANDS = {"powershell", "pwsh", "cmd", "bash", "sh", "zsh"}
SHELL_INLINE_FLAGS = {"-c", "-command", "/c", "/k", "-commandwithargs"}
# PowerShell 参数名：其后的值才是路径（-Path X / -Destination Y）；-Value 等内容参数不当作路径。
PS_VALUE_FLAGS = {"-value", "-encoding", "-filter", "-include", "-exclude", "-pattern", "-itemtype", "-name",
                  "-propertytype", "-type", "-delimiter"}
REGISTRY_RE = re.compile(r"^(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE):?[\\/]", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\")
# 其他 Windows 反斜杠路径：`~\`、`.\`、`..\` 与 `$HOME\`、`$env:USERPROFILE\`、`%APPDATA%\` 等变量开头的路径。
WINDOWS_RELPATH_RE = re.compile(r"""(?:^|[\s'"(=,])(?:~|\.{1,2}|\$\{?env:\w+\}?|\$\{?home\}?|%\w+%)\\""",
                                re.IGNORECASE)
GIT_NETWORK_SUBCOMMANDS = {"push", "clone", "fetch", "pull", "ls-remote", "remote"}
WRAPPER_COMMANDS = {"sudo", "env", "nohup", "time", "timeout", "nice", "xargs", "command", "exec", "stdbuf",
                    "doas", "setsid", "ionice", "chrt", "taskset", "unbuffer", "caffeinate"}
# 包装命令中带取值的选项（`sudo -u root cat …`、`env -u X cat …`），取值一并跳过。
WRAPPER_VALUE_OPTIONS = {
    "sudo": {"-u", "-g", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "-h"}, "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}, "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"}, "time": {"-f", "-o", "--format", "--output"},
    "xargs": {"-I", "-n", "-L", "-P", "-d", "-E", "-s", "-a", "--arg-file", "--delimiter"},
    "stdbuf": {"-i", "-o", "-e"}, "exec": {"-a"}, "ionice": {"-c", "-n", "-p"}, "chrt": {"-p"},
    "taskset": {"-p", "-c"},
}
# shell 控制结构关键字：`if …; then cat x; fi`、`for …; do cat x; done` 中关键字之后才是命令。
SHELL_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!"}
# 脚本解释器：内联代码（-c/-e、heredoc）中的路径字面量按读取处理，含写入特征时同时按写入处理。
# 无法还原动态拼接的路径；目标是覆盖 `python3 -c "open('.claude/settings.json','w')…"` 这类直接形态。
INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "osascript"}
QUOTED_LITERAL_RE = re.compile(r"""(?:'([^'\n]{1,256})'|"([^"\n]{1,256})")""")
PATH_LITERAL_RE = re.compile(r"^(?:~|\.{1,2})?/[^/\s]|^\.[A-Za-z0-9_-]")
CODE_WRITE_RE = re.compile(
    r"""open\([^)]*['"][wax+]|\.write|writeFile|appendFile|createWriteStream|unlink|\bremove|rmtree|rmSync"""
    r"""|\brename|\breplace\(|truncate|chmod|copyfile|shutil\.|File\.(?:write|open)|IO\.write|fs\.\w+Sync""")


def _tokens(segment: str) -> list[str]:
    if WINDOWS_PATH_RE.search(segment) or WINDOWS_RELPATH_RE.search(segment):
        # Windows 反斜杠路径：POSIX shlex 会把反斜杠当转义吞掉，先统一成正斜杠再切分。
        segment = segment.replace("\\", "/")
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _strip_wrappers(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        base = token.rsplit("/", 1)[-1]
        if token in SHELL_KEYWORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
            index += 1
            continue
        if base not in WRAPPER_COMMANDS:
            break
        index += 1
        valued = WRAPPER_VALUE_OPTIONS.get(base, set())
        while index < len(tokens) and tokens[index].startswith("-") and tokens[index] != "-":
            option = tokens[index]
            index += 1
            if option == "--":
                break
            if option in valued:
                index += 1
        # timeout 的时长参数、chrt / taskset 的优先级与 CPU 掩码
        if base in ("timeout", "chrt", "taskset") and index < len(tokens) and re.match(r"^[\d.]", tokens[index]):
            index += 1
    return tokens[index:]


def _inline_code_calls(texts: list[str], interpreter: str) -> list[NormalizedCall]:
    paths = []
    literals = [item for text in texts for item in QUOTED_LITERAL_RE.findall(text)]
    for single, double in literals:
        literal = (single or double).strip()
        if PATH_LITERAL_RE.match(literal) and not URL_RE.match(literal) and " " not in literal:
            paths.append(normalize_path(literal))
    if not paths:
        return []
    origin = f"bash:{interpreter}"
    calls = [NormalizedCall(FILE_READ, path, origin=origin) for path in dict.fromkeys(paths)]
    if any(CODE_WRITE_RE.search(text) for text in texts):
        calls += [NormalizedCall(FILE_WRITE, path, origin=origin) for path in dict.fromkeys(paths)]
    return calls


def _path_args(args: list[str]) -> list[str]:
    paths, skip = [], False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = arg.lower() in PS_VALUE_FLAGS
            continue
        if arg and not URL_RE.match(arg) and not (len(arg) == 2 and arg[0] == "/"):
            paths.append(arg)   # 跳过 cmd 风格开关（/s、/q）
    return paths


def _remote(path: str) -> bool:
    """scp / rsync 的 `host:path` 远端参数（盘符路径 `C:/...` 不算）。"""
    return ":" in path.split("/", 1)[0] and not DRIVE_RE.match(path)


def _command_name(token: str) -> str:
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _registry_path(key: str) -> str:
    """`HKCU\\Software\\...\\Run` / `HKCU:\\Software\\...` → `HKCU/Software/.../Run`（持久化规则匹配用）。"""
    return normalize_path(re.sub(r"^([A-Za-z_]+):", r"\1", key))


def _windows_persistence(name: str, args: list[str]) -> list[NormalizedCall]:
    lowered = [arg.lower() for arg in args]
    if name == "schtasks" and "/create" in lowered:
        task = args[lowered.index("/tn") + 1] if "/tn" in lowered[:-1] else "task"
        return [NormalizedCall(FILE_WRITE, "C:/Windows/System32/Tasks/" + task.strip("/\\"), origin="bash:schtasks")]
    if name == "reg" and lowered[:1] in (["add"], ["import"], ["copy"]):
        keys = [arg for arg in args[1:] if REGISTRY_RE.match(arg)]
        return [NormalizedCall(FILE_WRITE, _registry_path(key), origin="bash:reg") for key in keys[:1]]
    if name in ("new-itemproperty", "set-itemproperty", "new-item", "set-item"):
        keys = [arg for arg in args if REGISTRY_RE.match(arg)]
        return [NormalizedCall(FILE_WRITE, _registry_path(key), origin=f"bash:{name}") for key in keys[:1]]
    return []


def _mask_heredocs(text: str) -> str:
    """heredoc 正文不是命令：引号定界（<<'EOF'）的正文按字面量整体屏蔽 `<>` 与引号；
    未加引号的定界符正文仍会展开 $(...)，只屏蔽引号，避免正文里的撇号打乱后续引号配对。"""
    lines, pending, out = text.split("\n"), [], []
    for line in lines:
        if pending:
            strip_tabs, quoted, delimiter = pending[0]
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                pending.pop(0)
                out.append(line)
                continue
            out.append(re.sub(r"[<>'\"`]" if quoted else r"['\"`]", "_", line))
            continue
        out.append(line)
        pending = [(bool(dash), bool(slash or quote), name) for dash, slash, quote, name in HEREDOC_RE.findall(line)]
    return "\n".join(out)


def _mask_quoted(text: str) -> str:
    """把引号内与转义的 `<` `>` 换成占位符，只用于提取重定向：`sed 's/></>/'`、`--body "a -> b"` 不是重定向。
    双引号内的 $(...) 与反引号仍是命令，按未加引号处理；重定向目标本身带引号时保持原样。"""
    text = _mask_heredocs(text)
    out, stack, index = [], ["top"], 0
    while index < len(text):
        char, state = text[index], stack[-1]
        if state == "single":
            if char == "'":
                stack.pop()
            out.append("_" if char in "<>" else char)
        elif char == "\\" and index + 1 < len(text):
            following = text[index + 1]
            out.append(char + ("_" if following in "<>" else following))
            index += 1
        elif state == "double":
            if char == '"':
                stack.pop()
                out.append(char)
            elif char == "$" and text[index + 1:index + 2] == "(":
                stack.append(0)
                out.append("$(")
                index += 1
            elif char == "`":
                stack.append("tick")
                out.append(char)
            else:
                out.append("_" if char in "<>" else char)
        else:
            if char == "'":
                stack.append("single")
            elif char == '"':
                stack.append("double")
            elif char == "`" and state == "tick":
                stack.pop()
            elif char == "`":
                stack.append("tick")
            elif char == "$" and text[index + 1:index + 2] == "(":
                stack.append(0)
                out.append("$")
                index += 1
                char = "("
            elif isinstance(state, int) and char == "(":
                stack[-1] += 1
            elif isinstance(state, int) and char == ")":
                if state:
                    stack[-1] -= 1
                else:
                    stack.pop()
            out.append(char)
        index += 1
    return "".join(out)


def expand_command(cmd: str) -> list[NormalizedCall]:
    """把 shell 命令展开为 EXEC 主能力 + 读取/写入/出网子能力。

    解析不追求完备（变量拼接、脚本间接执行无法静态还原），目标是把常见确定性形态
    在执行前识别出来；漏报由出网防护兜底。
    """
    text = str(cmd or "")
    network = False
    subcalls: list[NormalizedCall] = []

    # 引号 / heredoc 正文里的 `>` 多半不是重定向（sed 表达式、PR 描述），但 eval、find -exec sh -c 等
    # 会执行引号里的命令：仍按写入展开，来源标为 QUOTED_REDIRECT，只在“工作区外写入”判定中忽略。
    certain = Counter(REDIRECT_RE.findall(_mask_quoted(text)))
    for target in REDIRECT_RE.findall(text):
        if target not in ("/dev/null", "&1", "&2") and not target.startswith("&"):
            origin = "bash:redirect" if certain[target] > 0 else QUOTED_REDIRECT
            certain[target] -= 1
            # `> "$HOME/.bashrc"`、`sh -c 'echo y >> ~/.bashrc'`：目标带着引号被截取，去掉后才能按路径判定。
            subcalls.append(NormalizedCall(FILE_WRITE, normalize_path(target.strip("'\"`")), origin=origin))
    for source in INPUT_REDIRECT_RE.findall(text):
        subcalls.append(NormalizedCall(FILE_READ, normalize_path(source), origin="bash:redirect"))

    for dollar, backtick in SUBSTITUTION_RE.findall(text):
        inner = expand_command(dollar or backtick)
        network = network or inner[0].sink
        # 重定向与 URL 按整条命令另行提取，这里只取内层命令本身的读写。
        subcalls.extend(call for call in inner[1:] if call.origin not in ("bash:url", "bash:redirect", QUOTED_REDIRECT))

    interpreter, code_texts = "", [text]
    for segment in SEGMENT_SPLIT_RE.split(BRACED_VAR_RE.sub(r"$\1", text)):
        tokens = _strip_wrappers(_tokens(REDIRECT_RE.sub(" ", segment)))
        if not tokens:
            continue
        name = _command_name(tokens[0])
        args = tokens[1:]
        if name in SHELL_COMMANDS:
            flags = [index for index, arg in enumerate(args) if arg.lower() in SHELL_INLINE_FLAGS]
            if flags and flags[0] + 1 < len(args):
                inner = expand_command(" ".join(args[flags[0] + 1:]))
                network = network or inner[0].sink
                subcalls.extend(call for call in inner[1:] if call.origin != "bash:url")
                continue
        subcalls.extend(_windows_persistence(name, args))
        if re.sub(r"[0-9.]+$", "", name) in INTERPRETERS or name in INTERPRETERS:
            interpreter = interpreter or name
            code_texts.extend(args)   # shlex 去掉外层引号后，内联代码里的字面量才可见
        if name in NETWORK_COMMANDS or (name == "git" and args and args[0] in GIT_NETWORK_SUBCOMMANDS):
            network = True
        if name == "certutil" and any(arg.lower() in ("-urlcache", "/urlcache") for arg in args):
            network = True
        if name in ("curl", "wget"):
            # curl -d @file / --data-binary @file / -T file / -F x=@file 读取本地文件并外发
            for arg in args:
                match = re.search(r"@([^\s;'\"]+)$", arg)
                if match and match.group(1) != "-":
                    subcalls.append(NormalizedCall(FILE_READ, normalize_path(match.group(1)), origin="bash:upload"))
        if name in READ_COMMANDS:
            for path in _path_args(args if name not in ("jq", "yq") else args[1:]):
                subcalls.append(NormalizedCall(FILE_READ, normalize_path(path), origin=f"bash:{name}"))
        elif name in GREP_COMMANDS:
            for path in _path_args(args)[1:]:
                subcalls.append(NormalizedCall(FILE_READ, normalize_path(path), origin=f"bash:{name}"))
        elif name in ("sed", "perl") and any(re.match(r"^-[A-Za-z]*i", arg) for arg in args):
            for path in _path_args(args)[1:]:
                subcalls.append(NormalizedCall(FILE_WRITE, normalize_path(path), origin=f"bash:{name}"))
        elif name in WRITE_COMMANDS and not any(REGISTRY_RE.match(arg) for arg in args):
            for path in _path_args(args):
                subcalls.append(NormalizedCall(FILE_WRITE, normalize_path(path), origin=f"bash:{name}"))
        elif name in DEST_COMMANDS:
            paths = [normalize_path(path) for path in _path_args(args)]
            if len(paths) >= 2:
                for path in paths[:-1]:
                    if not _remote(path):
                        subcalls.append(NormalizedCall(FILE_READ, path, origin=f"bash:{name}"))
                if not _remote(paths[-1]):
                    subcalls.append(NormalizedCall(FILE_WRITE, paths[-1], origin=f"bash:{name}"))
        elif name == "crontab" and args and args[0] != "-l":
            subcalls.append(NormalizedCall(FILE_WRITE, "/var/spool/cron/crontab", origin="bash:crontab"))

    if interpreter:
        # heredoc 正文与含 `;` 的内联代码会被分段切开，再按整条命令的 shlex 结果扫描一次。
        code_texts.extend(_tokens(text))
        subcalls.extend(_inline_code_calls(code_texts, interpreter))

    for url in URL_RE.findall(text):
        network = True
        subcalls.append(NormalizedCall(NET_FETCH, url, content=text, sink=True, origin="bash:url"))

    return [NormalizedCall(EXEC, text, content=text, sink=network, origin="bash")] + subcalls
