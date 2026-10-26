"""设备静态快照协议：固定采集范围、资源限额与上传前脱敏（仅标准库）。"""

import ast
import io
import json
import re
import tokenize

PROTOCOL = "agent-assets-v1"
MAX_FILES = 1000
MAX_FILE_BYTES = 256 * 1024
MAX_CONFIGURABLE_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 12
LEASE_SECONDS = 120
WAIT_SECONDS = 24 * 60 * 60
SCOPES = ("user", "user_project")


def snapshot_file_limit(limits=None):
    """管理端指定的单文件限额；旧任务保留 256 KiB 默认值。"""
    if limits is None:
        limits = {}
    if not isinstance(limits, dict) or set(limits) - {"max_file_parse_bytes"}:
        raise ValueError("invalid device scan limits")
    value = limits.get("max_file_parse_bytes", MAX_FILE_BYTES)
    if type(value) is not int or not MAX_FILE_BYTES <= value <= MAX_CONFIGURABLE_FILE_BYTES:
        raise ValueError("单文件大小限额须为 256–2048 KiB（262144–2097152 字节）的整数")
    return value


AGENT_DIRS = {
    "claude-code": (".claude",),
    "codex": (".codex", ".agents"),
    "trae": (".trae-cn", ".trae"),
    "qoder": (".qoder", ".qoder-cn", ".lingma"),
    "zcode": (".zcode",),
    "workbuddy": (".workbuddy", ".workbuddy-ai"),
    "codebuddy": (".codebuddy",),
}
CONFIG_FILES = {"settings.json", "settings.local.json", "hooks.json", "config.json", "config.toml",
                "mcp.json", ".mcp.json", "mcp_config.json", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"}
ASSET_DIRS = {"skills", "commands", "agents", "rules", "mcp"}
TEXT_SUFFIXES = {".md", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".json", ".yaml", ".yml",
                 ".toml", ".sh", ".ps1", ".bash", ".txt", ".ini", ".cfg"}
EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".cache"}
SECRET_MARKER = "AG_REDACTED_SECRET_VALUE"
SECRET_KEY = re.compile(r"secret|token|password|passwd|credential|api.?key|access.?key|private.?key|authorization|cookie|dsn", re.I)
REFERENCE = re.compile(r"^(?:\$\{[^}]+\}|\$[A-Za-z_][\w]*|\$env:[\w]+|env:[\w]+)$", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")
BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
TOKEN = re.compile(r"\b(?:sk-|gh[pousr]_|github_pat_)[A-Za-z0-9_-]{12,}")
URL_AUTH = re.compile(r"(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}://)[^/\s:@]+:[^@/\s]+@")
URL_SECRET = re.compile(r"(?i)([?&](?:api[_-]?key|token|secret|password|access_token)=)[^\s&#\"']+")
ASSIGNMENT = re.compile(
    r"(?i)(\b[\w.-]*(?:secret|token|password|passwd|credential|api[_-]?key|access[_-]?key|authorization|cookie|dsn)[\w.-]*"
    r"[\"']?\s*[:=]\s*)(\"(?:\\.|[^\"\\])*\"|'[^']*'|[^\s,;}\]\r\n]+)")


def allowed_path(agent: str, path: str) -> bool:
    """快照只允许 user/ 或 project/ 内、选定 Agent 的固定相对路径。"""
    if not isinstance(path, str) or len(path) > 512 or "\\" in path or ":" in path:
        return False
    parts = path.split("/")
    if len(parts) < 2 or any(part in ("", ".", "..") or any(ord(ch) < 32 or 0xD800 <= ord(ch) <= 0xDFFF for ch in part) for part in parts):
        return False
    if parts[0] not in ("user", "project") or len(parts) > MAX_DEPTH + 4:
        return False
    rest = parts[1:]
    if agent == "claude-code" and rest in ([".claude.json"], [".mcp.json"], ["CLAUDE.md"], ["CLAUDE.local.md"]):
        return True
    if agent == "codex" and rest == ["AGENTS.md"]:
        return True
    if rest[0] not in AGENT_DIRS.get(agent, ()) or len(rest) < 2:
        return False
    if agent == "zcode" and rest == [".zcode", "cli", "config.json"]:
        return True
    if len(rest) == 2:
        return rest[1] in CONFIG_FILES
    return (rest[1] in ASSET_DIRS and not any(part in EXCLUDED_DIRS for part in rest[2:-1])
            and any(rest[-1].lower().endswith(suffix) for suffix in TEXT_SUFFIXES)
            and rest[-1].lower() not in {"auth.json", "credentials.json"})


def _mask_value(value):
    if not isinstance(value, str) or not value.strip() or REFERENCE.fullmatch(value.strip()):
        return value
    return SECRET_MARKER


def _mask_json(value, key="", depth=0):
    if depth > 32:
        raise ValueError("configuration nesting limit exceeded")
    if isinstance(value, dict):
        return {k: _mask_json(v, "authorization" if key.lower() == "headers" else k, depth + 1)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_json(v, "authorization" if index and isinstance(value[index - 1], str)
                           and value[index - 1].startswith("--") and SECRET_KEY.search(value[index - 1]) else key,
                           depth + 1) for index, v in enumerate(value)]
    if isinstance(value, str):
        return _mask_value(value) if SECRET_KEY.search(key) else _mask_string(value)
    return value


def _mask_string(text):
    text = PRIVATE_KEY.sub(SECRET_MARKER, text)
    text = BEARER.sub(r"\1" + SECRET_MARKER, text)
    text = JWT.sub(SECRET_MARKER, text)
    text = TOKEN.sub(SECRET_MARKER, text)
    text = URL_AUTH.sub(r"\1" + SECRET_MARKER + "@", text)
    text = URL_SECRET.sub(r"\1" + SECRET_MARKER, text)

    def assignment(match):
        raw = match[2]
        quote = raw[0] if raw.startswith(('"', "'")) else ""
        value = raw[1:-1] if quote else raw
        masked = _mask_value(value)
        return match[1] + quote + masked + quote

    return ASSIGNMENT.sub(assignment, text)


def _python_secret_literals(tree):
    """只标记敏感值中的字符串；变量、调用、条件和设计 token 的表达式保持原样。"""
    sensitive = set()

    def mark(node):
        if isinstance(node, (ast.Constant, ast.JoinedStr)):
            sensitive.add(id(node))
        elif isinstance(node, ast.Dict):
            for value in node.values:
                mark(value)
        elif isinstance(node, ast.Subscript):
            mark(node.value)  # 下标是字段名，不是凭证值。
        elif isinstance(node, ast.Call):
            func = node.func
            lookup = isinstance(func, ast.Attribute) and func.attr in ("getenv", "get")
            for arg in node.args[1:] if lookup else node.args:
                mark(arg)
            for kw in node.keywords:
                mark(kw.value)
        elif node is not None:
            for child in ast.iter_child_nodes(node):
                mark(child)

    def secret_target(node):
        return any(SECRET_KEY.search(getattr(item, "id", "") or getattr(item, "attr", "")
                                     or (item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else ""))
                   for item in ast.walk(node))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(secret_target(target) for target in node.targets):
            mark(node.value)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and secret_target(node.target):
            mark(node.value)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if SECRET_KEY.search(key.value) or key.value.lower() == "headers":
                        mark(value)
        elif isinstance(node, ast.keyword) and node.arg and (SECRET_KEY.search(node.arg) or node.arg.lower() == "headers"):
            mark(node.value)
        elif isinstance(node, ast.arguments):
            positional = node.posonlyargs + node.args
            defaults = zip(positional[len(positional) - len(node.defaults):], node.defaults)
            for arg, default in list(defaults) + list(zip(node.kwonlyargs, node.kw_defaults)):
                if SECRET_KEY.search(arg.arg):
                    mark(default)
        elif isinstance(node, (ast.List, ast.Tuple)):
            for previous, value in zip(node.elts, node.elts[1:]):
                if (isinstance(previous, ast.Constant) and isinstance(previous.value, str)
                        and previous.value.startswith("--") and SECRET_KEY.search(previous.value)):
                    mark(value)
    return sensitive


def _sanitize_python(text):
    """AST 定位字面量后按原位置替换，不对 Python 表达式运行赋值正则。"""
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line.encode("utf-8")))
    raw = text.encode("utf-8")
    changes = []

    def replace(start, end, value):
        original = raw[start:end].decode("utf-8")
        rendered = repr(value)
        # 多行字面量仍占相同行数，保留后续证据的行号。
        if "\n" in original:
            rendered = "(" + rendered + "\n" * original.count("\n") + ")"
        changes.append((start, end, rendered.encode("utf-8")))

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        tree = None
    sensitive = _python_secret_literals(tree) if tree else set()

    class Literals(ast.NodeVisitor):
        def visit_Constant(self, node):
            if not isinstance(node.value, (str, bytes)):
                return
            binary = isinstance(node.value, bytes)
            value = node.value.decode("latin-1") if binary else node.value
            masked = _mask_value(value) if id(node) in sensitive else _mask_string(value)
            if masked != value:
                replace(offsets[node.lineno - 1] + node.col_offset,
                        offsets[node.end_lineno - 1] + node.end_col_offset,
                        masked.encode("latin-1") if binary else masked)

        def visit_JoinedStr(self, node):
            # f-string 内的 AST 文本节点不具备独立源码范围；有凭证时掩码整个值。
            if id(node) in sensitive or any(isinstance(part, ast.Constant) and isinstance(part.value, str)
                                           and _mask_string(part.value) != part.value for part in node.values):
                replace(offsets[node.lineno - 1] + node.col_offset,
                        offsets[node.end_lineno - 1] + node.end_col_offset, SECRET_MARKER)
            else:
                for part in node.values:
                    if isinstance(part, ast.FormattedValue):
                        self.visit(part)

    if tree:
        Literals().visit(tree)
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                masked = _mask_string(token.string)
                if masked != token.string:
                    start = offsets[token.start[0] - 1] + len(lines[token.start[0] - 1][:token.start[1]].encode("utf-8"))
                    end = start + len(token.string.encode("utf-8"))
                    if not any(left <= start and end <= right for left, right, _ in changes):
                        changes.append((start, end, masked.encode("utf-8")))
            elif tree is None:
                # 原文语法不兼容时保守掩码所有字符串；不修复或隐藏原有语法错误。
                if token.type == tokenize.STRING:
                    value = ast.literal_eval(token.string)
                    start = offsets[token.start[0] - 1] + len(lines[token.start[0] - 1][:token.start[1]].encode("utf-8"))
                    end = offsets[token.end[0] - 1] + len(lines[token.end[0] - 1][:token.end[1]].encode("utf-8"))
                    replace(start, end, SECRET_MARKER.encode() if isinstance(value, bytes) else SECRET_MARKER)
                elif (token.type == tokenize.ERRORTOKEN and not token.string.isspace()
                      or tokenize.tok_name.get(token.type, "").startswith("FSTRING")):
                    raise ValueError("unsupported Python syntax")
    except (tokenize.TokenError, SyntaxError, IndentationError) as exc:
        raise ValueError("unsupported Python syntax") from exc
    for start, end, replacement in sorted(changes, reverse=True):
        raw = raw[:start] + replacement + raw[end:]
    result = raw.decode("utf-8")
    if tree:
        ast.parse(result)  # 脱敏不能将原本合法的 Python 变成不可解析的源码。
    return result


def sanitize_text(path: str, text: str) -> str:
    """重复执行结果不变；保留配置结构、引用与风险命令，掩码凭证字面量。"""
    if path.lower().endswith(".py"):
        return _sanitize_python(text)
    if path.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            raise ValueError("invalid JSON configuration") from None
        if path.endswith("/.claude.json") and isinstance(data, dict):
            # ~/.claude.json 还包含历史项目、账号与登录元数据，只采集全局 MCP 声明。
            data = {"mcpServers": data.get("mcpServers", {})}
        return json.dumps(_mask_json(data), ensure_ascii=False, indent=2)
    # TOML/Python 的跨行凭证不能只掩码首行；未知格式保持结构，先处理完整引号块。
    multiline = re.compile(r"(?is)(\b[\w.-]*(?:secret|token|password|credential|api_key)[\w.-]*\s*[:=]\s*)"
                           r"(\"\"\"|''')(.*?)(\2)")
    text = multiline.sub(lambda match: match[1] + match[2] + SECRET_MARKER + match[2], text)
    return _mask_string(text)
