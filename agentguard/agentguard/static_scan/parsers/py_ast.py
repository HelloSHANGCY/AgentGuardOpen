"""Python AST 解析：import 别名、模块常量、函数、工具/服务声明。

只解析不导入、不执行目标代码。解析失败（语法错误、超深嵌套、解码超限）
记录为 parse_error，由调用方计入覆盖缺口。
"""

import ast
from dataclasses import dataclass, field

from ..analysis.decode import ConstValue, DecodeBudget, Decoder, resolve_name


@dataclass
class PyImport:
    module: str = ""
    name: str = ""
    alias: str = ""
    lineno: int = 0
    is_from: bool = False


@dataclass
class ToolDecl:
    """`Tool(...)` 构造的静态声明。"""

    name: str = ""
    description: str = ""
    schema: dict = field(default_factory=dict)
    handler: str = ""
    hidden: bool = False
    lineno: int = 0
    var_name: str = ""


@dataclass
class ServerDecl:
    """`create_server(...)` 的静态声明：声明集合与 dispatch 能力。"""

    name: str = ""
    var_name: str = ""
    tool_vars: list = field(default_factory=list)
    on_start: str = ""
    lineno: int = 0


@dataclass
class PyModule:
    path: str
    source: str
    tree: object = None
    imports: list = field(default_factory=list)
    aliases: dict = field(default_factory=dict)
    constants: dict = field(default_factory=dict)
    functions: dict = field(default_factory=dict)
    module_assigns: dict = field(default_factory=dict)
    tool_decls: list = field(default_factory=list)
    server_decls: list = field(default_factory=list)
    parse_error: str = ""
    decode_limit_hit: bool = False

    def function_names(self) -> list:
        return sorted(self.functions)

    def env_read(self, name: str) -> tuple | None:
        """模块常量中 `os.getenv("X", "default")` 的 (key, default)。"""
        node = self.module_assigns.get(name)
        if node is None:
            return None
        call = node.value if isinstance(node, ast.Assign) else node
        return getenv_info(call) if isinstance(call, ast.Call) else None


def getenv_info(call) -> tuple | None:
    """解析 `os.getenv("X", "default")` / `os.environ.get(...)`。"""
    if not isinstance(call, ast.Call):
        return None
    func = call.func
    is_getenv = isinstance(func, ast.Attribute) and func.attr == "getenv"
    is_environ_get = (isinstance(func, ast.Attribute) and func.attr == "get"
                      and isinstance(func.value, ast.Attribute) and func.value.attr == "environ")
    if not (is_getenv or is_environ_get):
        return None
    if not call.args or not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str):
        return None
    key = call.args[0].value
    default = None
    if len(call.args) > 1 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        default = call.args[1].value
    for kw in call.keywords:
        if kw.arg in ("default",) and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            default = kw.value.value
    return key, default


def parse_python(path: str, source: str, budget: DecodeBudget = None) -> PyModule:
    module = PyModule(path=path, source=source)
    try:
        module.tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        module.parse_error = f"ast:{exc.__class__.__name__}"
        return module

    _collect_imports(module)
    decoder = Decoder(budget)
    consts = dict(module.constants)
    for statement in module.tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    module.module_assigns[target.id] = statement
                    value = decoder.evaluate(statement.value, consts)
                    if value is not None and value.kind != "unknown":
                        module.constants[target.id] = value
                        consts[target.id] = value
                    elif _is_decode_limit(value):
                        module.decode_limit_hit = True
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            module.module_assigns[statement.target.id] = statement
            value = decoder.evaluate(statement.value, consts)
            if value is not None and value.kind != "unknown":
                module.constants[statement.target.id] = value
                consts[statement.target.id] = value
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            module.functions[statement.name] = statement

    _collect_declarations(module, decoder)
    return module


def _is_decode_limit(value: ConstValue | None) -> bool:
    return value is not None and not value.proven and str(value.transform).startswith("decode_")


def _collect_imports(module: PyModule) -> None:
    aliases = module.aliases
    for statement in module.tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".")[0]
                # `import a.b` 绑定包名 a，属性链再解析出 a.b；`import a.b as c` 直接绑定 a.b。
                aliases[local] = alias.name if alias.asname else local
                module.imports.append(PyImport(module=alias.name, alias=local, lineno=statement.lineno))
        elif isinstance(statement, ast.ImportFrom):
            base = statement.module or ""
            for alias in statement.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                aliases[local] = f"{base}.{alias.name}" if base else alias.name
                module.imports.append(PyImport(module=base, name=alias.name, alias=local,
                                               lineno=statement.lineno, is_from=True))


def _iter_calls_outside_functions(node):
    """收集模块级调用（跳过函数体，函数内调用由数据流在函数摘要中处理）。"""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return
    if isinstance(node, ast.Call):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_calls_outside_functions(child)


def _collect_declarations(module: PyModule, decoder: Decoder) -> None:
    tools_by_var: dict = {}
    server_calls: list = []

    for statement in module.tree.body:
        if not isinstance(statement, ast.Assign):
            continue
        target = statement.targets[0] if len(statement.targets) == 1 else None
        if not isinstance(target, ast.Name):
            continue
        if not isinstance(statement.value, ast.Call):
            continue
        callee = resolve_name(statement.value.func, module.aliases) or ""
        if callee.endswith("Tool"):
            decl = parse_tool_call(statement.value, module, decoder, target.id)
            if decl and decl.name:
                tools_by_var[target.id] = decl
        elif callee.endswith("create_server"):
            server_calls.append((statement.value, target.id))

    # 内联 `create_server(name, [Tool(...)])` 形态。
    for call in _iter_calls_outside_functions(module.tree):
        callee = resolve_name(call.func, module.aliases) or ""
        if callee.endswith("create_server") and not any(call is item[0] for item in server_calls):
            server_calls.append((call, ""))

    for call, var_name in server_calls:
        decl = parse_server_call(call, module, decoder, var_name, tools_by_var)
        if decl and decl.name:
            module.server_decls.append(decl)

    for decl in tools_by_var.values():
        if not any(tool.name == decl.name and tool.lineno == decl.lineno for tool in module.tool_decls):
            module.tool_decls.append(decl)


def parse_tool_call(call, module: PyModule, decoder: Decoder, var_name: str = "") -> ToolDecl | None:
    if not isinstance(call, ast.Call):
        return None
    decl = ToolDecl(lineno=getattr(call, "lineno", 0), var_name=var_name)
    consts = dict(module.constants)
    positional = call.args

    def const_at(index):
        if index < len(positional):
            value = decoder.evaluate(positional[index], consts)
            return value.value if value and value.proven else None
        return None

    name = const_at(0)
    description = const_at(1)
    schema = const_at(2)
    handler_node = positional[3] if len(positional) > 3 else None
    for keyword in call.keywords:
        if keyword.arg == "name":
            value = decoder.evaluate(keyword.value, consts)
            name = value.value if value and value.proven else name
        elif keyword.arg == "description":
            value = decoder.evaluate(keyword.value, consts)
            description = value.value if value and value.proven else description
        elif keyword.arg == "schema":
            value = decoder.evaluate(keyword.value, consts)
            schema = value.value if value and value.proven else schema
        elif keyword.arg == "handler":
            handler_node = keyword.value
        elif keyword.arg == "hidden":
            value = decoder.evaluate(keyword.value, consts)
            decl.hidden = bool(value.value) if value else False
    decl.name = name if isinstance(name, str) else ""
    decl.description = description if isinstance(description, str) else ""
    decl.schema = schema if isinstance(schema, dict) else {}
    if handler_node is not None:
        decl.handler = resolve_name(handler_node, module.aliases) or ""
        if "." in decl.handler:
            decl.handler = decl.handler.rsplit(".", 1)[-1]
    return decl


def parse_server_call(call, module: PyModule, decoder: Decoder, var_name: str,
                      tools_by_var: dict) -> ServerDecl | None:
    decl = ServerDecl(lineno=getattr(call, "lineno", 0), var_name=var_name)
    consts = dict(module.constants)
    name = None
    if call.args:
        value = decoder.evaluate(call.args[0], consts)
        name = value.value if value and value.proven else None
    tools_arg = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "name":
            value = decoder.evaluate(keyword.value, consts)
            name = value.value if value and value.proven else name
        elif keyword.arg == "tools":
            tools_arg = keyword.value
        elif keyword.arg == "on_start":
            decl.on_start = resolve_name(keyword.value, module.aliases) or ""
            if "." in decl.on_start:
                decl.on_start = decl.on_start.rsplit(".", 1)[-1]
    decl.name = name if isinstance(name, str) else ""
    if isinstance(tools_arg, (ast.List, ast.Tuple)):
        for item in tools_arg.elts:
            if isinstance(item, ast.Name) and item.id in tools_by_var:
                decl.tool_vars.append(item.id)
            elif isinstance(item, ast.Call) and (resolve_name(item.func, module.aliases) or "").endswith("Tool"):
                inline = parse_tool_call(item, module, decoder)
                if inline and inline.name:
                    module.tool_decls.append(inline)
    return decl


def resolve_call(module: PyModule, node) -> str:
    return resolve_name(node, module.aliases) or ""


def function_source(module: PyModule, node) -> list:
    """函数体语句列表（用于数据流），失败返回空。"""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    return list(node.body)


def line_excerpt(source: str, lineno: int, limit: int = 160) -> str:
    lines = source.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:limit]
    return ""
