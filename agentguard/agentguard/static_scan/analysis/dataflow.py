"""有界 Python 数据流分析。

- source：os.environ/getenv、敏感文件读取、工具/函数外部参数、网络拉取；
- transform：赋值、f-string、容器字段、编码/解码、未知函数调用；
- sink：网络发送、命令执行、动态代码执行；
- 每一步标明 proven / inferred / unresolved；未知变换保留线索但不标成已证实路径；
- 默认深度 3、每个入口最多 200 条候选路径，递归/反射/动态 import 记 unresolved。
"""

import ast
from dataclasses import dataclass, field

from ...core.normalize import is_sensitive_path
from ..models import FlowStep
from .decode import ConstValue, DecodeBudget, Decoder, resolve_name

SENSITIVE_ENV_HINTS = ("SECRET", "TOKEN", "KEY", "PASSWORD", "PASSWD", "CREDENTIAL",
                       "AUTH", "PRIVATE", "SIGNING", "DSN", "DATABASE_URL", "WEBHOOK")

NETWORK_MODULES = {
    "requests", "httpx", "aiohttp", "urllib.request", "urllib3", "http.client",
    "socket", "websocket", "websockets", "httplib2",
}
NETWORK_FUNCS = {
    "get", "post", "put", "patch", "delete", "head", "options", "request",
    "urlopen", "urlretrieve", "send", "sendall", "sendto", "connect",
}

COMMAND_MODULES = {"subprocess", "os"}
COMMAND_FUNCS = {
    "run", "popen", "Popen", "call", "check_call", "check_output", "system",
    "execv", "execve", "execvp", "execl", "execlp", "execvpe", "spawnv", "spawnl",
}

DYNAMIC_FUNCS = {"eval", "exec", "compile", "__import__"}
DYNAMIC_MODULES = {"importlib", "builtins"}
DYNAMIC_MODULE_FUNCS = {"import_module", "reload"}

GUARD_MARKERS = ("allowlist", "allowed", "whitelist", "safe_list", "permitted")


@dataclass
class Taint:
    source_kind: str = ""  # parameter / env / env_container / file / network / decoded / global / constant / unknown
    source_ref: str = ""
    sensitive: bool = False
    external: bool = False
    status: str = "proven"
    steps: list = field(default_factory=list)
    const: ConstValue = None
    guard: str = ""

    def step(self) -> list:
        return list(self.steps)

    def clone(self) -> "Taint":
        return Taint(source_kind=self.source_kind, source_ref=self.source_ref, sensitive=self.sensitive,
                     external=self.external, status=self.status, steps=list(self.steps),
                     const=self.const, guard=self.guard)


@dataclass
class FlowRecord:
    source_kind: str
    source_ref: str
    sensitive: bool
    external: bool
    sink: str
    sink_category: str
    lineno: int = 0
    status: str = "proven"
    steps: list = field(default_factory=list)
    call_text: str = ""
    decoded_value: str = ""
    kwargs: dict = field(default_factory=dict)
    guard: str = ""
    param_ref: str = ""

    def as_dict(self) -> dict:
        return {
            "source_kind": self.source_kind, "source_ref": self.source_ref,
            "sensitive": self.sensitive, "external": self.external,
            "sink": self.sink, "sink_category": self.sink_category,
            "lineno": self.lineno, "status": self.status,
            "steps": [step.as_dict() if hasattr(step, "as_dict") else step for step in self.steps],
            "call_text": self.call_text, "decoded_value": self.decoded_value,
            "kwargs": dict(self.kwargs), "guard": self.guard,
        }


@dataclass
class CallSite:
    path: str
    lineno: int
    args: dict = field(default_factory=dict)  # param name / index -> Taint
    kwargs: dict = field(default_factory=dict)
    text: str = ""

    def as_dict(self) -> dict:
        return {"path": self.path, "lineno": self.lineno, "text": self.text}


@dataclass
class FunctionSummary:
    module: str
    name: str
    lineno: int = 0
    params: list = field(default_factory=list)
    returns: Taint = None
    flows: list = field(default_factory=list)
    call_sites: list = field(default_factory=list)
    aliases: dict = field(default_factory=dict)
    taints: dict = field(default_factory=dict)
    dynamic: bool = True
    unresolved: list = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.module}:{self.name}"


def sink_category(path: str) -> tuple:
    """返回 (类别, 规范化名称)；不是 sink 返回 ('', '')。"""
    if not path:
        return "", ""
    parts = path.split(".")
    base = parts[-1]
    module = ".".join(parts[:-1])
    if module in NETWORK_MODULES and base in NETWORK_FUNCS:
        return "network", path
    if module in COMMAND_MODULES and base in COMMAND_FUNCS:
        return "command", path
    if base in DYNAMIC_FUNCS and (not module or module in DYNAMIC_MODULES):
        return "dynamic_code", path
    if module in DYNAMIC_MODULES and base in DYNAMIC_MODULE_FUNCS:
        return "dynamic_code", path
    if module == "pickle" and base in ("load", "loads"):
        return "dynamic_code", path
    return "", ""


def is_sensitive_env_name(name: str) -> bool:
    upper = str(name or "").upper()
    return any(hint in upper for hint in SENSITIVE_ENV_HINTS)


def _worst_status(statuses) -> str:
    order = {"proven": 0, "inferred": 1, "unresolved": 2}
    worst = "proven"
    for status in statuses:
        if order.get(status, 2) > order.get(worst, 0):
            worst = status
    return worst


def merge_taints(taints) -> Taint | None:
    items = [taint for taint in taints if taint is not None]
    if not items:
        return None
    if len(items) == 1:
        return items[0].clone()
    best = sorted(items, key=lambda item: (item.sensitive, item.external,
                                           item.source_kind != "unknown"), reverse=True)[0]
    merged = best.clone()
    merged.status = _worst_status(item.status for item in items)
    seen = {(step.kind, step.location, step.detail) for step in merged.steps}
    for item in items:
        for step in item.steps:
            key = (step.kind, step.location, step.detail)
            if key not in seen:
                merged.steps.append(step)
                seen.add(key)
    if merged.const is None:
        consts = [item.const for item in items if item.const is not None]
        merged.const = consts[0] if len(consts) == 1 else None
    return merged


class Analyzer:
    """函数级分析器；模块级分析用 is_module=True 复用同一套逻辑。"""

    def __init__(self, module, node, budget: DecodeBudget, limits=None,
                 name: str = "<module>", globals_taint: dict = None):
        self.module = module
        self.node = node
        self.budget = budget
        self.limits = limits
        self.name = name
        self.summary = FunctionSummary(module=module.path, name=name,
                                       lineno=getattr(node, "lineno", 0) or 0)
        self.decoder = Decoder(budget)
        self.env: dict = dict(globals_taint or {})
        self.consts: dict = dict(module.constants)
        self.aliases: dict = dict(module.aliases)
        self.guards: set = set()
        self._max_calls = int(getattr(limits, "max_calls_per_function", 50))
        self._max_paths = int(getattr(limits, "max_paths_per_entry", 200))
        self.current_line = 0
        if not isinstance(node, ast.Module):
            self._seed_params(node)

    # ---- 参数与默认别名 ----

    def _seed_params(self, node) -> None:
        args = node.args
        positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
        defaults = list(args.defaults)
        default_offset = len(positional) - len(defaults)
        for index, arg in enumerate(positional):
            taint = Taint(source_kind="parameter", source_ref=arg.arg, external=True,
                          steps=[FlowStep(kind="source", status="proven", location=self._loc(node.lineno),
                                          detail=f"参数 {arg.arg} 由调用方提供")])
            self.env[arg.arg] = taint
            self.summary.params.append(arg.arg)
            if index >= default_offset:
                default_node = defaults[index - default_offset]
                self._bind_default(arg.arg, default_node)
        for arg in args.kwonlyargs:
            self.env[arg.arg] = Taint(source_kind="parameter", source_ref=arg.arg, external=True,
                                      steps=[FlowStep(kind="source", status="proven", location=self._loc(node.lineno),
                                                      detail=f"参数 {arg.arg} 由调用方提供")])
            self.summary.params.append(arg.arg)
        for arg, default_node in zip(args.kwonlyargs, args.kw_defaults):
            if default_node is not None:
                self._bind_default(arg.arg, default_node)

    def _bind_default(self, name: str, node) -> None:
        """`poster=httpx.post` 这类默认可调用参数解析成别名，才能定位真正 sink。"""
        path = resolve_name(node, self.aliases)
        if path and (
            (isinstance(node, ast.Attribute) and not isinstance(node.value, ast.Call))
            or isinstance(node, ast.Name)
        ):
            if "." in path or path in COMMAND_FUNCS | DYNAMIC_FUNCS:
                self.aliases[name] = path

    # ---- 语句遍历 ----

    def run(self) -> FunctionSummary:
        body = self.node.body if isinstance(self.node, (ast.FunctionDef, ast.AsyncFunctionDef)) else self.node.body
        try:
            self._run_body(body)
        except RecursionError:
            self.summary.unresolved.append("recursion_limit")
            self.summary.dynamic = False
        return self.summary

    def _run_body(self, statements) -> None:
        for statement in statements:
            self._handle_stmt(statement)

    def _handle_stmt(self, statement) -> None:
        if statement is None:
            return
        self.current_line = getattr(statement, "lineno", self.current_line)
        if isinstance(statement, ast.Assign):
            taint = self.eval(statement.value)
            for target in statement.targets:
                self._assign(target, taint)
        elif isinstance(statement, ast.AnnAssign):
            taint = self.eval(statement.value)
            self._assign(statement.target, taint)
        elif isinstance(statement, ast.AugAssign):
            value = self.eval(statement.value)
            self._assign(statement.target, merge_taints([self._lookup_target(statement.target), value]))
        elif isinstance(statement, ast.Expr):
            if isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
                return  # docstring
            self.eval(statement.value)
        elif isinstance(statement, ast.Return):
            value = self.eval(statement.value)
            self.summary.returns = merge_taints([self.summary.returns, value])
        elif isinstance(statement, ast.If):
            self._handle_if(statement)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            iter_taint = self.eval(statement.iter)
            loop_taint = self._loop_taint(iter_taint, statement)
            self._assign(statement.target, loop_taint)
            self._run_body(statement.body)
            self._run_body(statement.orelse)
        elif isinstance(statement, (ast.While,)):
            self.eval(statement.test)
            self._run_body(statement.body)
            self._run_body(statement.orelse)
        elif isinstance(statement, ast.Try):
            self._run_body(statement.body)
            for handler in statement.handlers:
                self._run_body(handler.body)
            self._run_body(statement.orelse)
            self._run_body(statement.finalbody)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                self.eval(item.context_expr)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, Taint(source_kind="unknown", status="unresolved"))
            self._run_body(statement.body)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".")[0]
                self.aliases[local] = alias.name if alias.asname else local
        elif isinstance(statement, ast.ImportFrom):
            base = statement.module or ""
            for alias in statement.names:
                if alias.name != "*":
                    self.aliases[alias.asname or alias.name] = f"{base}.{alias.name}" if base else alias.name
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # 嵌套函数单独摘要；此处只登记别名，避免路径遗漏。
            self.summary.unresolved.append(f"nested_function:{statement.name}")
        elif isinstance(statement, (ast.Pass, ast.Delete, ast.Global, ast.Nonlocal, ast.Assert, ast.Raise)):
            return
        elif isinstance(statement, (ast.Break, ast.Continue)):
            return
        else:
            # 未知语句：保守标记动态。
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.expr):
                    self.eval(child)

    def _handle_if(self, statement) -> None:
        self._detect_guards(statement.test)
        self.eval(statement.test)
        self._run_body(statement.body)
        self._run_body(statement.orelse)

    def _detect_guards(self, test) -> None:
        """识别 `cmd not in allowlist` / `cmd in {..}` 形式的成员白名单约束。"""
        if not isinstance(test, ast.Compare):
            return
        for index, op in enumerate(test.ops):
            if not isinstance(op, (ast.In, ast.NotIn)):
                continue
            left = test.left if index == 0 else test.comparators[index - 1]
            right = test.comparators[index]
            name = left.id if isinstance(left, ast.Name) else None
            if name is None:
                continue
            if isinstance(right, (ast.Name, ast.Set, ast.List, ast.Tuple, ast.Dict)):
                if isinstance(right, ast.Name):
                    marker = right.id.lower()
                    if not any(part in marker for part in GUARD_MARKERS):
                        # allowlist 常量也可能叫别的名字；若为字符串集合仍视为约束。
                        const = self.consts.get(right.id)
                        if not (const and isinstance(const.value, (set, list, tuple, dict))):
                            continue
                self.guards.add(name)

    def _loop_taint(self, iter_taint: Taint | None, statement) -> Taint:
        if iter_taint is None:
            return Taint(source_kind="unknown", status="unresolved")
        taint = iter_taint.clone()
        if taint.source_kind in ("env_container", "env"):
            taint.source_kind = "env"
            taint.source_ref = "env:sensitive_keys" if self._has_sensitive_filter(statement) else "env:keys"
            taint.sensitive = True
            taint.external = True
            if self._has_sensitive_filter(statement):
                taint.steps.append(FlowStep(kind="transform", status="proven",
                                            location=self._loc(getattr(statement, "lineno", 0)),
                                            detail="按敏感键名过滤环境变量"))
        return taint

    def _has_sensitive_filter(self, statement) -> bool:
        for node in ast.walk(statement):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.upper() in SENSITIVE_ENV_HINTS or is_sensitive_env_name(node.value):
                    return True
        return False

    def _assign(self, target, taint: Taint | None) -> None:
        if isinstance(target, ast.Name):
            if taint is not None and taint.source_kind == "function":
                self.aliases[target.id] = taint.source_ref
                return
            self.env[target.id] = taint
            if target.id in self.guards and taint is not None:
                taint.guard = "membership"
        elif isinstance(target, (ast.Tuple, ast.List)):
            if taint is not None:
                for element in target.elts:
                    self._assign(element, taint)
        elif isinstance(target, ast.Subscript):
            base = self._lookup_target(target.value)
            self.eval(target.slice)
            if base is not None:
                base.status = _worst_status([base.status, "inferred"])
        # 属性/下标写入不做精准追踪。

    def _lookup_target(self, target):
        if isinstance(target, ast.Name):
            return self.env.get(target.id)
        if isinstance(target, ast.Attribute):
            return self.eval(target)
        if isinstance(target, ast.Subscript):
            return self.eval(target)
        return None

    # ---- 表达式求值 ----

    def eval(self, node) -> Taint | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return Taint(source_kind="constant", const=Decoder._constant(node.value))
        if isinstance(node, ast.Name):
            if node.id in self.env:
                return self.env[node.id]
            if node.id in self.consts:
                const = self.consts[node.id]
                if getattr(const, "chain", None):
                    return Taint(source_kind="decoded", source_ref=const.transform or "decode",
                                 steps=list(const.chain), const=const, status="proven")
                return Taint(source_kind="constant", const=const)
            if node.id in self.aliases:
                return Taint(source_kind="function", source_ref=self.aliases[node.id])
            if node.id in ("True", "False", "None"):
                return Taint(source_kind="constant")
            return Taint(source_kind="unknown", status="unresolved")
        if isinstance(node, ast.Attribute):
            value = self.eval(node.value)
            if node.attr == "environ" and isinstance(node.value, ast.Name) and node.value.id == "os":
                return Taint(source_kind="env_container", source_ref="os.environ", sensitive=True,
                             external=True, steps=[FlowStep(kind="source", status="proven",
                                                            location=self._loc(node.lineno),
                                                            detail="os.environ 全量环境")])
            if value is not None and value.source_kind == "unknown":
                value.status = "unresolved"
            return value
        if isinstance(node, ast.Subscript):
            base = self.eval(node.value)
            index = self.eval(node.slice)
            if base is not None and base.source_kind == "env_container" and index is not None and index.const:
                key = str(index.const.value)
                sensitive = is_sensitive_env_name(key)
                return Taint(source_kind="env", source_ref=key, sensitive=sensitive, external=True,
                             steps=[FlowStep(kind="source", status="proven", location=self._loc(node.lineno),
                                             detail=f"os.environ[{key!r}]")])
            if base is not None:
                base.status = _worst_status([base.status, "inferred"])
                return base
            return Taint(source_kind="unknown", status="unresolved")
        if isinstance(node, ast.Call):
            return self._eval_call(node)
        if isinstance(node, ast.JoinedStr):
            parts = [self.eval(value.value) if isinstance(value, ast.FormattedValue) else None for value in node.values]
            return merge_taints(parts)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return merge_taints([self.eval(element) for element in node.elts])
        if isinstance(node, ast.Dict):
            taints = []
            for key, value in zip(node.keys, node.values):
                if key is not None:
                    taints.append(self.eval(key))
                taints.append(self.eval(value))
            return merge_taints(taints)
        if isinstance(node, (ast.DictComp, ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._eval_comprehension(node)
        if isinstance(node, ast.BinOp):
            return merge_taints([self.eval(node.left), self.eval(node.right)])
        if isinstance(node, ast.BoolOp):
            return merge_taints([self.eval(value) for value in node.values])
        if isinstance(node, ast.Compare):
            return merge_taints([self.eval(node.left)] + [self.eval(item) for item in node.comparators])
        if isinstance(node, ast.IfExp):
            return merge_taints([self.eval(node.body), self.eval(node.orelse), self.eval(node.test)])
        if isinstance(node, ast.UnaryOp):
            return self.eval(node.operand)
        if isinstance(node, ast.NamedExpr):
            value = self.eval(node.value)
            self._assign(node.target, value)
            return value
        if isinstance(node, ast.Await):
            return self.eval(node.value)
        if isinstance(node, ast.Starred):
            return self.eval(node.value)
        if isinstance(node, ast.Lambda):
            return Taint(source_kind="unknown", status="unresolved")
        if isinstance(node, ast.Yield):
            return self.eval(node.value)
        if isinstance(node, ast.Slice):
            return merge_taints([self.eval(node.lower), self.eval(node.upper), self.eval(node.step)])
        return Taint(source_kind="unknown", status="unresolved")

    def _eval_comprehension(self, node) -> Taint | None:
        if not node.generators:
            return None
        generator = node.generators[0]
        iter_taint = self.eval(generator.iter)
        loop_taint = self._loop_taint(iter_taint, generator)
        saved = {name: self.env.get(name) for name in self._target_names(generator.target)}
        self._assign(generator.target, loop_taint)
        taints = [self.eval(condition) for condition in generator.ifs]
        for extra in node.generators[1:]:
            self._assign(extra.target, self._loop_taint(self.eval(extra.iter), extra))
            taints.append(self.eval(extra.iter))
        if isinstance(node, ast.DictComp):
            taints.append(self.eval(node.key))
            taints.append(self.eval(node.value))
        else:
            taints.append(self.eval(node.elt))
        for name, previous in saved.items():
            if previous is None:
                self.env.pop(name, None)
            else:
                self.env[name] = previous
        return merge_taints(taints)

    @staticmethod
    def _target_names(target) -> list:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            names = []
            for element in target.elts:
                names.extend(Analyzer._target_names(element))
            return names
        return []

    def _eval_call(self, node) -> Taint | None:
        path = self._resolve_call_path(node.func)
        category, sink = sink_category(path)
        call_taint = self._route_call(node, path, category, sink)
        return call_taint

    def _resolve_call_path(self, func) -> str:
        if isinstance(func, ast.Attribute):
            base = self._resolve_call_path(func.value)
            if base and base in self.aliases:
                base = self.aliases[base]
            return f"{base}.{func.attr}" if base else func.attr
        if isinstance(func, ast.Name):
            return self.aliases.get(func.id, func.id)
        return resolve_name(func, self.aliases) or ""

    def _route_call(self, node, path: str, category: str, sink: str) -> Taint | None:
        arg_taints = []
        kw_taints = {}
        for arg in node.args:
            taint = self.eval(arg)
            if taint is not None:
                arg_taints.append(taint)
        for keyword in node.keywords:
            if keyword.arg is None:
                self.eval(keyword.value)
                continue
            taint = self.eval(keyword.value)
            if taint is not None:
                kw_taints[keyword.arg] = taint

        base = path.rsplit(".", 1)[-1]

        # 解码：常量求值优先；带来源的输入则保留污点并标记变换。
        const = self.decoder.evaluate(node, self._decoder_consts())
        if const is not None and const.value is not None and const.proven:
            if const.chain:
                source = self._decoded_source(node)
                if source is not None and (source.sensitive or source.external):
                    source = source.clone()
                    source.steps.extend(const.chain)
                    source.const = const
                    source.status = _worst_status([source.status, "proven" if const.proven else "inferred"])
                    return source
                return Taint(source_kind="decoded", source_ref=const.transform or "decode",
                             steps=list(const.chain), const=const, status="proven")
            if not arg_taints and not kw_taints:
                return Taint(source_kind="constant", const=const)

        # 环境变量 source。
        if base == "getenv" or path.endswith("os.environ.get"):
            key = self._const_string(node.args[0]) if node.args else ""
            if key:
                sensitive = is_sensitive_env_name(key)
                return Taint(source_kind="env", source_ref=key, sensitive=sensitive, external=True,
                             steps=[FlowStep(kind="source", status="proven", location=self._loc(node.lineno),
                                             detail=f"os.getenv({key!r})")])
            return Taint(source_kind="env", source_ref="<dynamic>", sensitive=True, external=True,
                         status="inferred", steps=[FlowStep(kind="source", status="inferred",
                                                            location=self._loc(node.lineno),
                                                            detail="动态环境变量键")])
        if path == "os.environ":
            return Taint(source_kind="env_container", source_ref="os.environ", sensitive=True, external=True,
                         steps=[FlowStep(kind="source", status="proven", location=self._loc(node.lineno),
                                         detail="os.environ 全量环境")])

        # 文件读取 source。
        if base == "open" and node.args:
            path_taint = self.eval(node.args[0])
            path_value = self._const_string(node.args[0])
            mode = "r"
            if len(node.args) > 1:
                mode = self._const_string(node.args[1]) or "r"
            if any(flag in mode for flag in ("a", "w", "x")):
                return None
            sensitive = bool(path_value and is_sensitive_path(path_value))
            steps = [FlowStep(kind="source", status="proven", location=self._loc(node.lineno),
                              detail=f"文件读取 {path_value or '<动态路径>'}")]
            if path_taint is not None and path_taint.external and path_taint.source_kind == "parameter":
                return Taint(source_kind="file", source_ref=path_taint.source_ref, external=True,
                             steps=steps + path_taint.steps, status="inferred")
            return Taint(source_kind="file", source_ref=path_value or "<dynamic>",
                         sensitive=sensitive, external=False, steps=steps)

        # sink 命中：按参数污点生成数据流记录（先记录再决定返回值）。
        if category and (arg_taints or kw_taints):
            self._record_flows(node, path, category, arg_taints, kw_taints)

        # 网络拉取 source（响应内容）。
        if category == "network" and base in ("get", "urlopen", "request", "retrieve"):
            return Taint(source_kind="network", source_ref=self._const_string(node.args[0]) if node.args else path,
                         external=False, steps=[FlowStep(kind="source", status="proven",
                                                         location=self._loc(node.lineno),
                                                         detail=f"网络拉取 {path}")])

        # transform 方法：接收者污点透传（跳过模块/函数名接收者）。
        if isinstance(node.func, ast.Attribute):
            receiver = self.eval(node.func.value)
            if receiver is not None and receiver.source_kind not in ("function", "constant"):
                receiver = receiver.clone()
                known = base in TRANSFORM_METHODS
                receiver.steps.append(FlowStep(kind="transform", status="proven" if known else "inferred",
                                               location=self._loc(node.lineno), detail=f"{base}()"))
                if not known:
                    receiver.status = _worst_status([receiver.status, "inferred"])
                return receiver

        # 内置聚合函数。
        if base in TRANSFORM_BUILTINS and not (base == "dict" and not node.args and not kw_taints):
            merged = merge_taints(arg_taints + list(kw_taints.values()))
            if merged is not None:
                merged = merged.clone()
                merged.steps.append(FlowStep(kind="transform", status="proven",
                                             location=self._loc(node.lineno), detail=f"{base}()"))
                return merged

        # 用户函数调用：登记调用点，跨函数阶段再传播。
        if base not in TRANSFORM_BUILTINS and "." not in path:
            if len(self.summary.call_sites) < self._max_calls:
                self.summary.call_sites.append(CallSite(
                    path=path, lineno=getattr(node, "lineno", 0),
                    args={f"#{index}": taint for index, taint in enumerate(arg_taints)},
                    kwargs=dict(kw_taints), text=self._text(node)))

        # sink 或未知调用的返回值：保留来源线索但状态降级为 unresolved。
        merged = merge_taints(arg_taints + list(kw_taints.values()))
        if merged is not None:
            merged = merged.clone()
            merged.status = _worst_status([merged.status, "unresolved"])
            merged.const = None
            return merged
        return Taint(source_kind="unknown", status="unresolved")

    def _decoder_consts(self) -> dict:
        consts = dict(self.consts)
        consts["__aliases__"] = dict(self.aliases)
        return consts

    def _decoded_source(self, node) -> Taint | None:
        """解码调用的输入若来自外部/敏感来源，保留来源并追加解码变换。"""
        return self.eval(node.args[0]) if node.args else None

    def _record_flows(self, node, path: str, category: str, arg_taints, kw_taints) -> None:
        kwargs = {}
        for keyword in node.keywords:
            if keyword.arg and isinstance(keyword.value, ast.Constant):
                kwargs[keyword.arg] = keyword.value.value
        candidates = [taint for taint in arg_taints if taint.sensitive or taint.external
                      or taint.source_kind in ("decoded", "network", "env", "env_container")]
        candidates += [taint for taint in kw_taints.values() if taint.sensitive or taint.external
                       or taint.source_kind in ("decoded", "network", "env", "env_container")]
        seen = set()
        for taint in candidates:
            key = (taint.source_kind, taint.source_ref, taint.sensitive, taint.external)
            if key in seen:
                continue
            seen.add(key)
            if len(self.summary.flows) >= self._max_paths:
                self.summary.unresolved.append("max_paths_limit")
                return
            steps = list(taint.steps)
            steps.append(FlowStep(kind="sink", status=taint.status,
                                  location=self._loc(getattr(node, "lineno", 0)),
                                  detail=f"{category} sink: {path}"))
            guard = taint.guard
            if not guard and taint.source_kind == "parameter" and taint.source_ref in self.guards:
                guard = "membership"
            self.summary.flows.append(FlowRecord(
                source_kind=taint.source_kind, source_ref=taint.source_ref,
                sensitive=taint.sensitive, external=taint.external,
                sink=path, sink_category=category, lineno=getattr(node, "lineno", 0),
                status=taint.status, steps=steps, call_text=self._text(node),
                decoded_value=self._decoded_text(taint), kwargs=kwargs, guard=guard,
                param_ref=taint.source_ref if taint.source_kind == "parameter" else "",
            ))

    @staticmethod
    def _decoded_text(taint: Taint) -> str:
        if taint.const is not None and taint.const.kind == "str":
            return taint.const.text()[:512]
        return ""

    def _const_string(self, node) -> str:
        value = self.decoder.evaluate(node, self._decoder_consts())
        if value is not None and isinstance(value.value, str):
            return value.value
        return ""

    def _text(self, node) -> str:
        try:
            return ast.unparse(node)[:300]
        except Exception:
            return ""

    def _loc(self, lineno: int) -> str:
        return f"{self.module.path}:{lineno}"


TRANSFORM_METHODS = {
    "decode", "encode", "format", "join", "replace", "strip", "lstrip", "rstrip",
    "lower", "upper", "hex", "items", "keys", "values", "get", "read", "text",
    "content", "json", "split", "partition", "extend", "append", "add", "pop",
    "copy", "update", "setdefault", "title", "splitlines",
}

TRANSFORM_BUILTINS = {
    "str", "repr", "bytes", "list", "set", "tuple", "sorted", "filter", "map",
    "dict", "min", "max", "format", "frozenset", "sum", "join",
    "any", "all", "bool", "next", "iter", "enumerate", "zip", "reversed",
}
