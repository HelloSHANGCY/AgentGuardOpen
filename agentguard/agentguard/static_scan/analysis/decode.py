"""固定白名单常量求值 / 解码。

安全约束（方案 §5.3）：
- 只求值字面量、容器、字符串拼接与白名单编解码函数；
- 绝不 exec/eval，解码结果只作为文本继续分析；
- 默认最多两层解码、单结果 256 KiB，超限标记截断，不计入 proven。
"""

import ast
import base64
import binascii
from dataclasses import dataclass, field

from ..models import FlowStep

# 只有这些函数名允许执行常量变换。
DECODE_FUNCS = {
    "base64.b64decode",
    "base64.b64encode",
    "base64.urlsafe_b64decode",
    "base64.urlsafe_b64encode",
    "binascii.unhexlify",
    "binascii.a2b_hex",
    "binascii.hexlify",
    "bytes.fromhex",
    "codecs.decode",
    "codecs.encode",
}

SAFE_CODECS = {"base64", "base64_codec", "hex", "hex_codec", "utf-8", "utf8", "ascii", "latin-1", "latin1"}

DECODE_METHODS = {"decode", "encode", "hex", "fromhex", "unhexlify"}


@dataclass
class ConstValue:
    kind: str  # str / bytes / int / float / bool / none / list / dict / set / tuple / unknown
    value: object = None
    proven: bool = True
    chain: list = field(default_factory=list)
    transform: str = ""

    def text(self) -> str:
        if self.kind == "bytes" and isinstance(self.value, (bytes, bytearray)):
            return bytes(self.value).decode("utf-8", "replace")
        if self.kind == "str":
            return str(self.value)
        return ""

    def size_hint(self) -> int:
        if isinstance(self.value, (str, bytes, bytearray)):
            return len(self.value)
        return 0


class DecodeBudget:
    """扫描级解码预算：总字节数 + 操作计数，防止解码炸弹。

    层数限制按单条解码链计算（见 Decoder._decode_text），不是扫描级累计。
    """

    def __init__(self, limits=None) -> None:
        self.limits = limits
        self.total_bytes = 0
        self.decode_ops = 0

    @property
    def max_layers(self) -> int:
        return int(getattr(self.limits, "max_decode_layers", 2))

    @property
    def max_bytes(self) -> int:
        return int(getattr(self.limits, "max_decoded_bytes", 256 * 1024))


class Decoder:
    """在给定常量环境下求值表达式。无法确认时返回 None（不猜测）。"""

    def __init__(self, budget: DecodeBudget = None, max_nodes: int = 5000) -> None:
        self.budget = budget or DecodeBudget()
        self.max_nodes = max_nodes
        self._visited = 0

    def evaluate(self, node, consts: dict | None = None) -> ConstValue | None:
        consts = consts or {}
        self._visited += 1
        if self._visited > self.max_nodes:
            return None
        return self._eval(node, consts)

    # ---- 基础表达式 ----

    def _eval(self, node, consts: dict) -> ConstValue | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return self._constant(node.value)
        if isinstance(node, ast.Name):
            return consts.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._eval(node.left, consts)
            right = self._eval(node.right, consts)
            return self._add(left, right)
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                    continue
                if isinstance(value, ast.FormattedValue):
                    part = self._eval(value.value, consts)
                    if part is None or not part.proven or part.kind not in ("str", "int", "float", "bool"):
                        return None
                    parts.append(str(part.value))
                    continue
                return None
            return ConstValue(kind="str", value="".join(parts))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            items = []
            for element in node.elts:
                item = self._eval(element, consts)
                if item is None:
                    return None
                items.append(item.value)
            kind = "list" if isinstance(node, ast.List) else ("tuple" if isinstance(node, ast.Tuple) else "set")
            return ConstValue(kind=kind, value=items)
        if isinstance(node, ast.Dict):
            result = {}
            for key_node, value_node in zip(node.keys, node.values):
                key = self._eval(key_node, consts)
                value = self._eval(value_node, consts)
                if key is None or value is None or key.kind != "str":
                    return None
                result[str(key.value)] = value.value
            return ConstValue(kind="dict", value=result)
        if isinstance(node, ast.Subscript):
            base = self._eval(node.value, consts)
            index = self._eval(node.slice, consts)
            if base is None or index is None:
                return None
            try:
                if base.kind == "dict" and index.kind == "str":
                    return self._constant(base.value.get(str(index.value)))
                if base.kind in ("list", "tuple"):
                    return self._constant(base.value[int(index.value)])
            except (KeyError, IndexError, TypeError, ValueError):
                return None
            return None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            inner = self._eval(node.operand, consts)
            if inner and isinstance(inner.value, (int, float)) and not isinstance(inner.value, bool):
                return ConstValue(kind=inner.kind, value=-inner.value)
            return None
        if isinstance(node, ast.IfExp):
            test = self._eval(node.test, consts)
            if test is None or not isinstance(test.value, (bool, int, str, bytes)):
                return None
            branch = node.body if test.value else node.orelse
            return self._eval(branch, consts)
        if isinstance(node, ast.Call):
            return self._eval_call(node, consts)
        return None

    def _eval_call(self, node, consts: dict) -> ConstValue | None:
        path = self.resolve_name(node.func, consts)
        if path is None:
            return None
        args = [self._eval(arg, consts) for arg in node.args]
        kwargs = {kw.arg: self._eval(kw.value, consts) for kw in node.keywords if kw.arg}
        if any(arg is None for arg in args) or any(value is None for value in kwargs.values()):
            return None
        arg_consts = list(args)
        receiver = None
        if isinstance(node.func, ast.Attribute):
            # 方法调用：接收者也必须是常量才继续求值。
            receiver = self._eval(node.func.value, consts)
            if receiver is not None:
                arg_consts = [receiver] + arg_consts
        values = [item.value for item in arg_consts]
        kw_values = {key: value.value for key, value in kwargs.items()}
        base = path.rsplit(".", 1)[-1]

        if receiver is None and (path in DECODE_FUNCS or base in ("b64decode", "urlsafe_b64decode", "unhexlify", "a2b_hex", "fromhex")):
            return self._decode_call(path, arg_consts, kw_values)

        if base == "encode" or base in ("b64encode", "urlsafe_b64encode", "hexlify"):
            return self._encode_call(path, values, kw_values)

        if base == "decode":
            return self._decode_bytes(path, arg_consts, kw_values)

        if base == "join" and len(values) == 2 and isinstance(values[0], str):
            if isinstance(values[1], (list, tuple, set)):
                return ConstValue(kind="str", value=str(values[0]).join(str(part) for part in values[1]))
        if base == "replace" and len(values) == 3:
            return ConstValue(kind="str", value=str(values[0]).replace(str(values[1]), str(values[2])))
        if base in ("strip", "lstrip", "rstrip") and values:
            return ConstValue(kind="str", value=str(values[0]).strip())
        if base in ("lower", "upper") and values:
            return ConstValue(kind="str", value=str(values[0]).lower() if base == "lower" else str(values[0]).upper())
        if base == "format" and values and isinstance(values[0], str):
            try:
                return ConstValue(kind="str", value=str(values[0]).format(*values[1:], **kw_values))
            except (IndexError, KeyError, ValueError):
                return None
        if base in ("decode", "encode") and values and isinstance(values[0], (str, bytes)):
            codec = str(values[1]) if len(values) > 1 else "utf-8"
            if codec.lower() not in SAFE_CODECS:
                return None
            try:
                if base == "encode":
                    return ConstValue(kind="bytes", value=str(values[0]).encode(codec))
                return ConstValue(kind="str", value=bytes(values[0]).decode(codec))
            except (UnicodeDecodeError, LookupError, ValueError):
                return None
        if base in ("getenv",) or path.endswith("os.environ.get"):
            # 环境变量默认值只是声明值，不是运行值：proven=False。
            default = values[1] if len(values) > 1 else None
            if isinstance(default, str):
                return ConstValue(kind="str", value=default, proven=False,
                                  transform=f"env:{values[0]}")
            return ConstValue(kind="unknown", value=None, proven=False, transform="env")
        return None

    def _decode_call(self, path: str, consts: list, kw_values: dict) -> ConstValue | None:
        if not consts:
            return None
        first = consts[0]
        data = first.value
        label = path or "decode"
        if not isinstance(data, (str, bytes, bytearray)):
            return None
        if path.endswith("fromhex"):
            if not isinstance(data, str):
                return None
            try:
                return self._decode_text(label, bytes.fromhex(data), first.chain)
            except ValueError:
                return None
        codec = str(consts[1].value).lower() if len(consts) > 1 and consts[1].value is not None else ""
        try:
            if "codecs" in path and codec:
                if codec.replace("_codec", "") == "hex":
                    return self._decode_text(label, binascii.unhexlify(data), first.chain)
                if codec.replace("_codec", "") == "base64":
                    return self._decode_text(label, base64.b64decode(self._pad(data), validate=False), first.chain)
                return None
            if "unhexlify" in path or "a2b_hex" in path:
                raw = binascii.unhexlify(data)
            elif "urlsafe" in path:
                raw = base64.urlsafe_b64decode(self._pad(data))
            else:
                raw = base64.b64decode(self._pad(data), validate=False)
        except (binascii.Error, ValueError, TypeError):
            return None
        return self._decode_text(label, raw, first.chain)

    def _encode_call(self, path: str, values: list, kw_values: dict) -> ConstValue | None:
        if not values or not isinstance(values[0], (str, bytes)):
            return None
        data = values[0].encode() if isinstance(values[0], str) else values[0]
        try:
            if "hexlify" in path:
                raw = binascii.hexlify(data)
            elif "urlsafe" in path:
                raw = base64.urlsafe_b64encode(data)
            else:
                raw = base64.b64encode(data)
        except (binascii.Error, ValueError, TypeError):
            return None
        return ConstValue(kind="bytes", value=raw, chain=[self._step(path)], transform=path)

    def _decode_bytes(self, path: str, consts: list, kw_values: dict) -> ConstValue | None:
        if not consts:
            return None
        first = consts[0]
        if not isinstance(first.value, (bytes, bytearray)):
            return None
        encoding = kw_values.get("encoding")
        if encoding is None and len(consts) > 1:
            encoding = consts[1].value
        encoding = encoding or "utf-8"
        if str(encoding).lower().replace("_codec", "") not in ("utf-8", "utf8", "ascii", "latin-1", "latin1"):
            return None
        return self._decode_text(path, bytes(first.value), first.chain)

    def _decode_text(self, label: str, raw: bytes | None, base_chain: list = None) -> ConstValue | None:
        if raw is None:
            return None
        chain = list(base_chain or [])
        if len(chain) + 1 > self.budget.max_layers:
            return ConstValue(kind="unknown", value=None, proven=False,
                              chain=chain + [self._step(label)], transform="decode_layer_limit")
        if self.budget.total_bytes + len(raw) > self.budget.max_bytes:
            return ConstValue(kind="unknown", value=None, proven=False,
                              chain=chain + [self._step(label)], transform="decode_size_limit")
        self.budget.total_bytes += len(raw)
        self.budget.decode_ops += 1
        text = raw.decode("utf-8", "replace")
        chain.append(self._step(label, f"decoded {len(raw)} bytes"))
        return ConstValue(kind="str", value=text, proven=True, chain=chain, transform=label)

    @staticmethod
    def _pad(data) -> bytes | str:
        if isinstance(data, str):
            padding = (-len(data)) % 4
            return data + "=" * padding
        return data + b"=" * ((-len(data)) % 4)

    @staticmethod
    def _step(label: str, detail: str = "") -> FlowStep:
        return FlowStep(kind="transform", status="proven", location="", detail=f"{label}{(' ' + detail) if detail else ''}")

    @staticmethod
    def _add(left: ConstValue | None, right: ConstValue | None) -> ConstValue | None:
        if left is None or right is None:
            return None
        if isinstance(left.value, str) and isinstance(right.value, str):
            chain = list(left.chain) + list(right.chain)
            return ConstValue(kind="str", value=left.value + right.value,
                              proven=left.proven and right.proven, chain=chain)
        if isinstance(left.value, (bytes, bytearray)) and isinstance(right.value, (bytes, bytearray)):
            return ConstValue(kind="bytes", value=bytes(left.value) + bytes(right.value),
                              proven=left.proven and right.proven,
                              chain=list(left.chain) + list(right.chain))
        if isinstance(left.value, list) and isinstance(right.value, list):
            return ConstValue(kind="list", value=left.value + right.value)
        return None

    @staticmethod
    def _constant(value) -> ConstValue:
        if value is None:
            return ConstValue(kind="none", value=None)
        if isinstance(value, bool):
            return ConstValue(kind="bool", value=value)
        if isinstance(value, int):
            return ConstValue(kind="int", value=value)
        if isinstance(value, float):
            return ConstValue(kind="float", value=value)
        if isinstance(value, str):
            return ConstValue(kind="str", value=value)
        if isinstance(value, (bytes, bytearray)):
            return ConstValue(kind="bytes", value=bytes(value))
        if isinstance(value, (list, tuple, set)):
            return ConstValue(kind="list", value=list(value))
        if isinstance(value, dict):
            return ConstValue(kind="dict", value=value)
        return ConstValue(kind="unknown", value=None, proven=False)

    # ---- 名称解析 ----

    @staticmethod
    def resolve_name(node, consts: dict = None) -> str | None:
        """把表达式解析成点分名称；import 别名由调用方预置在 consts['__aliases__']。"""
        aliases = (consts or {}).get("__aliases__") if consts else None
        return resolve_name(node, aliases or {})


def resolve_name(node, aliases: dict = None) -> str | None:
    return _resolve_with_aliases(node, aliases or {})


def _resolve_with_aliases(node, aliases: dict) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _resolve_with_aliases(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _resolve_with_aliases(node.func, aliases)
    if isinstance(node, ast.Subscript):
        return _resolve_with_aliases(node.value, aliases)
    return None
