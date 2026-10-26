"""函数摘要与有界跨函数传播（方案 §5.3 第 2 步）。

第一阶段：模块常量 + 单函数数据流；
第二阶段：同项目函数名索引、静态实参绑定与调用边，深度默认 3。
递归、反射、动态 import、复杂别名或未知库调用输出 unresolved，不编造完整数据流。
"""

from dataclasses import dataclass, field

from ..models import FlowStep
from .dataflow import Analyzer, CallSite, FlowRecord, FunctionSummary, _worst_status


@dataclass
class SummaryRegistry:
    functions: dict = field(default_factory=dict)  # "path:func" -> FunctionSummary
    by_name: dict = field(default_factory=dict)  # 函数名 -> [FunctionSummary]
    module_taints: dict = field(default_factory=dict)
    module_flows: dict = field(default_factory=dict)
    module_calls: dict = field(default_factory=dict)

    def flows_for(self, module_path: str) -> list:
        flows = list(self.module_flows.get(module_path, []))
        for summary in self.functions.values():
            if summary.module == module_path:
                flows.extend(summary.flows)
        return flows

    def summary_for(self, module_path: str, name: str) -> FunctionSummary | None:
        return self.functions.get(f"{module_path}:{name}")


def build_summaries(py_modules: dict, limits, budget) -> SummaryRegistry:
    registry = SummaryRegistry()
    max_paths = int(getattr(limits, "max_paths_per_entry", 200))

    for path, module in py_modules.items():
        if module.parse_error or module.tree is None:
            continue
        analyzer = Analyzer(module, module.tree, budget, limits, name="<module>")
        summary = analyzer.run()
        registry.module_taints[path] = {name: taint for name, taint in analyzer.env.items() if taint is not None}
        registry.module_flows[path] = summary.flows[:max_paths]
        registry.module_calls[path] = summary.call_sites

    for path, module in py_modules.items():
        if module.parse_error or module.tree is None:
            continue
        globals_taint = registry.module_taints.get(path, {})
        for name, node in module.functions.items():
            analyzer = Analyzer(module, node, budget, limits, name=name, globals_taint=globals_taint)
            summary = analyzer.run()
            registry.functions[summary.key] = summary
            registry.by_name.setdefault(name, []).append(summary)

    _propagate_cross_function(registry, limits)
    return registry


def _propagate_cross_function(registry: SummaryRegistry, limits) -> None:
    max_depth = int(getattr(limits, "max_flow_depth", 3))
    for summary in list(registry.functions.values()):
        _walk_calls(summary, registry, max_depth, depth=0, visited=set())


def _walk_calls(summary: FunctionSummary, registry: SummaryRegistry, max_depth: int,
                depth: int, visited: set) -> None:
    if depth >= max_depth or summary.key in visited:
        return
    visited = visited | {summary.key}
    for call in summary.call_sites:
        callee = _match_callee(summary, call, registry)
        if callee is None or callee.key == summary.key:
            continue
        _apply_flow(summary, callee, call)
        _walk_calls(callee, registry, max_depth, depth + 1, visited)
    _apply_returns(summary, registry)


def _match_callee(caller: FunctionSummary, call: CallSite, registry: SummaryRegistry) -> FunctionSummary | None:
    name = call.path.rsplit(".", 1)[-1]
    candidates = registry.by_name.get(name) or []
    if not candidates:
        return None
    same_module = [item for item in candidates if item.module == caller.module]
    if same_module:
        return same_module[0]
    return candidates[0]


def _arg_bindings(callee: FunctionSummary, call: CallSite) -> dict:
    bindings = {}
    for index, param in enumerate(callee.params):
        taint = call.args.get(f"#{index}")
        if taint is not None:
            bindings[param] = taint
    for name, taint in call.kwargs.items():
        if name in callee.params:
            bindings[name] = taint
    return bindings


def _apply_flow(caller: FunctionSummary, callee: FunctionSummary, call: CallSite) -> None:
    if not callee.flows:
        return
    bindings = _arg_bindings(callee, call)
    seen = {(flow.sink, flow.source_ref, flow.source_kind) for flow in caller.flows}
    for flow in callee.flows:
        if not flow.param_ref or flow.param_ref not in bindings:
            continue
        source_taint = bindings[flow.param_ref]
        if not (source_taint.sensitive or source_taint.external or source_taint.source_kind == "decoded"):
            continue
        key = (flow.sink, source_taint.source_ref, source_taint.source_kind)
        if key in seen:
            continue
        seen.add(key)
        steps = list(source_taint.steps)
        steps.append(FlowStep(kind="transform", status="proven",
                              location=f"{caller.module}:{call.lineno}",
                              detail=f"调用 {callee.name}() 参数 {flow.param_ref}"))
        steps.extend(step for step in flow.steps if step.kind != "source")
        caller.flows.append(FlowRecord(
            source_kind=source_taint.source_kind, source_ref=source_taint.source_ref,
            sensitive=source_taint.sensitive, external=source_taint.external,
            sink=flow.sink, sink_category=flow.sink_category, lineno=flow.lineno,
            status=_worst_status([source_taint.status, flow.status]), steps=steps,
            call_text=flow.call_text, decoded_value=flow.decoded_value or "",
            kwargs=dict(flow.kwargs), guard=source_taint.guard, param_ref=flow.param_ref,
        ))


def _apply_returns(caller: FunctionSummary, registry: SummaryRegistry) -> None:
    """被调函数返回值携带敏感/外部来源时登记 unresolved 线索。

    不做完整过程间返回值重写：未知变换不冒充已证实路径。
    """
    for call in caller.call_sites:
        callee = _match_callee(caller, call, registry)
        if callee is None or callee.returns is None:
            continue
        returns = callee.returns
        if returns.source_kind in ("decoded", "env", "file", "network") and returns.source_ref:
            marker = f"return_taint:{callee.name}:{call.lineno}"
            if marker not in caller.unresolved:
                caller.unresolved.append(marker)


def cross_function_flows(registry: SummaryRegistry, module_path: str) -> list:
    return registry.flows_for(module_path)
