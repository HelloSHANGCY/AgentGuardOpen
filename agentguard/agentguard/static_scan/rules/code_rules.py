"""代码数据流规则 AG-STATIC-CODE-001 ~ 002（方案 §5.2）。

需要值关联证据：不能仅因同文件同时存在 getenv 和 HTTP 就判泄密；
固定运维命令与可验证 allowlist 不报“未约束注入”。
"""

from .base import flow_step, make_finding

VERSION = "1.0"

STATUS_CONFIDENCE = {"proven": "high", "inferred": "medium", "unresolved": "low"}


class UnconstrainedExecutionRule:
    rule_id = "AG-STATIC-CODE-001"
    rule_version = VERSION
    category = "code"
    title = "外部参数未经可识别约束进入 shell/eval/exec"

    def evaluate(self, facts, context):
        findings = []
        for module_path, function, flows in _iter_flows(facts):
            for flow in flows:
                if flow.sink_category not in ("command", "dynamic_code"):
                    continue
                if flow.guard:
                    continue  # 可验证的成员白名单约束：单独处理，不报未约束注入
                if flow.source_kind == "decoded":
                    # Skill 内由 SKILL-002 负责；其余作为一般动态执行线索。
                    entry = facts.index.get(module_path)
                    if entry and entry.skill_dir:
                        continue
                    severity = "MEDIUM"
                    confidence = "high"
                    explanation = f"常量解码内容进入 {flow.sink}，解码链完整"
                else:
                    if not (flow.sensitive or flow.external):
                        continue
                    if flow.source_kind not in ("parameter", "env", "env_container", "file", "network"):
                        continue
                    entry = facts.index.get(module_path)
                    in_skill = bool(entry and entry.skill_dir)
                    severity = "HIGH" if (flow.sink_category == "dynamic_code" or flow.kwargs.get("shell")) else "MEDIUM"
                    if in_skill:
                        severity = "MEDIUM"  # Skill 内由 SKILL 规则专门定级，避免双高
                    confidence = STATUS_CONFIDENCE.get(flow.status, "low")
                    explanation = (f"外部来源 {flow.source_ref} 未经可识别约束进入 "
                                   f"{flow.sink}（{flow.sink_category}）")
                if function and _suppressed_hidden_handler(facts, module_path, function):
                    continue
                findings.append(_finding(self, facts, context, module_path, function, flow,
                                         severity, confidence, explanation))
        return findings


class SensitiveExfilRule:
    rule_id = "AG-STATIC-CODE-002"
    rule_version = VERSION
    category = "code"
    title = "敏感文件/环境变量进入 HTTP、socket 等外发 sink"

    def evaluate(self, facts, context):
        findings = []
        for module_path, function, flows in _iter_flows(facts):
            for flow in flows:
                if flow.sink_category != "network" or not flow.sensitive:
                    continue
                if flow.source_kind not in ("env", "env_container", "file"):
                    continue
                if function and (module_path, function) in facts.mcp_on_start:
                    continue  # 启动回路由 MCP-002 专门报告
                severity = "HIGH" if flow.status == "proven" else "MEDIUM"
                confidence = STATUS_CONFIDENCE.get(flow.status, "low")
                findings.append(_finding(
                    self, facts, context, module_path, function, flow, severity, confidence,
                    f"敏感来源 {flow.source_ref} 流向网络 sink {flow.sink}"))
        return findings


# ---------- 辅助 ----------

def _iter_flows(facts):
    if facts.summaries is None:
        return
    for path, flows in facts.summaries.module_flows.items():
        yield path, None, flows
    for summary in facts.summaries.functions.values():
        yield summary.module, summary.name, summary.flows


def _suppressed_hidden_handler(facts, module_path: str, function: str) -> bool:
    tool_id = facts.mcp_handlers.get((module_path, function))
    if not tool_id:
        return False
    tool = facts.assets.get(tool_id)
    return bool(tool and tool.metadata.get("hidden"))


def _finding(rule, facts, context, module_path, function, flow, severity, confidence, explanation):
    asset = facts.asset_for_path(module_path)
    evidence = []
    for step in flow.steps:
        if step.kind in ("source", "sink"):
            path, line = _split_location(step.location)
            evidence.append(facts.evidence_for(
                path or module_path, line=line,
                excerpt=(flow.call_text if step.kind == "sink" else step.detail) or step.detail,
                parser="ast", pointer=f"/{step.kind}"))
    if not evidence:
        evidence.append(facts.evidence_for(module_path, line=flow.lineno,
                                           excerpt=flow.call_text, parser="ast", pointer="/sink"))
    steps = list(flow.steps)
    if function:
        steps.insert(0, flow_step("binding", "proven", f"{module_path}:{flow.lineno}", f"函数 {function}"))
    return make_finding(
        rule, context, asset.asset_id if asset else "", severity, confidence,
        evidence=evidence, flow_steps=steps,
        explanation=explanation,
        remediation="对外部输入做参数化/白名单校验；敏感值禁止进入网络外发路径",
        limitations=_limitations(flow),
        fingerprint_extra=f"{module_path}:{function or '<module>'}:{flow.sink}:{flow.source_ref}:{flow.lineno}",
        title=f"数据流风险：{flow.sink}")


def _limitations(flow) -> str:
    parts = ["静态数据流证据，未在运行时验证可达性"]
    if flow.status == "inferred":
        parts.append("链路含未知变换，证据可靠度中等")
    elif flow.status == "unresolved":
        parts.append("存在未解析动态环节，仅作为线索")
    if flow.guard:
        parts.append(f"存在约束：{flow.guard}")
    return "；".join(parts)


def _split_location(location: str) -> tuple:
    if not location or ":" not in location:
        return "", 0
    path, _, tail = location.rpartition(":")
    return path, int(tail) if tail.isdigit() else 0
