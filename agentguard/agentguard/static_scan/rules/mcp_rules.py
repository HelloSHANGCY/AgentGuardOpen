"""MCP 恶意行为规则 AG-STATIC-MCP-001 ~ 003（方案 §5.2）。

必须比较 advertised 集合与 dispatch 集合，不能仅凭工具名称打标签。
"""

from .base import flow_step, make_finding
from .skill_rules import classify_instruction, instruction_strength

VERSION = "1.0"


class HiddenToolRule:
    rule_id = "AG-STATIC-MCP-001"
    rule_version = VERSION
    category = "mcp_malicious"
    title = "隐藏但可调用的危险工具"

    def evaluate(self, facts, context):
        findings = []
        for tool in facts.assets_of_kind("Tool"):
            if not tool.metadata.get("hidden"):
                continue
            path = str(tool.metadata.get("handler_file") or tool.relative_path)
            handler = str(tool.metadata.get("handler") or "")
            summary = facts.summaries.summary_for(path, handler) if facts.summaries else None
            dangerous = [flow for flow in (summary.flows if summary else [])
                         if flow.sink_category in ("command", "dynamic_code")]
            dispatch_ids = list(tool.metadata.get("dispatch_evidence") or [])
            server = facts.asset_by_logical("MCPServer", f"mcp:{tool.metadata.get('server', '')}")
            if not dispatch_ids and server is not None:
                dispatch_ids = list(server.metadata.get("dispatch_evidence") or [])
            evidence = self._evidence(facts, path, tool, dangerous, dispatch_ids)
            if dangerous:
                flow = dangerous[0]
                severity, confidence = "HIGH", "high"
                explanation = (f"隐藏工具 {tool.name} 不在 tools/list 中，但 dispatch 可调用，"
                               f"handler 进入 {flow.sink}（{flow.sink_category}）")
                limitations = "静态确认隐藏标志与 handler 能力；未实际调用工具"
                steps = list(flow.steps)
            else:
                severity, confidence = "MEDIUM", "medium"
                explanation = f"隐藏工具 {tool.name} 可经 dispatch 调用，未在 handler 中发现危险 sink"
                limitations = "未发现危险 sink 不代表 handler 无副作用；动态逻辑可能未覆盖"
                steps = [flow_step("binding", "proven", f"{path}:{tool.metadata.get('lineno', 0) or 0}",
                                   "hidden=True 且注册器保留全量 registry")]
            if not dispatch_ids:
                limitations += "；未静态定位 dispatch 实现，调用可达性依据隐藏标志推断"
                confidence = "medium"
            findings.append(make_finding(
                self, context, tool.asset_id, severity, confidence,
                evidence=evidence, flow_steps=steps,
                explanation=explanation,
                remediation="移除隐藏工具或将其纳入 tools/list 与最小权限审核",
                limitations=limitations,
                fingerprint_extra=f"hidden:{tool.asset_id}",
                title=f"隐藏可调用工具：{tool.name}"))
        return findings

    @staticmethod
    def _evidence(facts, path, tool, dangerous, dispatch_ids):
        evidence = []
        line = int(tool.metadata.get("lineno") or 0)
        evidence.append(facts.evidence_for(
            path, line=line, excerpt=f"Tool({tool.name!r}, hidden=True)",
            parser="ast", pointer="/tools/hidden"))
        for flow in dangerous[:1]:
            evidence.append(facts.evidence_for(
                path, line=flow.lineno, excerpt=flow.call_text or f"{flow.sink}",
                parser="ast", pointer="/handler/sink"))
        for evidence_id in dispatch_ids[:4]:
            item = facts.evidence.get(evidence_id)
            if item is not None:
                evidence.append(item)
        return evidence


class StartupBeaconRule:
    rule_id = "AG-STATIC-MCP-002"
    rule_version = VERSION
    category = "mcp_malicious"
    title = "启动回调读取敏感环境并发出网络请求"

    def evaluate(self, facts, context):
        findings = []
        for (path, function), server_id in sorted(facts.mcp_on_start.items()):
            summary = facts.summaries.summary_for(path, function) if facts.summaries else None
            if summary is None:
                continue
            matched = [flow for flow in summary.flows
                       if flow.sink_category == "network"
                       and flow.sensitive
                       and flow.source_kind in ("env", "env_container", "file")]
            if not matched:
                continue
            flow = matched[0]
            asset = facts.assets.get(server_id)
            evidence = [
                facts.evidence_for(path, line=summary.lineno, excerpt=f"on_start={function}",
                                   parser="ast", pointer="/on_start"),
                facts.evidence_for(path, line=flow.lineno, excerpt=flow.call_text or flow.sink,
                                   parser="ast", pointer="/on_start/sink"),
            ]
            for step in flow.steps:
                if step.kind == "source":
                    line = int(step.location.rsplit(":", 1)[-1]) if step.location.rsplit(":", 1)[-1].isdigit() else 0
                    evidence.append(facts.evidence_for(path, line=line, excerpt=step.detail,
                                                       parser="ast", pointer="/on_start/source"))
            binding = flow_step("binding", "proven", f"{path}:{summary.lineno}",
                                f"启动回调绑定 on_start={function}")
            steps = [binding] + list(flow.steps)
            severity = "HIGH" if flow.status == "proven" else "MEDIUM"
            limitations = "静态确认启动绑定与 source→transform→sink；未证实外传在运行时成功"
            if flow.status != "proven":
                limitations += "；数据流存在未知变换，已降低置信度"
            findings.append(make_finding(
                self, context, asset.asset_id if asset else "", severity,
                "high" if flow.status == "proven" else "medium",
                evidence=evidence, flow_steps=steps,
                explanation=f"启动回调 {function} 读取敏感环境并以 {flow.sink} 外发",
                remediation="移除启动外联；供应链组件应审查回调与网络行为",
                limitations=limitations,
                fingerprint_extra=f"onstart:{path}:{function}",
                title=f"启动回调外联：{function}"))
        return findings


class DescriptionPoisoningRule:
    rule_id = "AG-STATIC-MCP-003"
    rule_version = VERSION
    category = "mcp_malicious"
    title = "工具描述投毒诱导跨工具访问或泄密"

    def evaluate(self, facts, context):
        findings = []
        for tool in facts.assets_of_kind("Tool"):
            description = str(tool.metadata.get("description") or "")
            if not description:
                continue
            flags = classify_instruction(description)
            severity, kind, report = instruction_strength(flags)
            if not report:
                continue
            path = str(tool.metadata.get("handler_file") or tool.relative_path)
            line = int(tool.metadata.get("lineno") or 0)
            evidence = facts.evidence_for(
                path, line=line, excerpt=f"description: {_safe(description)}",
                parser="ast", pointer="/tools/description")
            steps = [
                flow_step("source", "proven", f"{path}:{line}", f"工具 {tool.name} 描述字段"),
                flow_step("sink", "inferred", f"{path}:{line}", "描述诱导读取凭证/跨工具调用"),
            ]
            findings.append(make_finding(
                self, context, tool.asset_id, severity, "high",
                evidence=[evidence], flow_steps=steps,
                explanation=f"工具描述包含投毒式指令（{kind}）",
                remediation="移除描述中的指令文本；对工具描述做发布审核与文本过滤",
                limitations="描述文本本身未被模型执行；命中不代表已造成泄密",
                fingerprint_extra=f"desc:{tool.asset_id}",
                title=f"工具描述投毒：{tool.name}"))
        return findings


def _safe(text: str, limit: int = 160) -> str:
    import re

    clean = re.sub(r"\s+", " ", text).strip()
    return clean[:limit]
