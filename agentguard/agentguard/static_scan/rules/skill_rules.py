"""Skill / 指令类检测规则（方案 §5.2）。

输出“高危行为证据”“可疑指令线索”“一般配置缺陷”，不把所有命中统称恶意资产。
文档引用攻击样例不自动判定为生效指令；代码块也不自动豁免。
"""

import re

from ...core.normalize import command_threats, injection_markers, signatures
from ..models import digest_text
from .base import downgrade, flow_step, make_finding

VERSION = "1.0"

# 四类指令特征来自特征规则库（skill.credential / exfil / conceal / override，见 rulepacks/static-skill.yaml）。
INSTRUCTION_GROUPS = {"cred": "skill.credential", "exfil": "skill.exfil",
                      "conceal": "skill.conceal", "override": "skill.override"}


def classify_instruction(text: str) -> dict:
    lowered = text or ""
    flags = {key: [pattern.pattern for pattern in signatures(group) if pattern.search(lowered)]
             for key, group in INSTRUCTION_GROUPS.items()}
    flags["markers"] = injection_markers(lowered)
    return flags


def instruction_strength(flags: dict) -> tuple:
    """返回 (severity, kind, 是否值得报告)。孤立关键词只作线索不单独成 finding。"""
    cred, exfil = bool(flags["cred"]), bool(flags["exfil"])
    conceal, override = bool(flags["conceal"]), bool(flags["override"])
    if cred and exfil and (conceal or override):
        return "CRITICAL", "凭证读取+外发+隐藏操作的组合指令", True
    if cred and exfil:
        return "HIGH", "凭证读取与外发组合指令", True
    if cred and conceal:
        return "HIGH", "凭证读取与隐藏操作组合指令", True
    if override and exfil:
        return "MEDIUM", "指令覆盖与外发组合", True
    if override and conceal:
        return "MEDIUM", "指令覆盖与隐藏操作组合", True
    return "", "", False


class SkillInstructionRule:
    rule_id = "AG-STATIC-SKILL-001"
    rule_version = VERSION
    category = "skill_malicious"
    title = "Skill 指令要求读凭证外传、隐藏操作或覆盖用户指令"

    def evaluate(self, facts, context):
        findings = []
        skill_paths = {asset.relative_path: asset for asset in facts.assets_of_kind("Skill")}
        for path, doc in sorted(facts.markdown.items()):
            is_skill = path in skill_paths
            for segment in doc.segments:
                if segment.kind == "frontmatter":
                    continue
                flags = classify_instruction(segment.text)
                severity, kind, report = instruction_strength(flags)
                if not report:
                    continue
                limitations = "组合意图证据，不代表指令已被模型实际执行"
                if not is_skill:
                    severity = min(severity, "MEDIUM", key=_rank)
                    kind = f"文档中的可疑指令线索（{kind}）"
                    limitations += "；该文件不是 Skill，可能是文档引用或测试样例"
                elif segment.kind == "code":
                    severity = downgrade(severity, 2)
                    limitations += "；命中位于代码块，已显著降级并需人工复核（可能是引用/测试样例）"
                elif segment.kind == "quote":
                    severity = downgrade(severity)
                    limitations += "；命中位于引用段，已降级"
                asset = skill_paths.get(path) if is_skill else None
                # 代码块/引用/普通文档只输出“可疑指令线索”，不与恶意 Skill 混为一类。
                category = ("instruction_clue" if (not is_skill or segment.kind in ("code", "quote"))
                            else "skill_malicious")
                evidence = facts.evidence_for(
                    path, line=segment.start_line,
                    excerpt=_redact_segment(segment.text),
                    parser="markdown", pointer=f"/{segment.kind}")
                steps = [
                    flow_step("source", "proven", f"{path}:{segment.start_line}",
                              f"{segment.kind} 段指令"),
                    flow_step("sink", "inferred", f"{path}:{segment.start_line}",
                              "读取敏感对象/外发/隐藏操作的组合"),
                ]
                if flags["markers"]:
                    limitations += f"；注入标记：{', '.join(flags['markers'][:5])}"
                findings.append(make_finding(
                    self, context, asset.asset_id if asset else "", severity, "medium",
                    evidence=[evidence], flow_steps=steps,
                    explanation=f"{kind}：{_summarize_flags(flags)}",
                    remediation="移除隐藏指令与凭证操作；Skill 权限与行为保持最小化并接受审核",
                    limitations=limitations, category=category,
                    fingerprint_extra=f"{path}:{segment.start_line}:{digest_text(segment.text, 12)}",
                    title=f"{kind}：{path.rsplit('/', 1)[-1]}"))
        return findings


class SkillDecodeExecRule:
    rule_id = "AG-STATIC-SKILL-002"
    rule_version = VERSION
    category = "skill_malicious"
    title = "常量解码内容流入 exec/eval/shell"

    def evaluate(self, facts, context):
        findings = []
        for module_path, flows in self._flows(facts):
            entry = facts.index.get(module_path)
            in_skill = bool(entry and entry.skill_dir)
            if not in_skill:
                continue
            for flow in flows:
                if flow.source_kind != "decoded":
                    continue
                if flow.sink_category not in ("dynamic_code", "command"):
                    continue
                asset = facts.asset_for_path(module_path, kinds=("Skill",))
                evidence = _flow_evidence(facts, flow)
                decoded = flow.decoded_value or ""
                findings.append(make_finding(
                    self, context, asset.asset_id if asset else "", "HIGH", "high",
                    evidence=evidence, flow_steps=flow.steps,
                    explanation=f"常量解码结果进入 {flow.sink}（{flow.sink_category}）",
                    remediation="移除动态执行；确需解码时限制来源并避免执行解码内容",
                    limitations="已确认静态解码链；解码内容是否实际执行取决于运行时路径",
                    fingerprint_extra=f"{module_path}:{flow.sink}:{digest_text(decoded, 12)}",
                    title=f"解码后执行：{module_path.rsplit('/', 1)[-1]}"))
        return findings

    @staticmethod
    def _flows(facts):
        if facts.summaries is None:
            return []
        rows = [(path, flows) for path, flows in facts.summaries.module_flows.items()]
        for summary in facts.summaries.functions.values():
            rows.append((summary.module, summary.flows))
        return rows


class SkillDownloadExecRule:
    rule_id = "AG-STATIC-SKILL-003"
    rule_version = VERSION
    category = "skill_malicious"
    title = "下载内容进入命令执行或解码后含下载执行线索"

    def evaluate(self, facts, context):
        findings = []
        for module_path, flows in SkillDecodeExecRule._flows(facts):
            entry = facts.index.get(module_path)
            in_skill = bool(entry and entry.skill_dir)
            for flow in flows:
                if flow.source_kind == "decoded" and flow.decoded_value:
                    threats = command_threats(flow.decoded_value, c2_hosts=())
                    download = [name for name in threats if name in ("DOWNLOAD_EXEC", "BASE64_EXEC", "REVERSE_SHELL")]
                    if download:
                        asset = facts.asset_for_path(module_path, kinds=("Skill",))
                        evidence = _flow_evidence(facts, flow)
                        decoded_evidence = facts.evidence_for(
                            module_path, line=flow.lineno,
                            excerpt=f"解码内容线索：{_snippet(flow.decoded_value)}",
                            parser="decode", pointer="/decoded")
                        findings.append(make_finding(
                            self, context, asset.asset_id if asset else "",
                            "HIGH" if in_skill else "MEDIUM", "medium",
                            evidence=evidence + [decoded_evidence], flow_steps=flow.steps,
                            explanation=f"解码内容包含下载执行结构：{', '.join(download)}",
                            remediation="审查解码载荷来源，禁止下载管道执行",
                            limitations="命中基于解码文本结构，未执行验证",
                            fingerprint_extra=f"{module_path}:{flow.sink}:dl:{digest_text(flow.decoded_value, 12)}",
                            title=f"下载执行线索：{module_path.rsplit('/', 1)[-1]}"))
                if flow.source_kind == "network" and flow.sink_category in ("command", "dynamic_code"):
                    asset = facts.asset_for_path(module_path, kinds=("Skill",))
                    findings.append(make_finding(
                        self, context, asset.asset_id if asset else "",
                        "HIGH" if in_skill else "MEDIUM", "medium",
                        evidence=_flow_evidence(facts, flow), flow_steps=flow.steps,
                        explanation=f"网络拉取内容流向 {flow.sink}",
                        remediation="禁止将远程内容直接交给解释器/命令执行",
                        limitations="未验证远程内容运行时行为",
                        fingerprint_extra=f"{module_path}:{flow.sink}:net",
                        title=f"远程内容执行：{module_path.rsplit('/', 1)[-1]}"))
        return findings


# ---------- 辅助 ----------

def _flow_evidence(facts, flow):
    evidence = []
    for step in flow.steps:
        if step.kind == "sink":
            evidence.append(facts.evidence_for(
                _path_of(step.location) or flow.sink, line=_line_of(step.location),
                excerpt=flow.call_text or step.detail, parser="ast", pointer="/sink"))
        elif step.kind == "source":
            evidence.append(facts.evidence_for(
                _path_of(step.location) or flow.sink, line=_line_of(step.location),
                excerpt=step.detail, parser="ast", pointer="/source"))
        elif step.kind == "transform":
            evidence.append(facts.evidence_for(
                _path_of(step.location) or flow.sink, line=_line_of(step.location),
                excerpt=step.detail, parser="ast", pointer="/transform"))
    if not evidence:
        evidence.append(facts.evidence_for(flow.sink, line=flow.lineno, excerpt=flow.call_text, parser="ast"))
    return evidence


def _path_of(location: str) -> str:
    if not location or ":" not in location:
        return ""
    path, _, _ = location.rpartition(":")
    return path


def _line_of(location: str) -> int:
    if not location or ":" not in location:
        return 0
    _, _, tail = location.rpartition(":")
    return int(tail) if tail.isdigit() else 0


def _snippet(text: str, limit: int = 120) -> str:
    clean = re.sub(r"\s+", " ", str(text or "")).strip()
    return clean[:limit]


def _redact_segment(text: str, limit: int = 200) -> str:
    clean = re.sub(r"\s+", " ", str(text or "")).strip()
    clean = re.sub(r"([A-Za-z0-9_\-]{20,})", lambda match: match.group(1)[:6] + "***", clean)
    return clean[:limit]


def _summarize_flags(flags: dict) -> str:
    parts = []
    if flags["cred"]:
        parts.append("读取敏感对象")
    if flags["exfil"]:
        parts.append("外发/同步动作")
    if flags["conceal"]:
        parts.append("隐藏操作")
    if flags["override"]:
        parts.append("覆盖指令")
    return "、".join(parts)


def _rank(severity: str) -> int:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return order.index(severity) if severity in order else 0
