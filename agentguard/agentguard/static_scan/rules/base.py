"""规则基类与 finding 构造。

severity 表示潜在影响，confidence 表示证据可靠性；缺少证据不能靠高严重度补足。
"""

from dataclasses import dataclass, field
from typing import Protocol

from ..models import SEVERITY_RANK, Finding, FlowStep, digest_text, finding_fingerprint


@dataclass
class RuleContext:
    facts: object
    context: object
    ruleset: object
    findings: list = field(default_factory=list)


class StaticRule(Protocol):
    rule_id: str
    rule_version: str
    category: str
    title: str

    def evaluate(self, facts, context) -> list:
        ...


def make_finding(rule, context, asset_id: str, severity: str, confidence: str,
                 evidence: list = None, explanation: str = "", remediation: str = "",
                 limitations: str = "", flow_steps: list = None, title: str = "",
                 fingerprint_extra: str = "", category: str = "") -> Finding:
    evidence = evidence or []
    locations = [f"{item.path}:{item.line}:{item.pointer}" for item in evidence]
    if fingerprint_extra:
        locations.append(fingerprint_extra)
    fingerprint = finding_fingerprint(rule.rule_id, asset_id, locations)
    return Finding(
        finding_id="find-" + digest_text(f"{context.scan_id}|{fingerprint}", 20),
        scan_id=context.scan_id, rule_id=rule.rule_id,
        rule_version=rule.rule_version, asset_id=asset_id, category=category or rule.category,
        severity=severity if severity in SEVERITY_RANK else "INFO",
        confidence=confidence, evidence_ids=[item.evidence_id for item in evidence],
        flow_steps=[step.as_dict() if hasattr(step, "as_dict") else step for step in (flow_steps or [])],
        explanation=explanation, remediation=remediation, limitations=limitations,
        fingerprint=fingerprint, title=title or rule.title,
    )


def flow_step(kind: str, status: str, location: str, detail: str) -> FlowStep:
    return FlowStep(kind=kind, status=status, location=location, detail=detail)




def downgrade(severity: str, steps: int = 1) -> str:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    index = max(0, order.index(severity) - steps) if severity in order else 0
    return order[index]
