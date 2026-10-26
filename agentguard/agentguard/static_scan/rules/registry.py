"""规则注册与执行。

适配器和规则实现为管理员部署的代码；单条规则异常不终止扫描，计入覆盖缺口。
"""

from .agent_config_rules import (
    AgentInstructionInjectionRule,
    AutoEnableProjectMcpRule,
    PermissiveAgentPermissionRule,
    RiskyHookCommandRule,
    UnmanagedMcpServerRule,
)
from .code_rules import SensitiveExfilRule, UnconstrainedExecutionRule
from .config_rules import (
    AuthDisabledRule,
    GatewayBypassRule,
    InsecureTransportRule,
    ModelRceRule,
    PrivilegedContainerRule,
    SkillPermissionRule,
    UnpinnedDependencyRule,
    WeakSecretRule,
)
from .mcp_rules import DescriptionPoisoningRule, HiddenToolRule, StartupBeaconRule
from .ruleset import load_ruleset
from .skill_rules import SkillDecodeExecRule, SkillDownloadExecRule, SkillInstructionRule
from .supply_chain import KnownVulnerabilityRule

RULES = (
    WeakSecretRule(),
    AuthDisabledRule(),
    PrivilegedContainerRule(),
    GatewayBypassRule(),
    InsecureTransportRule(),
    SkillPermissionRule(),
    ModelRceRule(),
    UnpinnedDependencyRule(),
    SkillInstructionRule(),
    SkillDecodeExecRule(),
    SkillDownloadExecRule(),
    HiddenToolRule(),
    StartupBeaconRule(),
    DescriptionPoisoningRule(),
    UnconstrainedExecutionRule(),
    SensitiveExfilRule(),
    KnownVulnerabilityRule(),
    PermissiveAgentPermissionRule(),
    AutoEnableProjectMcpRule(),
    RiskyHookCommandRule(),
    UnmanagedMcpServerRule(),
    AgentInstructionInjectionRule(),
)


def evaluate_all(facts, context, ruleset=None) -> list:
    ruleset = ruleset or load_ruleset()
    context.ruleset = ruleset
    context.ruleset_version = ruleset.version
    findings = []
    for rule in RULES:
        try:
            findings.extend(rule.evaluate(facts, context) or [])
        except Exception as exc:  # 单规则失败降级为覆盖缺口，不影响其他规则
            facts.gaps.append(f"rule {rule.rule_id} failed: {exc.__class__.__name__}: {exc}")
    return findings
