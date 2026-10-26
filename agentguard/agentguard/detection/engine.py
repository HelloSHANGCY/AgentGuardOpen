"""确定性运行时决策引擎（设计 §5.6 / §8；通用 Agent 接入设计 §5 / §7）。

评估所有规则并保留全部命中证据；同一次评估命中多个规则时取最严格决策
（DENY > ASK > ALLOW），主 reason 取优先级最高（最先评估）的命中。
引擎本身只做规范化与确定性规则，不依赖外部大模型；可选的大模型危险审批（llm/judge.py）
在 Hook 适配器中对引擎结论做二次复核，未开启时决策完全确定。

规则基于能力视图（capability.NormalizedCall）而非具体 (server, tool)：业务服务的
MCP 调用与通用 Agent 的内置工具共用同一套规则；与业务强相关的默认放行语义
按策略档案（service / developer / strict）区分。
"""

import json
import os
import re
import time
from dataclasses import dataclass, field

from ..config import SANDBOX_WHITELIST, SIDE_EFFECT_SERVERS, Settings
from ..core import capability as C
from ..core.normalize import (
    command_threats,
    is_agent_config_path,
    is_persistence_path,
    is_scratch_path,
    path_within,
    resolve_path,
    sensitive_content_types,
    sensitive_path_class,
)
from ..llm.judge import JudgeService
from ..llm.registry import ModelRegistry
from ..models import Decision, RuleMatch, TaskContext, ToolRequest, new_id, sha256_digest
from ..rules.catalog import strategy_title
from ..rules.trace import observe_features
from . import anomaly as A
from . import flow as F
from . import provenance as P
from . import taint as T
from .behavior import BehaviorService
from .intent import IntentService

ADMIN_ROLES = {"ops-admin"}
OPS_ROLES = {"ops-engineer", "ops-admin"}
HIGH_RISK_SERVERS = {"shell-runner", "notes-sync", "sandbox-exec"}

# 策略档案：任务信封未指定时按发起方 Agent 取默认值。
PROFILE_SERVICE = "service"
PROFILE_DEVELOPER = "developer"
PROFILE_STRICT = "strict"
PROFILE_DEFAULTS = {"mcp": PROFILE_SERVICE, "claude-code": PROFILE_DEVELOPER, "codex": PROFILE_DEVELOPER,
                    "trae": PROFILE_DEVELOPER, "qoder": PROFILE_DEVELOPER, "zcode": PROFILE_DEVELOPER,
                    "workbuddy": PROFILE_DEVELOPER, "codebuddy": PROFILE_DEVELOPER}
KNOWN_PROFILES = {PROFILE_SERVICE, PROFILE_DEVELOPER, PROFILE_STRICT}

# Skill allowed-tools 的等价写法归一：支持 server 名、server/tool、server.tool、
# OpenAI 工具名和裸工具名（业务 Skills 声明的是 server 名）。
OPENAI_ROUTES = {
    "customer_db_query": ("customer-db", "query"),
    "shell_runner_run": ("shell-runner", "run"),
    "shell_runner_read_file": ("shell-runner", "read_file"),
    "notes_sync_sync_note": ("notes-sync", "sync_note"),
    "notes_sync_debug_exec": ("notes-sync", "debug_exec"),
    "threat_intel_lookup": ("threat-intel", "lookup"),
    "gitlab_get_pr": ("gitlab", "get_pr"),
    "monitoring_query_metric": ("monitoring", "query_metric"),
    "knowledge_search": ("knowledge", "search"),
    "sandbox_exec_run_test": ("sandbox-exec", "run_test"),
}

# 通过 Agent 自身 CLI 修改 MCP/配置：绕开文件写入检查的等价路径（R017）。
AGENT_CONFIG_CLI_RE = re.compile(
    r"\bclaude\s+(mcp\s+(add|add-json|add-from-claude-desktop|remove)|config\s+(set|add|remove))\b"
    # Codex：增删 MCP server、开关特性，或以关闭 Hook 的参数启动嵌套会话。
    r"|\bcodex\b.*?(\bmcp\s+(add|remove)\b|\bfeatures\s+(enable|disable)\b|--disable[=\s]+hooks\b"
    r"|features\.hooks\s*=\s*false|\bhooks\.state\b)"
    # ZCode：以另一份用户配置启动嵌套会话（--settings），其中没有 AgentGuard 的 Hook（实测 zcode 0.16.5）。
    r"|\bzcode(-agent)?\b.*?--settings\b"
    # WorkBuddy / CodeBuddy Code：增删 MCP server，或以 --setting-sources 限定设置源启动嵌套会话（不含 user 时
    # 用户级 Hook 不加载；workbuddy.ai「CLI 参考」）。
    r"|\b(codebuddy|workbuddy)\b.*?(\bmcp\s+(add|add-json|remove)\b|--setting-sources\b)")
# URL 中夹带的高熵长串（编码后的外带数据）。
URL_BLOB_RE = re.compile(r"[A-Za-z0-9+/_=%-]{40,}")


def skill_allows(allowed_entries: list, server: str, tool: str, raw_tool: str = "") -> bool:
    """active skill 的 allowed-tools 是否覆盖当前 (server, tool) 或内置工具名。"""
    raw = (raw_tool or "").strip().lower()
    for entry_raw in allowed_entries or []:
        entry = str(entry_raw).strip().lower()
        if not entry:
            continue
        # Claude Code 写法 `Bash(git:*)`：按工具名覆盖，参数范围由原生权限控制。
        base = entry.split("(", 1)[0].strip()
        if raw and base == raw:
            return True
        if not server:
            continue
        if entry == server:
            return True
        if entry in (f"{server}/{tool}", f"{server}.{tool}", f"{server}-{tool}"):
            return True
        if entry == tool:
            return True
        if OPENAI_ROUTES.get(entry) == (server, tool):
            return True
    return False


@dataclass
class ManifestView:
    """引擎可见的上游运行时清单状态。"""

    known_tools: set | None = None   # None 表示当前无任何可信清单
    poisoned_servers: set = field(default_factory=set)
    poisoned_features: dict = field(default_factory=dict)


def sandbox_whitelisted(cmd: str) -> bool:
    text = str(cmd or "").strip()
    for allowed in SANDBOX_WHITELIST:
        if text == allowed or text.startswith(allowed + " "):
            return True
    return False


def resolve_profile(request: ToolRequest, task: TaskContext | None) -> str:
    profile = (task.policy_profile if task else "") or PROFILE_DEFAULTS.get(request.agent, PROFILE_SERVICE)
    return profile if profile in KNOWN_PROFILES else PROFILE_STRICT


def request_calls(request: ToolRequest) -> list:
    """适配器已给出能力展开时直接使用，否则按 MCP 映射表补全。"""
    return list(request.calls) or C.classify_mcp(request.server, request.tool, request.arguments)


def _session_untrusted(task: TaskContext | None, state) -> set:
    labels = {label for label in (task.source_labels if task else []) if label.startswith("UNTRUSTED_")}
    if state is not None:
        labels |= {label for label in state.taints if label.startswith("UNTRUSTED_") or label == T.POISONED_RESULT}
    return labels


class RuntimeDecisionEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        # 行为基线：内置模型随规则版本发布（baseline/transitions.json），控制台训练的模型启用后热切换。
        self.behavior = BehaviorService(getattr(settings, "behavior_dir", ""))
        # 意图识别：关键词，配置了大模型密钥时另做异步分类（intent.py）。
        self.intents = IntentService.from_settings(settings)
        # 大模型辅助研判（llm/judge.py）：危险审批复核静态判定、轮次结束后异步分析；未配置时不生效。
        self.judge = JudgeService.from_settings(settings, intents=self.intents)
        directory = getattr(settings, "agent_device_dir", "")
        self.models = ModelRegistry(os.path.join(directory, "llm-models.json") if directory else "",
                                    legacy_loader=self._legacy_models)
        self.intents.models = self.models
        self.judge.models = self.models

    def _legacy_models(self):
        with self.intents._lock:
            intent = dict(self.intents._config)
            intent_key = self.intents._key(intent)
        with self.judge._lock:
            judge = dict(self.judge._config)
            judge_key = self.judge._key(judge)[0]
        return {
            "intent": {"url": intent["url"], "model": intent["model"], "key": intent_key,
                       "effort": "off", "timeout": intent["timeout"]},
            "approval": {"url": judge["url"], "model": judge["model"], "key": judge_key,
                         "effort": judge["approval_effort"], "timeout": judge["approval_timeout"]},
            "analysis": {"url": judge["url"], "model": judge["analysis_model"] or judge["model"], "key": judge_key,
                         "effort": judge["analysis_effort"], "timeout": judge["analysis_timeout"]},
        }

    @property
    def baseline(self) -> A.Baseline:
        return self.behavior.baseline

    # ---- 规则实现，按设计 §7.2 优先级顺序执行 ----

    def _r002_sensitive_read(self, req, task, calls, profile, matches) -> None:
        for call in calls:
            if call.capability != C.FILE_READ:
                continue
            path = call.resource
            kind, features = observe_features(sensitive_path_class, path)
            if not kind:
                continue
            if profile == PROFILE_SERVICE:
                if task and task.actor.role in ADMIN_ROLES:
                    matches.append(RuleMatch("AG-RUNTIME-002", "ALLOW", "SENSITIVE_READ_ADMIN", "MEDIUM", path, features))
                else:
                    matches.append(RuleMatch("AG-RUNTIME-002", "DENY", "SENSITIVE_FILE_READ", "CRITICAL", path, features))
            elif kind in ("name_hint", "template"):
                # 通用 Agent：文件名关键字或模板文件不足以判定密钥文件，内容污点由结果侧检查补齐。
                continue
            elif kind == "credential_store" or profile == PROFILE_STRICT:
                # 主机凭证库任何档案都拒绝；严格档案下项目密钥同样拒绝。
                matches.append(RuleMatch("AG-RUNTIME-002", "DENY", "SENSITIVE_FILE_READ", "CRITICAL", path, features))
            else:
                matches.append(RuleMatch("AG-RUNTIME-002", "ASK", "PROJECT_SECRET_READ", "HIGH", path, features))

    def _r003_mass_read(self, req, task, matches) -> None:
        if req.server == "customer-db" and req.tool == "query":
            if req.arguments.get("tenant") == "*" and (not task or task.actor.role not in ADMIN_ROLES):
                matches.append(RuleMatch("AG-RUNTIME-003", "DENY", "MASS_DATA_READ", "CRITICAL", "tenant=*"))

    def _r004_command(self, req, task, calls, matches) -> None:
        for call in calls:
            if call.capability != C.EXEC:
                continue
            threats, features = observe_features(command_threats, call.resource, self.settings.c2_hosts)
            if threats:
                # 单独下载不构成下载执行，不能把该辅助特征归为最终命中的依据。
                groups = {"command.reverse_shell"} if "REVERSE_SHELL" in threats else set()
                if "BASE64_EXEC" in threats:
                    groups.add("command.base64_exec")
                if "DOWNLOAD_EXEC" in threats:
                    groups.update(("command.download", "command.pipe_to_shell"))
                features = [feature for feature in features if feature["group"] in groups]
                reason = "C2_CONTACT" if "C2_CONTACT" in threats else "COMMAND_INJECTION"
                matches.append(RuleMatch("AG-RUNTIME-004", "DENY", reason, "CRITICAL", ",".join(threats), features))
                return

    def _r023_secret_flow(self, req, task, profile, flow_hits, matches) -> None:
        """数据流溯源（创新检测实施方案 §4）：出网携带秘密指纹、暂存物或敏感文件本身。"""
        if not flow_hits or profile == PROFILE_SERVICE:
            return
        detail = "; ".join(
            f"{hit['kind']}:{hit.get('path') or hit.get('form')}"
            + (f"<-{hit['origin']}" if hit.get("origin") else "")
            + (f"@{hit['trace_id']}" if hit.get("trace_id") and hit["trace_id"] != req.trace_id else "")
            for hit in flow_hits[:4])
        confirmed = any(hit["kind"] != "possible" for hit in flow_hits)
        matches.append(RuleMatch("AG-RUNTIME-023", "DENY" if confirmed else "ASK",
                                 "SECRET_FLOW_EGRESS" if confirmed else "SECRET_FLOW_UNCERTAIN",
                                 "CRITICAL" if confirmed else "MEDIUM", detail))

    def _r006_taint_egress(self, req, task, state, calls, profile, flow_hits, matches) -> None:
        sinks = [call for call in calls if call.sink]
        if not sinks:
            return
        for call in sinks:
            direct, features = observe_features(sensitive_content_types, call.content)
            if direct:
                matches.append(RuleMatch("AG-RUNTIME-006", "DENY", "SENSITIVE_DATA_EGRESS", "CRITICAL",
                                         f"taints={sorted(state.taints) if state else []},direct={direct}", features))
                return
        if not (state and state.has_blocking_taint()):
            return
        taints = f"taints={sorted(state.taints)}"
        if self.feature("flow") and profile == PROFILE_DEVELOPER and not any(hit["kind"] != "possible" for hit in flow_hits):
            # 本次未匹配到已知秘密，不能证明不存在外泄：本机 / 私网放行，外部目标改为确认（§4.2 R006 精化）。
            if F.destination(calls, req.cwd) == "local":
                matches.append(RuleMatch("AG-RUNTIME-006", "ALLOW", "FLOW_CHECKED_LOCAL", "INFO", taints))
            else:
                matches.append(RuleMatch("AG-RUNTIME-006", "ASK", "SENSITIVE_SESSION_EGRESS", "MEDIUM", taints))
            return
        matches.append(RuleMatch("AG-RUNTIME-006", "DENY", "SENSITIVE_DATA_EGRESS", "CRITICAL", taints + ",direct=[]"))

    def _r021_url_exfil(self, req, task, state, calls, matches) -> None:
        # 不可信来源驱动下，URL 中夹带高熵长串：典型的“拼接到查询串外带”形态。
        if not _session_untrusted(task, state):
            return
        for call in calls:
            if call.capability == C.NET_FETCH and URL_BLOB_RE.search(call.resource.split("://", 1)[-1]):
                matches.append(RuleMatch("AG-RUNTIME-021", "DENY", "URL_DATA_EXFIL", "HIGH",
                                         call.resource[:120]))
                return

    def _r017_agent_config(self, req, task, calls, profile, matches) -> None:
        for call in calls:
            if call.capability == C.FILE_WRITE:
                matched, features = observe_features(is_agent_config_path, call.resource)
                if matched:
                    matches.append(RuleMatch("AG-RUNTIME-017", "DENY", "AGENT_CONFIG_TAMPER", "CRITICAL", call.resource, features))
                    return
            if (profile != PROFILE_SERVICE and call.capability == C.EXEC
                    and AGENT_CONFIG_CLI_RE.search(call.resource)):
                decision = "DENY" if profile == PROFILE_STRICT else "ASK"
                matches.append(RuleMatch("AG-RUNTIME-017", decision, "AGENT_CONFIG_TAMPER", "HIGH", "agent cli"))
                return

    def _r007_unknown_tool(self, req, task, manifest, matches) -> None:
        if not req.server or req.unmanaged_server:
            # 内置工具没有 MCP 清单；未受管 server 由 R018 处理。
            return
        if manifest.known_tools is None:
            # 通用 Agent 的受管第三方 server 副作用未知：无可信清单一律拒绝。
            if req.server in SIDE_EFFECT_SERVERS or req.agent != "mcp":
                matches.append(RuleMatch("AG-RUNTIME-007", "DENY", "MANIFEST_UNAVAILABLE", "HIGH", req.server))
            return
        if req.tool not in manifest.known_tools:
            matches.append(RuleMatch("AG-RUNTIME-007", "DENY", "HIDDEN_TOOL", "HIGH", f"{req.server}/{req.tool}"))

    def _r009_poisoned_mcp(self, req, task, calls, profile, manifest, matches) -> None:
        if req.server and req.server in manifest.poisoned_servers:
            high_risk = (req.server in HIGH_RISK_SERVERS
                         or any(call.capability in C.HIGH_RISK_CAPABILITIES for call in calls))
            # 通用 Agent 接入的第三方 server：描述投毒说明 server 本身不可信，任何工具都需确认。
            if high_risk or profile != PROFILE_SERVICE:
                features = list({(f["rule_id"], f.get("revision")): f
                                 for f in manifest.poisoned_features.get(req.server, [])}.values())
                matches.append(RuleMatch("AG-RUNTIME-009", "ASK", "POISONED_TOOL_DESCRIPTION", "MEDIUM", req.server,
                                         features))

    def _r018_unmanaged_mcp(self, req, task, profile, matches) -> None:
        if req.server and req.unmanaged_server:
            decision = "DENY" if profile == PROFILE_STRICT else "ASK"
            matches.append(RuleMatch("AG-RUNTIME-018", decision, "UNMANAGED_MCP_SERVER", "MEDIUM", req.server))

    def _r001_cross_tenant(self, req, task, matches) -> None:
        if req.server == "customer-db" and req.tool == "query" and task:
            tenant = req.arguments.get("tenant", "")
            if tenant != "*" and task.actor.role not in ADMIN_ROLES:
                if task.actor.scope.get("tenant") != tenant:
                    matches.append(RuleMatch("AG-RUNTIME-001", "DENY", "CROSS_TENANT_ACCESS", "CRITICAL",
                                             f"actor_tenant={task.actor.scope.get('tenant')},requested={tenant}"))

    def _r005_skill_capability(self, req, task, matches) -> None:
        if task and task.active_skill:
            allowed = task.active_skill.get("allowed_tools") or []
            if allowed and not skill_allows(allowed, req.server, req.tool, req.raw_tool):
                matches.append(RuleMatch("AG-RUNTIME-005", "DENY", "SKILL_CAPABILITY_VIOLATION", "HIGH",
                                         f"skill={task.active_skill.get('name')},allowed={allowed}"))

    def _r008_untrusted_source(self, req, task, state, calls, profile, matches) -> None:
        if profile == PROFILE_SERVICE:
            if not task:
                return
            untrusted = {label for label in task.source_labels if label.startswith("UNTRUSTED_")}
            if untrusted and (req.server in HIGH_RISK_SERVERS or (req.server, req.tool) == ("customer-db", "query")):
                matches.append(RuleMatch("AG-RUNTIME-008", "DENY", "UNTRUSTED_SOURCE_HIGH_RISK", "HIGH",
                                         ",".join(sorted(untrusted))))
            return
        # 通用 Agent：不可信内容在会话中途进入（网页/文件/MCP 返回），看会话污点。
        untrusted = _session_untrusted(task, state)
        if not untrusted:
            return
        injected = T.POISONED_RESULT in untrusted
        detail = ",".join(sorted(untrusted))
        if any(call.sink for call in calls):
            # 出网：检测到注入后一律拒绝；严格档案下任何不可信来源后都需确认。
            if injected:
                matches.append(RuleMatch("AG-RUNTIME-008", "DENY", "UNTRUSTED_SOURCE_HIGH_RISK", "HIGH", detail))
            elif profile == PROFILE_STRICT:
                matches.append(RuleMatch("AG-RUNTIME-008", "ASK", "UNTRUSTED_SOURCE_CONFIRM", "MEDIUM", detail))
        elif any(call.capability == C.EXEC for call in calls) and (injected or profile == PROFILE_STRICT):
            matches.append(RuleMatch("AG-RUNTIME-008", "ASK", "UNTRUSTED_SOURCE_CONFIRM", "MEDIUM", detail))

    def _r022_injected_instruction(self, req, task, provenance, profile, matches) -> None:
        """参数来源归因（创新检测实施方案 §3）：高危参数来自带指令痕迹的数据 → 拒绝。"""
        if profile == PROFILE_SERVICE:
            # service 业务档案仅记录归因证据，保持显式角色与工具授权策略。
            return
        data = [item for item in provenance if item["source"] == "DATA"]
        for item in data:
            if item.get("cues") and item["risk"] in P.DENY_KINDS:
                matches.append(RuleMatch("AG-RUNTIME-022", "DENY", "INJECTED_INSTRUCTION", "HIGH",
                                         f"{item['token']} <- {item.get('tool') or 'tool'}:{','.join(item['cues'])}"))
                return
        for item in data:
            instructed_fetch = item.get("cues") and item["risk"] == P.PLAIN_FETCH
            untrusted_payload = item.get("untrusted") and item["risk"] in P.CONFIRM_KINDS
            if instructed_fetch or untrusted_payload:
                matches.append(RuleMatch("AG-RUNTIME-022", "ASK", "DATA_DERIVED_TARGET", "MEDIUM",
                                         f"{item['token']} <- {item.get('tool') or 'tool'}"))
                return

    def _r019_persistence(self, req, task, state, calls, profile, matches) -> None:
        for call in calls:
            if call.capability != C.FILE_WRITE:
                continue
            matched, features = observe_features(is_persistence_path, call.resource)
            if matched:
                risky = profile == PROFILE_STRICT or bool(_session_untrusted(task, state))
                matches.append(RuleMatch("AG-RUNTIME-019", "DENY" if risky else "ASK", "PERSISTENCE_WRITE",
                                         "HIGH", call.resource, features))
                return

    def _r020_workspace_escape(self, req, task, state, calls, profile, matches) -> None:
        if profile == PROFILE_SERVICE or not req.cwd:
            return
        # 工作区 = 当前 cwd 与会话起始目录：Agent cd 进子目录后写项目根不算越界。
        # Claude Code 会把越出允许目录的 cd 复位，Hook 的 cwd 不会落到工作区之外。
        roots = [req.cwd] + [root for root in [getattr(state, "workspace", "")] if root]
        for call in calls:
            if call.capability != C.FILE_WRITE or call.origin == C.QUOTED_REDIRECT:
                continue
            path = resolve_path(call.resource, req.cwd)
            if any(path_within(path, root) for root in roots) or is_scratch_path(path):
                continue
            decision = "DENY" if profile == PROFILE_STRICT else "ASK"
            matches.append(RuleMatch("AG-RUNTIME-020", decision, "WORKSPACE_ESCAPE_WRITE", "MEDIUM", path))
            return

    def _context_gate(self, req, task, calls, matches) -> None:
        # 设计 §12：Task Context 缺失时，副作用工具 fail-closed，低风险只读降级放行。
        if task is None:
            if all(call.capability == C.READONLY for call in calls):
                matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "CONTEXT_MISSING_READONLY", "LOW", ""))
            else:
                matches.append(RuleMatch("AG-RUNTIME-000", "DENY", "MISSING_TASK_CONTEXT", "HIGH",
                                         req.server or req.raw_tool))

    def _defaults(self, req, task, calls, profile, matches) -> None:
        if profile == PROFILE_SERVICE:
            self._service_defaults(req, task, calls, matches)
        elif profile == PROFILE_STRICT:
            primary = calls[0].capability if calls else C.MCP_CALL
            if primary in (C.EXEC, C.NET_FETCH):
                matches.append(RuleMatch("AG-RUNTIME-015", "ASK", "STRICT_CONFIRM", "MEDIUM", primary))
            else:
                matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "STRICT_SCOPED", "INFO", primary))
        else:
            # developer：无风险特征时交给 Agent 原生权限流程（Hook 不输出，不代替用户放行）。
            matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "DEFER_TO_NATIVE", "INFO", ""))

    def _service_defaults(self, req, task, calls, matches) -> None:
        server, tool = req.server, req.tool
        if calls and calls[0].capability == C.READONLY:
            matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "SCOPED_READONLY", "INFO", ""))
            return
        if (server, tool) == ("sandbox-exec", "run_test"):
            if sandbox_whitelisted(req.arguments.get("cmd", "")):
                matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "SANDBOX_WHITELIST", "INFO", ""))
            else:
                matches.append(RuleMatch("AG-RUNTIME-015", "ASK", "SANDBOX_WHITELIST_MISMATCH", "MEDIUM", ""))
            return
        if (server, tool) == ("shell-runner", "run"):
            role = task.actor.role if task else ""
            if role in OPS_ROLES:
                matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "OPS_COMMAND", "INFO", role))
            else:
                matches.append(RuleMatch("AG-RUNTIME-015", "ASK", "ROLE_ELEVATION_REQUIRED", "MEDIUM", role))
            return
        if (server, tool) == ("shell-runner", "read_file"):
            role = task.actor.role if task else ""
            if role in OPS_ROLES | {"rd-dev", "sec-analyst"}:
                matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "SCOPED_FILE_READ", "INFO", role))
            else:
                matches.append(RuleMatch("AG-RUNTIME-015", "ASK", "ROLE_ELEVATION_REQUIRED", "MEDIUM", role))
            return
        if (server, tool) == ("customer-db", "query"):
            matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "SCOPED_READ", "INFO",
                                     f"tenant={req.arguments.get('tenant', '')}"))
            return
        if (server, tool) == ("notes-sync", "sync_note"):
            matches.append(RuleMatch("AG-RUNTIME-014", "ALLOW", "NOTE_SYNC", "INFO", ""))
            return
        # 未建模工具默认 ASK（不产生副作用，等待人工/策略补充）。
        matches.append(RuleMatch("AG-RUNTIME-016", "ASK", "UNMODELED_TOOL", "MEDIUM", f"{server}/{tool}"))

    def feature(self, name: str) -> bool:
        check = getattr(self.settings, "feature", None)
        return check(name) if check else True

    def _anomaly(self, request, task, state, calls, profile) -> dict | None:
        """行为基线异常分：只读取已观察执行的上下文，不推进序列。"""
        if state is None or profile == PROFILE_SERVICE or not self.feature("anomaly"):
            return None
        state.behavior.settle()
        if not state.behavior.intents and task and task.intent_summary:
            state.behavior.set_prompt(task.intent_summary)
        result = A.score_request(self.baseline, state.behavior, calls, request.cwd, request.device_id)
        return result

    def _r024_behavior_anomaly(self, req, task, state, anomaly, matches) -> None:
        """异常分是软信号：与不可信来源或秘密污点同时出现才要求确认，否则只记录观察。"""
        if not anomaly or not anomaly["anomalous"]:
            return
        previous = " -> ".join(anomaly["history"]) if "history" in anomaly else anomaly["prev"]
        detail = f"{previous or '<unknown>'} -> {anomaly['symbol']} p={anomaly['probability']} score={anomaly['score']}"
        if _session_untrusted(task, state) or state.has_blocking_taint():
            matches.append(RuleMatch("AG-RUNTIME-024", "ASK", "BEHAVIOR_ANOMALY", "MEDIUM", detail))
        else:
            # 排在默认放行之后：不改变决策与主原因码，只留下观察记录。
            matches.append(RuleMatch("AG-RUNTIME-024", "ALLOW", "BEHAVIOR_ANOMALY_OBSERVED", "LOW", detail))

    def _provenance(self, request, task, state, calls) -> list:
        if state is None or not self.feature("provenance"):
            return []
        # 业务任务信封的 prompt 只在不含不可信来源时视为用户指令。
        extra = []
        if task and task.intent_summary and not any(label.startswith("UNTRUSTED_") for label in task.source_labels):
            extra.append(task.intent_summary)
        return P.attribute_calls(calls, state.sources, request.cwd, extra)

    @staticmethod
    def request_fingerprint(request) -> str:
        return sha256_digest(json.dumps([request.server, request.tool or request.raw_tool, request.arguments],
                                        sort_keys=True, ensure_ascii=False, default=str))

    def _record_behavior(self, request, state, item, execution, record=True) -> None:
        if record and self.feature("anomaly"):
            self.behavior.recorder.record(
                device=request.device_id, agent=request.agent, trace=request.trace_id,
                intents=item["intents"], symbols=item["symbols"], decision=item["decision"],
                call_id=item["key"], execution=execution, sequence=item["sequence"],
                cut_before=item.get("cut_before", False), cut_after=item.get("cut_after", False),
                model_version=item["model_version"])

    def begin_call(self, request, state, decision, call_id, *, observe=False, record=True):
        """Called by the authoritative adapter after all decision overrides."""
        with state.behavior.lock:
            for key, old in list(state.behavior.inflight.items()):
                if time.monotonic() - old["at"] > A.PENDING_TTL or len(state.behavior.inflight) >= A.MAX_PENDING:
                    self.finish_call(request, state, key, "unknown", record=record, match=False)
            item = state.behavior.register(call_id or decision.decision_id, self.request_fingerprint(request), {
                "symbols": A.symbols(request_calls(request), request.cwd), "intents": list(state.behavior.intents),
                "decision": decision.decision, "executes": decision.decision != "DENY" or observe,
                "model_version": (decision.anomaly or {}).get("baseline") or self.baseline.version,
                "candidates": F.plan_request(state.flow, request_calls(request), request.cwd) if self.feature("flow") else [],
                "request": request, "record": record})
            if item is not None:
                self._record_behavior(request, state, item, "pending", record)
                if decision.decision == "DENY" and not observe:
                    self.finish_call(request, state, item["key"], "denied", record=record)
            return item

    def finish_call(self, request, state, call_id, status, *, event_id="", record=True, match=True):
        with state.behavior.lock:
            item = state.behavior.complete(call_id, self.request_fingerprint(request) if match else "", status)
            if item is None:
                return None
            original = item.pop("request", request)
            if status in {"succeeded", "failed", "unknown"} and self.feature("flow"):
                F.commit_staged(state.flow, item["candidates"], original.trace_id,
                                event_id, item["key"], status)
            self._record_behavior(original, state, item, status, record and item["record"])
            return item

    def close_calls(self, state, status="unknown"):
        with state.behavior.lock:
            for key, item in list(state.behavior.inflight.items()):
                self.finish_call(item["request"], state, key, status, match=False)

    # ---- 主入口 ----

    def evaluate(self, request: ToolRequest, task: TaskContext | None,
                 state: T.TaskTaintState | None, manifest: ManifestView) -> Decision:
        started = time.perf_counter()
        matches: list[RuleMatch] = []
        calls = request_calls(request)
        profile = resolve_profile(request, task)
        provenance = self._provenance(request, task, state, calls)
        flow_hits = (F.egress_hits(state.flow, calls, request.cwd)
                     if state is not None and self.feature("flow") else [])
        anomaly = None

        # 优先级：硬 DENY（敏感读/全量读/命令）→ 污点外泄 → 配置篡改 → 隐藏工具 → 投毒 →
        # 未受管 MCP → 租户越权 → Skill 能力 → 不可信来源 → 持久化 → 越界写 → 上下文缺失 → 默认策略。
        self._r002_sensitive_read(request, task, calls, profile, matches)
        self._r003_mass_read(request, task, matches)
        self._r004_command(request, task, calls, matches)
        self._r023_secret_flow(request, task, profile, flow_hits, matches)
        self._r006_taint_egress(request, task, state, calls, profile, flow_hits, matches)
        self._r021_url_exfil(request, task, state, calls, matches)
        self._r017_agent_config(request, task, calls, profile, matches)
        self._r007_unknown_tool(request, task, manifest, matches)
        self._r009_poisoned_mcp(request, task, calls, profile, manifest, matches)
        self._r018_unmanaged_mcp(request, task, profile, matches)
        self._r001_cross_tenant(request, task, matches)
        self._r005_skill_capability(request, task, matches)
        self._r008_untrusted_source(request, task, state, calls, profile, matches)
        self._r022_injected_instruction(request, task, provenance, profile, matches)
        self._r019_persistence(request, task, state, calls, profile, matches)
        self._r020_workspace_escape(request, task, state, calls, profile, matches)
        self._context_gate(request, task, calls, matches)
        self._defaults(request, task, calls, profile, matches)
        if any(match.decision == "DENY" for match in matches):
            anomaly = {"anomalous": False, "skipped_reason": "hard_deny"} if self.feature("anomaly") else None
        else:
            anomaly = self._anomaly(request, task, state, calls, profile)
        self._r024_behavior_anomaly(request, task, state, anomaly, matches)

        for match in matches:
            match.strategy_title = strategy_title(match.rule_id)
            if match.features is None:
                match.features = []

        strictness = {"ALLOW": 0, "ASK": 1, "DENY": 2}
        final = max((match.decision for match in matches), key=lambda d: strictness[d])
        primary = next(match for match in matches if match.decision == final)

        labels = sorted({label for match in matches for label in (match.reason_code,)})[:8]
        decision = Decision(
            decision=final,
            decision_id=new_id("dec"),
            reason_code=primary.reason_code,
            severity=primary.severity,
            matched_rules=matches,
            safe_message=SAFE_MESSAGES.get(primary.reason_code, "blocked by AgentGuard policy"),
            labels=labels,
            rules_version=self.settings.rules_version,
            trace_id=request.trace_id,
            server=request.server,
            tool=request.tool or request.raw_tool,
            provenance=provenance,
            flow=flow_hits,
            flow_status=F.coverage(state.flow, calls, flow_hits) if state is not None and self.feature("flow") else {},
            anomaly=anomaly,
        )
        if state is not None and state.behavior.inflight and decision.flow_status:
            decision.flow_status.update(complete=False)
            decision.flow_status["reasons"] = sorted(set(decision.flow_status["reasons"]) | {"unresolved_execution"})
            if decision.flow_status["result"] == "no_known_secret_match":
                decision.flow_status["result"] = "observation_incomplete"
        decision.latency_ms = (time.perf_counter() - started) * 1000
        return decision


SAFE_MESSAGES = {
    "CROSS_TENANT_ACCESS": "cross-tenant access denied",
    "SENSITIVE_FILE_READ": "sensitive file read denied",
    "PROJECT_SECRET_READ": "reading a secret file requires confirmation",
    "MASS_DATA_READ": "full-tenant data read denied",
    "COMMAND_INJECTION": "malicious command denied",
    "C2_CONTACT": "contact to C2 endpoint denied",
    "SENSITIVE_DATA_EGRESS": "sensitive data egress denied",
    "URL_DATA_EXFIL": "data smuggled in URL denied",
    "AGENT_CONFIG_TAMPER": "modifying agent or AgentGuard configuration denied",
    "HIDDEN_TOOL": "unknown or hidden tool denied",
    "MANIFEST_UNAVAILABLE": "tool manifest unavailable; side-effect denied",
    "UNMANAGED_MCP_SERVER": "MCP server not managed by AgentGuard",
    "RELAY_BYPASS": "MCP call bypassed the AgentGuard relay",
    "SKILL_CAPABILITY_VIOLATION": "tool outside skill allowed-tools denied",
    "UNTRUSTED_SOURCE_HIGH_RISK": "high-risk action from untrusted context denied",
    "UNTRUSTED_SOURCE_CONFIRM": "action after untrusted content requires confirmation",
    "PERSISTENCE_WRITE": "writing to a persistence location",
    "WORKSPACE_ESCAPE_WRITE": "write outside the workspace requires confirmation",
    "MISSING_TASK_CONTEXT": "trusted task context required",
    "ROLE_ELEVATION_REQUIRED": "action requires confirmation",
    "SANDBOX_WHITELIST_MISMATCH": "command outside sandbox whitelist requires confirmation",
    "POISONED_TOOL_DESCRIPTION": "tool description flagged; confirmation required",
    "UNMODELED_TOOL": "unmodeled tool requires confirmation",
    "STRICT_CONFIRM": "action requires confirmation under strict policy",
    "INJECTED_INSTRUCTION": "action target comes from instructions embedded in tool output",
    "DATA_DERIVED_TARGET": "action target comes from untrusted tool output; confirmation required",
    "BEHAVIOR_ANOMALY": "unusual action in a session with untrusted or secret data requires confirmation",
    "SECRET_FLOW_UNCERTAIN": "possible secret data flow requires confirmation",
    "SECRET_FLOW_EGRESS": "sending secret data out of the environment denied",
    "SENSITIVE_SESSION_EGRESS": "network access after reading secrets requires confirmation",
}
