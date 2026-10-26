"""配置基线规则 AG-STATIC-CFG-001 ~ 008（方案 §5.1）。

先由 parsers.config 转成统一事实，再匹配规则；等级随上下文调整：
示例文件、条件默认值、内部服务网与远程暴露分别定级，不把配置暴露当作实际公网可达。
"""

import ast
import re
from urllib.parse import urlsplit

from ...core.normalize import record_signature_hit, signatures
from ..models import redact_secret
from ..parsers.config import compose_services, key_lines
from ..parsers.py_ast import line_excerpt
from .base import make_finding

VERSION = "1.0"

TRUTHY = {"true", "1", "yes", "on", "enabled"}
FALSY = {"false", "0", "no", "off", "disabled", ""}

FIXED_SECRET_RE = re.compile(r"^[A-Za-z0-9_\-./+:@]{12,}$")
EXAMPLE_PATH_MARKERS = (".example", ".sample", ".template", "example_", "_example")


class ConfigRuleBase:
    rule_version = VERSION
    category = "config"
    title = "配置基线"

    def evaluate(self, facts, context):
        raise NotImplementedError


class WeakSecretRule(ConfigRuleBase):
    rule_id = "AG-STATIC-CFG-001"
    title = "默认弱密钥或固定明文密钥"

    def evaluate(self, facts, context):
        findings = []
        for fact in facts.config_facts(lambda item: item.is_sensitive_key() and _secret_like(item)):
            # 有默认值时按 resolved 判定，同时保留“条件默认”语义。
            conditional = "${" in str(fact.declared)
            value = (fact.resolved if conditional and fact.resolved else fact.value).strip()
            weak = _is_weak(value)
            if not weak and not _looks_fixed(value):
                continue
            is_example = _is_example_path(fact.path)
            if weak:
                severity = "LOW" if is_example else ("MEDIUM" if conditional else "HIGH")
                kind = "条件默认弱密钥" if conditional else "默认弱密钥"
                limitations = "示例文件中的默认值不直接构成部署风险；需结合实际生效配置判断" if is_example else \
                    "未验证该配置在运行时是否被更强来源覆盖"
            else:
                severity = "LOW" if is_example else "MEDIUM"
                kind = "固定明文密钥"
                limitations = "静态发现明文密钥，不代表凭证当前有效或可被访问"
            asset = facts.asset_for_path(fact.path, kinds=("ConfigArtifact", "SecretReference"))
            evidence = facts.evidence_for(
                fact.path, line=fact.line,
                excerpt=f"{fact.key} = {redact_secret(value)}",
                parser="config", pointer=fact.pointer)
            findings.append(make_finding(
                self, context, asset.asset_id if asset else "", severity, "high",
                evidence=[evidence],
                explanation=f"{kind}：{fact.pointer}（值已脱敏）",
                remediation="改为从运行时密钥管理注入；示例文件使用明显的占位符并禁止提交真实值",
                limitations=limitations,
                fingerprint_extra=f"config:{fact.pointer}",
                title=f"{kind}：{fact.key}"))
        for item in facts.env_defaults:
            default = item.get("default")
            if not default or not _is_weak(default):
                continue
            asset = None
            secret_id = facts.secret_refs.get(item["key"])
            if secret_id:
                asset = facts.assets.get(secret_id)
            if asset is None:
                asset = facts.asset_for_path(item["path"], kinds=("SecretReference", "AgentApplication"))
            evidence = facts.evidence_for(
                item["path"], line=item["line"],
                excerpt=f'os.getenv("{item["key"]}", {redact_secret(default)})',
                parser="ast", pointer=f"/{item.get('symbol', '')}")
            findings.append(make_finding(
                self, context, asset.asset_id if asset else "", "HIGH", "high",
                evidence=[evidence],
                explanation=f"代码内弱默认密钥：{item['key']}，环境变量缺失时生效",
                remediation="移除代码内默认密钥，缺失配置时启动失败",
                limitations="未验证部署环境是否已设置强环境变量覆盖该默认值",
                fingerprint_extra=f"code-env:{item['path']}:{item['key']}",
                title=f"代码内弱默认密钥：{item['key']}"))
        return findings


class AuthDisabledRule(ConfigRuleBase):
    rule_id = "AG-STATIC-CFG-002"
    title = "自动登录或鉴权关闭"

    def evaluate(self, facts, context):
        findings = []
        # 键名来自特征规则库：off_when_true 为真即关闭（自动登录 / DISABLE_*），off_when_false 非真即关闭。
        off_when_true = {key.upper() for key in signatures("config.auth_off_when_true")}
        off_when_false = {key.upper() for key in signatures("config.auth_off_when_false")}
        for fact in facts.config_facts(lambda item: isinstance(item.value, (str, bool, int))
                                       and item.key.upper() in off_when_true | off_when_false):
            key = fact.key.upper()
            value = str(fact.value).strip().lower()
            disabled = value in TRUTHY if key in off_when_true else value not in TRUTHY
            if not disabled:
                continue
            record_signature_hit("config.auth_off_when_true" if key in off_when_true
                                 else "config.auth_off_when_false", fact.key)
            exposed = _has_port_mapping(facts, fact.path)
            severity = "HIGH" if exposed else "MEDIUM"
            asset = facts.asset_for_path(fact.path, kinds=("ConfigArtifact", "MCPServer"))
            evidence = facts.evidence_for(
                fact.path, line=fact.line, excerpt=f"{fact.key}={fact.value}",
                parser="config", pointer=fact.pointer)
            findings.append(make_finding(
                self, context, asset.asset_id if asset else "", severity, "high",
                evidence=[evidence],
                explanation=("自动登录/鉴权关闭" + ("，且同一配置存在端口映射" if exposed else "")),
                remediation="关闭自动登录，启用认证并限制管理端口的网络可达范围",
                limitations="端口映射不证明服务实际可从公网访问",
                fingerprint_extra=f"auth:{fact.pointer}",
                title=f"鉴权弱化配置：{fact.key}"))
        return findings


class PrivilegedContainerRule(ConfigRuleBase):
    rule_id = "AG-STATIC-CFG-003"
    title = "特权容器或宿主敏感目录挂载"

    def evaluate(self, facts, context):
        findings = []
        for doc in facts.configs_of("compose"):
            services = compose_services(doc)
            lines = key_lines(doc.raw)
            for service_name, service in services.items():
                if not isinstance(service, dict):
                    continue
                if service.get("privileged") in (True, "true"):
                    findings.append(self._finding(facts, context, doc, service_name, lines,
                                                  "privileged", "HIGH", "容器以特权模式运行"))
                if str(service.get("network_mode") or "") == "host" or str(service.get("pid") or "") == "host":
                    findings.append(self._finding(facts, context, doc, service_name, lines,
                                                  "network_mode/pid", "MEDIUM", "使用宿主命名空间"))
                caps = service.get("cap_add") or []
                if isinstance(caps, list) and any(str(cap).upper() in ("SYS_ADMIN", "ALL") for cap in caps):
                    findings.append(self._finding(facts, context, doc, service_name, lines,
                                                  "cap_add", "HIGH", "授予 SYS_ADMIN/ALL 能力"))
                if service.get("user") in ("root", "0") or service.get("user") == 0:
                    findings.append(self._finding(facts, context, doc, service_name, lines,
                                                  "user", "LOW", "以 root 用户运行容器"))
                for mount in _volumes(service):
                    for pattern, severity in signatures("config.sensitive_mount"):
                        if pattern.search(mount):
                            findings.append(self._finding(
                                facts, context, doc, service_name, lines, "volumes", severity,
                                f"挂载宿主敏感路径：{_redact_mount(mount)}",
                                fingerprint=f"{service_name}:{mount[:40]}"))
                            break
        return findings

    def _finding(self, facts, context, doc, service_name, lines, field, severity,
                 explanation, fingerprint: str = "") -> object:
        asset = facts.asset_for_path(doc.path, kinds=("ConfigArtifact",))
        evidence = facts.evidence_for(
            doc.path, line=lines.get(field, lines.get("services", 0)),
            excerpt=f"{service_name}: {field} {explanation}",
            parser="config", pointer=f"/services/{service_name}/{field}")
        return make_finding(
            self, context, asset.asset_id if asset else "", severity, "high",
            evidence=[evidence], explanation=f"服务 {service_name}：{explanation}",
            remediation="移除特权/宿主挂载；确需访问时使用最小权限的只读挂载或专用代理",
            limitations="是否实际可利用取决于容器内进程与运行时配置",
            fingerprint_extra=f"{service_name}:{field}:{fingerprint}",
            title=f"高权限容器配置：{service_name}")


class GatewayBypassRule(ConfigRuleBase):
    rule_id = "AG-STATIC-CFG-004"
    title = "Agent 可绕开网关直连原始服务"

    def evaluate(self, facts, context):
        findings = []
        for doc in facts.configs_of("compose"):
            services = compose_services(doc)
            if not services:
                continue
            networks = {name: _service_networks(service) for name, service in services.items()}
            lines = key_lines(doc.raw)
            for service_name, service in services.items():
                env = _service_env(service)
                if not _agent_service(service_name, env):
                    continue
                agent_nets = networks.get(service_name, set())
                for key, value in sorted(env.items()):
                    upper = key.upper()
                    if not upper.startswith(("MCP_", "LANGFLOW_", "AGENTGUARD_")):
                        continue
                    host = _host_of(str(value))
                    if not host or host.startswith("agentguard"):
                        continue
                    target = next((name for name in (host, f"mcp-{host}") if name in services), "")
                    if not target:
                        continue
                    if not (agent_nets & networks.get(target, set())):
                        continue
                    asset = facts.asset_for_path(doc.path, kinds=("ConfigArtifact",))
                    evidence = facts.evidence_for(
                        doc.path, line=lines.get(key, lines.get("environment", 0)),
                        excerpt=f"{service_name}.{key} -> {target}（直连原始服务）",
                        parser="config", pointer=f"/services/{service_name}/environment/{key}")
                    findings.append(make_finding(
                        self, context, asset.asset_id if asset else "", "MEDIUM", "high",
                        evidence=[evidence],
                        explanation=f"Agent 服务 {service_name} 与原始服务 {target} 处于同一网络，"
                                    f"且 {key} 未指向 AgentGuard 网关",
                        remediation="将端点统一改写为网关地址，并用网络分区阻止 Agent 直连原始服务",
                        limitations="仅说明声明的网络成员关系，未验证运行时网络策略实际放行",
                        fingerprint_extra=f"{service_name}:{key}:{target}",
                        title=f"网关旁路：{service_name} -> {target}"))
        return findings


class InsecureTransportRule(ConfigRuleBase):
    rule_id = "AG-STATIC-CFG-005"
    title = "远程高风险端点使用不安全传输"

    def evaluate(self, facts, context):
        findings = []
        for fact in facts.config_facts():
            value = fact.value
            if not isinstance(value, str) or not value.lower().startswith("http://"):
                continue
            if not _url_key_relevant(fact.key):
                continue
            host = _host_of(value)
            if not host or _is_loopback(host) or "." not in host:
                continue  # loopback / 内部服务网：在设计内，仅记录上下文
            asset = facts.asset_for_path(fact.path, kinds=("MCPServer", "ConfigArtifact", "Endpoint"))
            evidence = facts.evidence_for(
                fact.path, line=fact.line, excerpt=f"{fact.key} -> http://{host}",
                parser="config", pointer=fact.pointer)
            findings.append(make_finding(
                self, context, asset.asset_id if asset else "", "MEDIUM", "medium",
                evidence=[evidence],
                explanation=f"远程端点 {host} 使用明文 HTTP",
                remediation="改用 HTTPS 并为远程 MCP/工具配置认证与来源校验",
                limitations="配置不可见不等于服务必然无认证；未进行在线探测",
                fingerprint_extra=f"transport:{fact.pointer}",
                title=f"明文传输：{fact.key}"))
        for asset in facts.assets_of_kind("MCPServer"):
            endpoint = str(asset.metadata.get("endpoint") or "")
            if asset.metadata.get("adapter") != "mcp":
                continue
            if not endpoint or _is_loopback(endpoint) or "." not in endpoint:
                continue
            if asset.metadata.get("has_auth_config"):
                continue
            evidence = facts.evidence_for(
                asset.relative_path, line=0, excerpt=f"远程 MCP 端点 {endpoint}，可见配置无认证",
                parser="config", pointer=str(asset.metadata.get("config_pointer") or ""))
            findings.append(make_finding(
                self, context, asset.asset_id, "MEDIUM", "medium",
                evidence=[evidence],
                explanation=f"远程 MCP Server {asset.name} 端点 {endpoint} 未见认证配置",
                remediation="配置 headers/token 并强制 TLS",
                limitations="配置不可见不等于服务必然无认证",
                fingerprint_extra=f"mcpauth:{asset.asset_id}",
                title=f"远程工具缺少可见认证：{asset.name}"))
        return findings


class SkillPermissionRule(ConfigRuleBase):
    rule_id = "AG-STATIC-CFG-006"
    title = "Skill 权限缺失、通配或声明与使用不一致"

    def evaluate(self, facts, context):
        findings = []
        server_names = {asset.name for asset in facts.assets_of_kind("MCPServer")}
        tool_names = {asset.name: str(asset.metadata.get("server") or "")
                      for asset in facts.assets_of_kind("Tool") if len(asset.name) > 2}
        for asset in facts.assets_of_kind("Skill"):
            metadata = asset.metadata
            declared = metadata.get("allowed_tools_declared")
            allowed = metadata.get("allowed_tools") or []
            allowed_set = {str(item).lower() for item in allowed}
            evidence = facts.evidence_for(
                asset.relative_path, line=1, excerpt=f"allowed-tools={allowed}",
                parser="markdown", pointer="/frontmatter/allowed-tools")
            if not declared:
                findings.append(make_finding(
                    self, context, asset.asset_id, "INFO", "high",
                    evidence=[evidence], explanation="Skill 未声明 allowed-tools，权限边界不可审计",
                    remediation="在 frontmatter 显式声明最小 allowed-tools",
                    limitations="未声明权限不等于 Skill 实际调用了工具",
                    title=f"Skill 未声明权限：{asset.name}"))
                continue
            if any(str(item) in ("*", "all", "any") for item in allowed):
                findings.append(make_finding(
                    self, context, asset.asset_id, "MEDIUM", "high",
                    evidence=[evidence], explanation="Skill 使用通配权限声明",
                    remediation="收敛到具体工具/服务名",
                    limitations="通配声明是否被运行时强制执行取决于加载器实现",
                    title=f"Skill 通配权限：{asset.name}"))
            doc = facts.markdown.get(asset.relative_path)
            body = doc.all_text() if doc else ""
            for name in sorted(server_names | set(tool_names)):
                if str(name).lower() in allowed_set:
                    continue
                if tool_names.get(name, "").lower() in allowed_set:
                    continue  # 工具所属服务已声明，不视为越权
                if re.search(rf"(?<![A-Za-z0-9_\-]){re.escape(name)}(?![A-Za-z0-9_\-])", body or ""):
                    mismatch_evidence = facts.evidence_for(
                        asset.relative_path, line=0,
                        excerpt=f"正文引用 {name}，未在 allowed-tools 中声明",
                        parser="markdown", pointer="/body")
                    findings.append(make_finding(
                        self, context, asset.asset_id, "MEDIUM", "medium",
                        evidence=[evidence, mismatch_evidence],
                        explanation=f"Skill 正文引用 {name}，但 allowed-tools={allowed}",
                        remediation="使声明与实际使用一致，或移除未授权引用",
                        limitations="正文引用可能是文档示例；需结合加载器语义复核",
                        fingerprint_extra=f"mismatch:{name}",
                        title=f"Skill 权限声明不一致：{asset.name} -> {name}"))
        return findings


class ModelRceRule(ConfigRuleBase):
    rule_id = "AG-STATIC-CFG-007"
    title = "模型/数据不受控动态加载"

    DANGEROUS_CALLS = ("from_pretrained", "load", "loads")

    def evaluate(self, facts, context):
        findings = []
        for path, module in facts.py_modules.items():
            if module.parse_error or module.tree is None:
                continue
            for node in ast.walk(module.tree):
                if not isinstance(node, ast.Call):
                    continue
                callee = _resolve(module, node.func)
                reason = _dangerous_load(callee, node)
                if not reason:
                    continue
                asset = facts.asset_for_path(path)
                evidence = facts.evidence_for(
                    path, line=getattr(node, "lineno", 0),
                    excerpt=line_excerpt(module.source, getattr(node, "lineno", 0)),
                    parser="ast", pointer="/call")
                findings.append(make_finding(
                    self, context, asset.asset_id if asset else "", "MEDIUM", "high",
                    evidence=[evidence], explanation=reason,
                    remediation="固定可信模型来源并校验摘要；禁用远程代码执行与不安全反序列化",
                    limitations="未加载模型验证实际行为，仅静态识别危险开关",
                    fingerprint_extra=f"modelrce:{path}:{getattr(node, 'lineno', 0)}",
                    title=f"动态加载风险：{callee}"))
        return findings


class UnpinnedDependencyRule(ConfigRuleBase):
    rule_id = "AG-STATIC-CFG-008"
    title = "依赖或镜像未固定版本/摘要"

    def evaluate(self, facts, context):
        findings = []
        seen_images = set()
        for dep in facts.dependencies:
            if dep.ecosystem == "docker":
                if not dep.image or "@sha256:" in dep.image:
                    continue
                if dep.image in seen_images:
                    continue  # 同一镜像在多个 Dockerfile 中只报一条
                seen_images.add(dep.image)
                severity, explanation = "INFO", f"镜像 {dep.image} 未固定摘要"
            elif not dep.version:
                severity, explanation = "LOW", f"依赖 {dep.name}{dep.specifier} 未固定精确版本"
            else:
                continue
            asset = (facts.asset_by_logical("Framework", f"framework:{dep.ecosystem}:{dep.name}")
                     or facts.asset_by_logical("Dependency", f"dep:{dep.ecosystem}:{dep.name}"))
            evidence = facts.evidence_for(
                dep.source_path, line=dep.line, excerpt=dep.image or dep.coordinate(),
                parser="dependency", pointer=f"/{dep.name}")
            findings.append(make_finding(
                self, context, asset.asset_id if asset else "", severity, "high",
                evidence=[evidence], explanation=explanation,
                remediation="锁定精确版本或镜像摘要，并使用可复现构建",
                limitations="可重复性风险，不代表组件本身恶意",
                fingerprint_extra=f"pin:{dep.ecosystem}:{dep.name}:{dep.version or dep.image}",
                title=f"未固定版本：{dep.name}"))
        return findings


# ---------- 辅助 ----------

def _is_weak(value: str) -> bool:
    from .ruleset import Ruleset

    return Ruleset().is_weak_secret(value) or len(value.strip()) < 8


def _looks_fixed(value: str) -> bool:
    return bool(FIXED_SECRET_RE.match(value.strip()))


NON_SECRET_SUFFIXES = ("_ttl", "_seconds", "_timeout", "_port", "_days", "_bytes", "_size",
                       "_interval", "_count", "_mode", "_enabled")
NON_SECRET_VALUES = {"true", "false", "yes", "no", "on", "off", "enabled", "disabled",
                     "none", "null", "auto", "debug", "info", "warning", "error"}


def _secret_like(fact) -> bool:
    """布尔开关、端口/TTL 等非凭证值不按密钥处理。"""
    value = fact.value
    if not isinstance(value, str) or not value.strip():
        return False
    lowered = value.strip().lower()
    if lowered in NON_SECRET_VALUES or value.strip().isdigit():
        return False
    key = fact.key.lower()
    if key.endswith(NON_SECRET_SUFFIXES):
        return False
    return True


def _is_example_path(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in EXAMPLE_PATH_MARKERS)


def _has_port_mapping(facts, path: str) -> bool:
    doc = facts.configs.get(path)
    if doc is None:
        return False
    services = compose_services(doc)
    for service in services.values():
        if isinstance(service, dict) and service.get("ports"):
            return True
    return bool(doc.find(lambda fact: fact.key == "ports"))


def _volumes(service: dict) -> list:
    volumes = service.get("volumes") or []
    result = []
    if isinstance(volumes, list):
        for item in volumes:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                result.append(str(item.get("source") or item.get("bind") or ""))
    elif isinstance(volumes, dict):
        result.extend(str(key) for key in volumes)
    return result


def _redact_mount(mount: str) -> str:
    return mount if len(mount) <= 80 else mount[:77] + "..."


def _service_networks(service: dict) -> set:
    networks = service.get("networks")
    if isinstance(networks, dict):
        return set(networks)
    if isinstance(networks, list):
        return set(networks)
    return {"default"}


def _service_env(service: dict) -> dict:
    environment = service.get("environment") or {}
    if isinstance(environment, dict):
        return {str(key): str(value) for key, value in environment.items()}
    result = {}
    if isinstance(environment, list):
        for item in environment:
            text = str(item)
            key, _, value = text.partition("=")
            result[key.strip()] = value.strip()
    return result


def _agent_service(service_name: str, env: dict) -> bool:
    lower = service_name.lower()
    if any(token in lower for token in ("opspilot", "agent", "runner")):
        return True
    return any(key.upper().startswith(("MCP_", "AGENTGUARD_")) for key in env)


def _host_of(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return ""
    host = parts.hostname or ""
    return host


def _is_loopback(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def _url_key_relevant(key: str) -> bool:
    upper = key.upper()
    hints = ("MCP_", "LANGFLOW", "AGENTGUARD", "BASE_URL", "ENDPOINT", "SERVER_URL", "OPENAI_API_BASE")
    return any(hint in upper for hint in hints)


def _resolve(module, func) -> str:
    from ..analysis.decode import resolve_name

    return resolve_name(func, module.aliases) or ""


def _dangerous_load(callee: str, node: ast.Call) -> str:
    kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
    if _const_true(kwargs.get("allow_dangerous_deserialization")):
        return "允许危险反序列化（allow_dangerous_deserialization=True）"
    if callee.endswith("from_pretrained") and _const_true(kwargs.get("trust_remote_code")):
        return "from_pretrained 开启 trust_remote_code，加载远程代码"
    if callee.endswith("torch.load") and _const_false(kwargs.get("weights_only")):
        return "torch.load 显式关闭 weights_only"
    if callee.endswith(("pickle.load", "pickle.loads")):
        return "使用 pickle 反序列化不可信数据"
    if callee.endswith("yaml.load") and "Loader" not in kwargs and "loader" not in kwargs:
        return "yaml.load 未指定 SafeLoader"
    return ""


def _const_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _const_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False
