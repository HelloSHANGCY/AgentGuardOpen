"""依赖清单与镜像引用解析。

声明范围与锁定版本分别保存，不能把范围当作实际安装版本；不安装依赖验证。
"""

import json
import re
from dataclasses import dataclass

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

REQ_LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.\-]+)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>(?:[<>=!~]=?[^;]*)?)\s*(?P<marker>;.*)?$"
)
REQ_INCLUDE_RE = re.compile(r"^(?:-r|--requirement)\s+(?P<path>.+)$")
PIN_RE = re.compile(r"^==\s*(?P<version>[0-9][^,;\s]*)$")


@dataclass
class Dependency:
    name: str
    ecosystem: str = "pypi"
    specifier: str = ""
    version: str = ""  # 仅精确锁定版本
    resolved: bool = False
    source_path: str = ""
    line: int = 0
    source_kind: str = ""
    extras: str = ""
    marker: str = ""
    image: str = ""

    @property
    def pinned(self) -> bool:
        return bool(self.version) or (self.ecosystem == "docker" and ":" in self.image and "@sha256:" in self.image)

    def coordinate(self) -> str:
        base = f"{self.name}=={self.version}" if self.version else f"{self.name}{self.specifier}"
        return f"{self.ecosystem}:{base}"

    def as_dict(self) -> dict:
        return vars(self)


def parse_requirements(path: str, text: str, line_offset: int = 0) -> list:
    deps: list = []
    logical = ""
    for index, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            logical += line[:-1] + " "
            continue
        full = (logical + line).strip()
        logical = ""
        lineno = index + line_offset
        if full.startswith(("-r", "--requirement", "-e", "--editable", "--index-url", "--extra-index-url",
                            "--find-links", "--no-binary", "--only-binary", "--hash")):
            continue
        match = REQ_LINE_RE.match(full)
        if not match:
            continue
        name = match.group("name")
        spec = (match.group("spec") or "").strip()
        pin = PIN_RE.match(spec)
        deps.append(Dependency(
            name=name, ecosystem="pypi", specifier=spec,
            version=pin.group("version") if pin else "",
            resolved=bool(pin), source_path=path, line=lineno,
            source_kind="requirements", extras=match.group("extras") or "",
            marker=match.group("marker") or "",
        ))
    return deps


def parse_package_json(path: str, text: str) -> list:
    deps: list = []
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return deps
    for section, kind in (("dependencies", "dependencies"), ("devDependencies", "devDependencies")):
        for name, spec in (data.get(section) or {}).items():
            deps.append(Dependency(name=name, ecosystem="npm", specifier=str(spec),
                                   source_path=path, source_kind=f"package.json:{kind}"))
    return deps


def parse_lockfile(path: str, text: str) -> list:
    lowered = path.lower()
    try:
        if lowered.endswith(".json"):
            return _parse_json_lock(path, text)
        if tomllib:
            data = tomllib.loads(text or "")
            if isinstance(data.get("package"), list):  # poetry.lock / uv.lock
                return [Dependency(name=str(item.get("name", "")), ecosystem="pypi",
                                   version=str(item.get("version", "")), resolved=True,
                                   source_path=path, source_kind="lockfile")
                        for item in data["package"] if item.get("name")]
    except (ValueError, TypeError, json.JSONDecodeError):
        return []
    return _parse_yarn_lock(path, text)


def _parse_json_lock(path: str, text: str) -> list:
    deps: list = []
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return deps
    if isinstance(data.get("packages"), dict):  # package-lock v2/v3
        for key, item in data["packages"].items():
            if not key or not isinstance(item, dict):
                continue
            name = key.split("node_modules/")[-1]
            deps.append(Dependency(name=name, ecosystem="npm", version=str(item.get("version", "")),
                                   resolved=True, source_path=path, source_kind="package-lock"))
    if isinstance(data.get("default"), dict):  # Pipfile.lock
        for name, item in data["default"].items():
            version = ""
            if isinstance(item, dict) and isinstance(item.get("version"), str):
                version = item["version"].lstrip("=") if item["version"].startswith("==") else ""
            deps.append(Dependency(name=name, ecosystem="pypi", version=version, resolved=bool(version),
                                   source_path=path, source_kind="pipfile.lock"))
    return deps


def _parse_yarn_lock(path: str, text: str) -> list:
    deps: list = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith(("version", "#")):
            current = stripped[:-1].strip('"').split("@")[0].strip('"')
        elif stripped.startswith("version") and current:
            version = stripped.split(None, 1)[-1].strip('"')
            deps.append(Dependency(name=current, ecosystem="npm", version=version, resolved=True,
                                   source_path=path, source_kind="yarn.lock"))
            current = ""
    return deps


def parse_dockerfile(path: str, text: str) -> tuple:
    """返回 (镜像依赖, 未固定版本的镜像数)。"""
    deps: list = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped.upper().startswith("FROM "):
            ref = stripped.split(None, 1)[1].split()[0]
            name, tag = _split_image(ref)
            deps.append(Dependency(name=name, ecosystem="docker", specifier=tag, image=ref,
                                   version=tag if _is_exact_tag(tag) else "",
                                   source_path=path, line=index + 1, source_kind="dockerfile"))
        index += 1
    return deps, [dep for dep in deps if not _is_digest_pinned(dep.image)]


def _split_image(ref: str) -> tuple:
    digest_split = ref.split("@", 1)
    name_tag = digest_split[0]
    if ":" in name_tag.rsplit("/", 1)[-1]:
        name, _, tag = name_tag.rpartition(":")
        return name, tag
    return name_tag, ""


def _is_exact_tag(tag: str) -> bool:
    return bool(tag) and tag.lower() != "latest" and not any(ch in tag for ch in "*^~<>=")


def _is_digest_pinned(ref: str) -> bool:
    return "@sha256:" in ref


KNOWN_FRAMEWORKS = {
    # 包名 -> (框架类别, 展示名)
    "langchain": ("agent_orchestration", "LangChain"),
    "langgraph": ("agent_orchestration", "LangGraph"),
    "langflow": ("agent_orchestration", "Langflow"),
    "crewai": ("agent_orchestration", "CrewAI"),
    "autogen": ("agent_orchestration", "AutoGen"),
    "pyautogen": ("agent_orchestration", "AutoGen"),
    "llama-index": ("agent_orchestration", "LlamaIndex"),
    "llama_index": ("agent_orchestration", "LlamaIndex"),
    "openai": ("llm_client", "OpenAI SDK"),
    "anthropic": ("llm_client", "Anthropic SDK"),
    "google-generativeai": ("llm_client", "Google Generative AI"),
    "fastapi": ("web_framework", "FastAPI"),
    "flask": ("web_framework", "Flask"),
    "django": ("web_framework", "Django"),
    "uvicorn": ("web_framework", "Uvicorn"),
    "starlette": ("web_framework", "Starlette"),
    "mcp": ("protocol_sdk", "MCP Python SDK"),
    "model-context-protocol": ("protocol_sdk", "MCP Python SDK"),
    "transformers": ("model_runtime", "Transformers"),
    "torch": ("model_runtime", "PyTorch"),
    "tensorflow": ("model_runtime", "TensorFlow"),
    "vllm": ("model_runtime", "vLLM"),
    "ollama": ("model_runtime", "Ollama"),
    "gradio": ("ui_runtime", "Gradio"),
    "streamlit": ("ui_runtime", "Streamlit"),
    "celery": ("task_queue", "Celery"),
    "redis": ("infrastructure", "Redis"),
    "sqlalchemy": ("infrastructure", "SQLAlchemy"),
    "psycopg2-binary": ("infrastructure", "psycopg2"),
    "psycopg": ("infrastructure", "psycopg"),
    "requests": ("http_client", "Requests"),
    "httpx": ("http_client", "HTTPX"),
    "aiohttp": ("http_client", "Aiohttp"),
}


def framework_for_package(name: str) -> tuple | None:
    return KNOWN_FRAMEWORKS.get(name.lower())


def is_requirement_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name.startswith("requirements") or name.startswith("constraints")
