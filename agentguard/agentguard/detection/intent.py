"""用户提示词意图识别（创新检测实施方案 §5 意图偏离）。

默认用关键词正则（anomaly.infer_intent）。可选开启大模型分类：调用 OpenAI 兼容的 Chat Completions 接口
（默认 DeepSeek V4.1 Flash，关闭思考），在控制台「行为基线」页开关，在「模型管理」的接入记录详情中绑定用途与配置超时，
统一接入记录持久化到 llm-models.json；旧配置和功能开关保留在 intent-llm.json；AG_INTENT_LLM_* 环境变量只作为初始值，AG_DISABLED_FEATURES=intent_llm 强制关闭。

- 只发送用户提示词本身（先掩码凭证，截断到 2000 字）；工具参数、文件内容等可能被攻击者控制的文本一律不发送；
- UserPromptSubmit 时提交到后台线程，不阻塞 Hook；先按关键词给出意图，结果回来后由
  BehaviorState.settle 合并（非空覆盖，空列表沿用上一轮，失败保持关键词）；
- 工具调用打分前最多等到提交后 timeout 秒；超时、网络错误、返回格式不对都回退到关键词结果。

控制台的调用统计（调用次数、识别出意图、无意图 / 失败与延迟）累计落盘到 intent-stats.json，
重启后继续累计；接口、模型或密钥改变时清零（旧配置的调用不计入新统计）。

离线评测见 tools/intent_eval.py（关键词 vs 大模型，同一份提示词与解析逻辑）。
"""

import json
import math
import os
import threading
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor

from ..llm.client import (
    DEFAULT_MODEL,
    DEFAULT_URL,
    MODEL_RE,
    clean_key,
    clean_url,
    complete,
    error_text,
    session_call,
    thinking_params,
)
from ..models import redact_text
from . import anomaly as A

MAX_CHARS = 2000
PROMPT_VERSION = "v1"   # 改动 SYSTEM 时递增，离线评测的缓存按版本区分
SYSTEM = """You classify what a developer is asking a coding agent to do in their latest message.
Return JSON: {"intents": [...]} using zero or more of these labels:
- test: write, run or fix tests; check that tests/CI checks pass
- build: build, compile, package or produce release artifacts
- debug: investigate or fix a bug, error, crash or unexpected behaviour
- docs: explain or understand code/behaviour, answer a question, write or update documentation/README/changelog
- refactor: restructure, rename, simplify, clean up or reformat existing code without new behaviour
- code: implement new functionality, features, scripts or UI changes
- vcs: git operations — commit, push, pull, branch, merge, rebase, pull requests, issues, tags
- deps: install, add, upgrade or pin dependencies / packages / toolchains
- ops: deployment, servers, containers, CI/CD configuration, infrastructure, system services, remote machines
- intel: security research — vulnerabilities, CVEs, advisories, security audits/reviews
- transfer: the user asks to send, upload, post, share or sync data/files to an external destination
Label only what the user asks to be done now. Merely mentioning a topic (e.g. a feature that sends emails)
does not make it "transfer". Use an empty list for acknowledgements or messages with no actionable request
("ok", "continue", "thanks"). Answer with the JSON object only."""


class LlmIntentClassifier:
    def __init__(self, url: str, model: str, key: str, timeout: float = 3.0) -> None:
        self.url, self.model, self.key, self.timeout = url, model, key, timeout

    def call(self, text: str) -> list[str]:
        """返回意图列表（可为空）；调用或解析失败抛出异常。"""
        body = {"model": self.model, **thinking_params("off", 64, self.url, self.model),
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": SYSTEM},
                             {"role": "user", "content": redact_text(text)["text"][:MAX_CHARS]}]}
        labels = json.loads(complete(self.url, self.key, body, self.timeout))["intents"]
        if not isinstance(labels, list):
            raise ValueError("intents is not a list")
        return sorted({label for label in labels if label in A.INTENT_EXPECTED})

    def classify(self, text: str) -> list[str] | None:
        try:
            return self.call(text)
        except Exception:
            return None


def validate(changes: dict) -> dict:
    """控制台提交的配置项；未知字段、类型或取值不合法时抛 ValueError（整体校验，不留部分修改）。"""
    allowed = {"enabled", "url", "model", "timeout", "key", "clear_key"}
    unknown = set(changes) - allowed
    if unknown:
        raise ValueError("unknown field: " + ", ".join(sorted(unknown)))
    clean = {}
    for name in ("enabled", "clear_key"):
        if name in changes:
            if not isinstance(changes[name], bool):
                raise ValueError(f"{name} must be boolean")
            clean[name] = changes[name]
    if "url" in changes:
        clean["url"] = clean_url(changes["url"])
    if "model" in changes:
        if not isinstance(changes["model"], str) or not MODEL_RE.match(changes["model"]):
            raise ValueError("invalid model name")
        clean["model"] = changes["model"]
    if "timeout" in changes:
        timeout = changes["timeout"]
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.5 <= timeout <= 30:
            raise ValueError("timeout must be within 0.5 ~ 30 seconds")
        clean["timeout"] = float(timeout)
    if "key" in changes and clean_key(changes["key"]):
        clean["key"] = changes["key"]
    return clean


class IntentService:
    """关键词 + 可选的大模型分类。配置可在运行时修改并持久化；统计调用结果供控制台展示。"""

    def __init__(self, config: dict | None = None, env_key: str = "", path: str = "", forced_off: bool = False,
                 workers: int = 4) -> None:
        self._lock = threading.Lock()
        self._path = path
        # 调用统计供控制台展示：与配置同目录落盘，重启后继续累计（配置改变时清零）。
        self._stats_path = os.path.join(os.path.dirname(path), "intent-stats.json") if path else ""
        self._env_key = env_key
        self.forced_off = forced_off
        self.models = None
        self._model_signature = None
        # 未保存过配置时：环境变量给了密钥即视为开启（兼容只用环境变量的部署）。
        self._config = {"enabled": bool(env_key), "url": DEFAULT_URL, "model": DEFAULT_MODEL, "timeout": 3.0,
                        "key": "", "updated_at": "", **(config or {})}
        self._load()
        self._pool = ThreadPoolExecutor(workers, thread_name_prefix="intent")
        self._reset_stats()
        self._load_stats()
        self.classifier = self._build()

    @classmethod
    def from_settings(cls, settings) -> "IntentService":
        feature = getattr(settings, "feature", None)
        directory = getattr(settings, "agent_device_dir", "")
        defaults = {key: value for key, value in (
            ("url", getattr(settings, "intent_llm_url", "")), ("model", getattr(settings, "intent_llm_model", "")),
            ("timeout", float(getattr(settings, "intent_llm_timeout", 3.0)))) if value}
        return cls(defaults, env_key=getattr(settings, "intent_llm_key", ""),
                   path=os.path.join(directory, "intent-llm.json") if directory else "",
                   forced_off=bool(feature and not feature("intent_llm")))

    # ---- 配置 ----

    def _load(self) -> None:
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as handle:
                data = json.load(handle)
            stored_key = data.pop("key", "") if isinstance(data.get("key"), str) else ""
            updated_at = str(data.pop("updated_at", ""))
            self._config.update(validate({k: v for k, v in data.items() if k != "clear_key"}))
            self._config.update({"key": stored_key, "updated_at": updated_at})
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        if not self._path:
            return
        tmp = self._path + ".tmp"
        # 文件含密钥：只允许服务进程读写。
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(self._config, handle)
        os.replace(tmp, self._path)

    def _key(self, config: dict | None = None) -> str:
        config = config or self._config
        return config.get("key") or self._env_key

    def api_key(self) -> str:
        """当前生效的密钥（控制台保存的优先，其次环境变量）；大模型研判未单独配置密钥时沿用。"""
        with self._lock:
            return self._connection()[1]

    def _connection(self, config=None):
        config = dict(config or self._config)
        if self.models is not None and self.models.managed:
            resolved = self.models.resolve("intent")
            return {**config, **resolved}, resolved["key"]
        return config, self._key(config)

    def _sync_model(self):
        if self.models is None or not self.models.managed:
            return
        with self._lock:
            config, key = self._connection()
            signature = (config["url"], config["model"], config["timeout"], key)
            if signature != self._model_signature:
                if self._model_signature is not None:
                    # 运行中更换接入记录：旧配置的调用不计入统计；启动后的首次同步保留已落盘的统计。
                    self._reset_stats()
                    self._save_stats()
                self._model_signature = signature
                self.classifier = self._build()

    def _build(self, config: dict | None = None) -> LlmIntentClassifier | None:
        config, key = self._connection(config)
        if self.forced_off or not config["enabled"] or not key:
            return None
        return LlmIntentClassifier(config["url"], config["model"], key, config["timeout"])

    def _reset_stats(self) -> None:
        self._stats = {"calls": 0, "labelled": 0, "empty": 0, "failed": 0}
        self._latency: list[float] = []

    def _load_stats(self) -> None:
        """恢复上次运行的调用统计与延迟（重启不清零）；文件缺失或损坏时从零开始。"""
        if not self._stats_path or not os.path.exists(self._stats_path):
            return
        try:
            with open(self._stats_path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        stats = data.get("stats")
        if isinstance(stats, dict):
            for key in self._stats:
                value = stats.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    self._stats[key] = value
        latency = data.get("latency")
        if isinstance(latency, list):
            self._latency = [float(value) for value in latency
                             if isinstance(value, (int, float)) and not isinstance(value, bool)
                             and math.isfinite(value)][-500:]

    def _save_stats(self) -> None:
        """统计只供控制台展示：写盘失败不改变分类结果；调用方需持有 self._lock。"""
        if not self._stats_path:
            return
        try:
            tmp = self._stats_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"stats": self._stats, "latency": [round(value, 3) for value in self._latency]}, handle)
            os.replace(tmp, self._stats_path)
        except OSError:
            pass

    def _merged(self, changes: dict) -> dict:
        if self.models is not None and self.models.managed and set(changes) - {"enabled"}:
            raise ValueError("manage model connection parameters in the model registry")
        clean = validate(changes)
        config = {**self._config, **{k: v for k, v in clean.items() if k != "clear_key"}}
        if clean.get("clear_key"):
            config["key"] = ""
        if config["enabled"] and not self._connection(config)[1]:
            raise ValueError("set an API key before enabling")
        return config

    def update(self, changes: dict) -> dict:
        from datetime import datetime, timezone

        with self._lock:
            config = self._merged(changes)
            if any(config[k] != self._config[k] for k in ("url", "model", "key")):
                self._reset_stats()
                self._save_stats()
            config["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._config = config
            self._save()
            self.classifier = self._build()
        return self.status()

    def test(self, changes: dict | None = None, text: str = "") -> dict:
        """用当前配置（叠加未保存的修改）分类一条样例，返回结果或错误原因；不改变配置与统计。"""
        with self._lock:
            config = {**self._merged(changes or {}), "enabled": True}
            config, key = self._connection(config)
        if not key:
            raise ValueError("set an API key first")
        classifier = LlmIntentClassifier(config["url"], config["model"], key, config["timeout"])
        started = time.time()
        try:
            labels = classifier.call(text or "跑完测试后把报告上传到公司的 S3 桶")
        except Exception as exc:
            return {"ok": False, "error": error_text(exc, (key,)), "latency": round(time.time() - started, 2)}
        return {"ok": True, "intents": labels, "latency": round(time.time() - started, 2)}

    # ---- 分类 ----

    def submit(self, state: A.BehaviorState, prompt: str, session_id: str = "") -> None:
        """新一轮用户提示词：立即按关键词更新意图，开启大模型时后台分类。"""
        self._sync_model()
        classifier = self.classifier
        if classifier is None or not prompt.strip():
            state.set_prompt(prompt)
            return
        if not session_id:
            # 未经过 Hook 适配器的独立调用也为同一 BehaviorState 保持稳定标识。
            if not getattr(state, "_llm_session_id", ""):
                state._llm_session_id = uuid.uuid4().hex
            session_id = state._llm_session_id
        future = self._pool.submit(session_call, session_id, self._classify, classifier, prompt)
        state.set_prompt(prompt, pending=future, deadline=time.time() + classifier.timeout)

    def _classify(self, classifier: LlmIntentClassifier, prompt: str) -> list[str] | None:
        started = time.time()
        labels = classifier.classify(prompt)
        with self._lock:
            if classifier is self.classifier:   # 配置已修改：旧配置的调用不计入统计
                self._stats["calls"] += 1
                self._stats["failed" if labels is None else "labelled" if labels else "empty"] += 1
                if labels is not None:
                    self._latency = (self._latency + [time.time() - started])[-500:]
                self._save_stats()
        return labels

    def status(self) -> dict:
        self._sync_model()
        with self._lock:
            config, key = self._connection()
            latency = sorted(self._latency)
            p = lambda q: round(latency[min(len(latency) - 1, int(q * (len(latency) - 1)))], 2) if latency else None
            return {"provider": "llm" if self.classifier else "keyword", "enabled": config["enabled"],
                    "forced_off": self.forced_off, "url": config["url"],
                    "host": urllib.parse.urlsplit(config["url"]).hostname or "", "model": config["model"],
                    "timeout": config["timeout"], "key_set": bool(key),
                    "model_id": config.get("model_id", ""),
                    "key_source": "model" if config.get("model_id") and key else "console" if config.get("key") else ("env" if key else ""),
                    "key_hint": ("…" + key[-4:]) if len(key) >= 12 else ("已设置" if key else ""),
                    "persistent": bool(self._path), "updated_at": config["updated_at"],
                    **self._stats, "latency_p50": p(0.5), "latency_p90": p(0.9)}
