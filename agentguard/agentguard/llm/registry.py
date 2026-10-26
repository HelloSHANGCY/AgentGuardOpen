"""模型接入记录与用途绑定。密钥只写不读；用途不自动启用对应功能。"""

import copy
import json
import math
import os
import tempfile
import threading
import time
import urllib.parse
import uuid

from .client import EFFORTS, MODEL_RE, chat_json, clean_key, clean_url, error_text
from .discovery import discover_models
from .providers import PRESETS, validate_connection

PURPOSES = {
    "intent": {"label": "意图识别", "timeout": 3.0, "min_timeout": 0.5, "max_timeout": 30.0},
    "approval": {"label": "危险审批", "timeout": 3.0, "min_timeout": 0.5, "max_timeout": 120.0},
    "analysis": {"label": "异步分析", "timeout": 60.0, "min_timeout": 5.0, "max_timeout": 180.0},
}
FIELDS = ("name", "provider", "url", "model", "effort")


class BindingConflict(ValueError):
    pass


def key_hint(key):
    return "…" + key[-4:] if len(key) >= 12 else "已设置" if key else ""


def validate_model(changes, previous=None, check_provider=True):
    if not isinstance(changes, dict) or set(changes) - {*FIELDS, "key", "clear_key", "usages", "replace_usages"}:
        raise ValueError("invalid model configuration fields")
    result = {"name": "", "provider": "", "url": "", "model": "", "effort": "off", "key": "",
              **(previous or {})}
    for field in ("name", "provider"):
        value = changes.get(field, result[field])
        if not isinstance(value, str) or not value.strip() or len(value) > 80 or any(ord(c) < 32 for c in value):
            raise ValueError(f"{field} must be a nonempty string of at most 80 characters")
        result[field] = value.strip()
    result["url"] = clean_url(changes.get("url", result["url"]))
    if urllib.parse.urlsplit(result["url"]).username is not None:
        raise ValueError("put credentials in the API key field, not the URL")
    result["model"] = changes.get("model", result["model"])
    if not isinstance(result["model"], str) or not MODEL_RE.fullmatch(result["model"]):
        raise ValueError("invalid model name")
    result["effort"] = changes.get("effort", result["effort"])
    if result["effort"] not in EFFORTS:
        raise ValueError("invalid thinking effort")
    if check_provider:
        validate_connection(result["url"], result["model"], result["effort"])
    for field in ("clear_key", "replace_usages"):
        if field in changes and not isinstance(changes[field], bool):
            raise ValueError(f"{field} must be boolean")
    if "key" in changes:
        key = clean_key(changes["key"])
        if key and changes.get("clear_key"):
            raise ValueError("cannot replace and clear a key together")
        if key:
            result["key"] = key
    if changes.get("clear_key"):
        result["key"] = ""
    return result


def validate_usages(usages):
    if not isinstance(usages, dict) or set(usages) - PURPOSES.keys():
        raise ValueError("unknown model purpose")
    result = {}
    for purpose, config in usages.items():
        if not isinstance(config, dict) or set(config) - {"timeout", "effort"}:
            raise ValueError("invalid purpose configuration fields")
        spec = PURPOSES[purpose]
        timeout = config.get("timeout", spec["timeout"])
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not spec["min_timeout"] <= timeout <= spec["max_timeout"]):
            raise ValueError(f"{purpose} timeout must be within {spec['min_timeout']:g} ~ {spec['max_timeout']:g} seconds")
        clean = {"timeout": float(timeout)}
        if config.get("effort") is not None:
            if config["effort"] not in EFFORTS or purpose == "intent" and config["effort"] != "off":
                raise ValueError("invalid purpose thinking effort")
            clean["effort"] = config["effort"]
        result[purpose] = clean
    return result


class ModelRegistry:
    def __init__(self, path="", legacy_loader=None):
        self._lock = threading.RLock()
        self._path = path
        self._legacy_loader = legacy_loader
        self._models = {}
        self._bindings = {}
        self._revision = 0
        self.managed = False
        self.chat = chat_json
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as handle:
                    data = json.load(handle)
                if (data["version"] != 1 or not isinstance(data["models"], dict) or len(data["models"]) > 256
                        or not isinstance(data["bindings"], dict)):
                    raise ValueError("invalid registry")
                for model_id, item in data["models"].items():
                    if not isinstance(model_id, str) or not isinstance(item, dict):
                        raise ValueError("invalid model")
                    model = validate_model({field: item[field] for field in (*FIELDS, "key")}, check_provider=False)
                    self._models[model_id] = {**model, "created_at": item.get("created_at", ""),
                                              "updated_at": item.get("updated_at", "")}
                for purpose, binding in data["bindings"].items():
                    model_id = binding["model_id"]
                    if model_id not in self._models:
                        raise ValueError("missing bound model")
                    clean = validate_usages({purpose: {k: v for k, v in binding.items() if k != "model_id"}})
                    self._bindings[purpose] = {"model_id": model_id, **clean[purpose]}
                self._revision = int(data.get("revision", 0))
                self.managed = True
            except (OSError, ValueError, KeyError, TypeError) as exc:
                # 已启用统一管理后，损坏的数据不能悄悄回退到旧密钥或旧绑定。
                raise ValueError("model registry could not be loaded") from exc

    def _seed_legacy(self):
        if self.managed or not self._legacy_loader:
            return
        connections = self._legacy_loader()
        with self._lock:
            if self.managed:
                return
            models, bindings = {}, {}
            for purpose, config in connections.items():
                if not config.get("key"):
                    continue
                signature = tuple(config[k] for k in ("url", "model", "key", "effort"))
                model_id = next((mid for mid, item in models.items()
                                 if tuple(item[k] for k in ("url", "model", "key", "effort")) == signature), "")
                if not model_id:
                    model_id = "mdl-legacy-" + purpose
                    models[model_id] = {"name": PURPOSES[purpose]["label"] + "模型",
                                        "provider": (urllib.parse.urlsplit(config["url"]).hostname or "OpenAI 兼容")[:80],
                                        **{k: config[k] for k in ("url", "model", "key", "effort")},
                                        "created_at": "", "updated_at": ""}
                bindings[purpose] = {"model_id": model_id, "timeout": config["timeout"]}
            self._models, self._bindings = models, bindings

    def _public(self, model_id, model):
        return {"model_id": model_id, **{k: model[k] for k in FIELDS},
                "created_at": model["created_at"], "updated_at": model["updated_at"],
                "key_set": bool(model["key"]), "key_hint": key_hint(model["key"]),
                "usages": {p: {k: v for k, v in b.items() if k != "model_id"}
                           for p, b in self._bindings.items() if b["model_id"] == model_id}}

    def overview(self):
        self._seed_legacy()
        with self._lock:
            return {"models": [self._public(mid, model) for mid, model in self._models.items()],
                    "bindings": copy.deepcopy(self._bindings), "purposes": copy.deepcopy(PURPOSES),
                    "managed": self.managed, "revision": self._revision, "presets": copy.deepcopy(PRESETS)}

    def resolve(self, purpose):
        if not self.managed:
            return None
        with self._lock:
            binding = self._bindings.get(purpose)
            if binding is None:
                return {"bound": False, "model_id": "", "url": "", "model": "", "key": "", "effort": "off",
                        "timeout": PURPOSES[purpose]["timeout"], "revision": self._revision}
            model = self._models[binding["model_id"]]
            effort = "off" if purpose == "intent" else binding.get("effort", model["effort"])
            return {**model, **binding, "bound": True, "effort": effort, "revision": self._revision}

    def _commit(self, models, bindings):
        revision = self._revision + 1
        if self._path:
            directory = os.path.dirname(self._path) or "."
            os.makedirs(directory, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".llm-models-", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump({"version": 1, "revision": revision, "models": models, "bindings": bindings}, handle)
                os.replace(temporary, self._path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        self._models, self._bindings = models, bindings
        self._revision, self.managed = revision, True

    def save(self, changes, model_id=None):
        self._seed_legacy()
        with self._lock:
            if model_id is not None and model_id not in self._models:
                raise KeyError("model not found")
            if model_id is None and len(self._models) >= 256:
                raise ValueError("model limit reached")
            previous = self._models.get(model_id)
            model = validate_model(changes, previous)
            model_id = model_id or "mdl-" + uuid.uuid4().hex
            models, bindings = copy.deepcopy(self._models), copy.deepcopy(self._bindings)
            if "usages" in changes:
                usages = validate_usages(changes["usages"])
                for purpose in usages:
                    owner = bindings.get(purpose, {}).get("model_id")
                    if owner and owner != model_id and not changes.get("replace_usages"):
                        raise BindingConflict(PURPOSES[purpose]["label"] + "已绑定到「" + models[owner]["name"] + "」")
                bindings = {p: b for p, b in bindings.items() if b["model_id"] != model_id}
                bindings.update({p: {"model_id": model_id, **config} for p, config in usages.items()})
            # 修改模型但省略 usages 时，也校验已有用途，整体失败不留下部分更新。
            for purpose, binding in bindings.items():
                if binding["model_id"] == model_id:
                    effort = "off" if purpose == "intent" else binding.get("effort", model["effort"])
                    validate_connection(model["url"], model["model"], effort)
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            model.update(created_at=previous["created_at"] if previous else now, updated_at=now)
            models[model_id] = model
            self._commit(models, bindings)
            return self._public(model_id, model)

    def delete(self, model_id):
        self._seed_legacy()
        with self._lock:
            if model_id not in self._models:
                raise KeyError("model not found")
            if any(b["model_id"] == model_id for b in self._bindings.values()):
                raise BindingConflict("请先在详情中解除用途绑定")
            models = copy.deepcopy(self._models)
            del models[model_id]
            self._commit(models, copy.deepcopy(self._bindings))

    def discover(self, config, model_id=None):
        if not isinstance(config, dict):
            raise ValueError("config must be an object")
        self._seed_legacy()
        with self._lock:
            previous = None
            if model_id is not None:
                if model_id not in self._models:
                    raise KeyError("model not found")
                previous = self._models[model_id]
            url = config.get("url") or (previous["url"] if previous else "")
            key = config.get("key") or ""
            if not isinstance(url, str) or not isinstance(key, str):
                raise ValueError("url and key must be strings")
            url = clean_url(url)
            key = clean_key(key)
            if previous and not key and url.rstrip("/") == previous["url"].rstrip("/"):
                key = previous["key"]
            if not key:
                raise ValueError("请先填写 API Key 再获取模型")
            provider = config.get("provider") or (previous or {}).get("provider") or ""
        return discover_models(url, key, provider)

    def test(self, config, model_id=None):
        if model_id is not None and not isinstance(model_id, str):
            raise ValueError("model_id must be a string")
        self._seed_legacy()
        with self._lock:
            if model_id is not None and model_id not in self._models:
                raise KeyError("model not found")
            model = validate_model(config, self._models.get(model_id))
        if not model["key"]:
            raise ValueError("set an API key first")
        started = time.monotonic()
        try:
            self.chat(model["url"], model["model"], model["key"], 30.0,
                      'Return a JSON object containing {"ok": true}.', 'Test this model connection.', 64, model["effort"])
            return {"ok": True, "latency": round(time.monotonic() - started, 2)}
        except Exception as exc:  # noqa: BLE001
            # 无论供应商错误格式如何，不能回显当前接入记录的完整密钥。
            error = error_text(exc, (model["key"],))
            return {"ok": False, "error": error, "latency": round(time.monotonic() - started, 2)}
