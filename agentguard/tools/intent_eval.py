#!/usr/bin/env python3
"""意图识别离线评测：关键词正则 vs 大模型分类（agentguard/detection/intent.py，创新检测实施方案 §5 意图偏离）。

    AG_INTENT_LLM_KEY=... python3 tools/intent_eval.py                # 默认 DeepSeek V4.1 Flash，关闭思考
    AG_INTENT_LLM_KEY=... python3 tools/intent_eval.py --fixtures     # 另外比较对评测夹具异常检测的影响

评测集：
- gold：SWE-chat test 侧候选的人工标注（data/intent/gold_annotated.json，多标签，不进仓库）；
- synth：手写的中英文提示词（tools/intent_synthetic.json，含外发意图的难负例）；
- en / zh：SWE-chat 用户提示词（tools/fetch_swechat_prompts.py 抽取）按会话哈希切出的 test 侧抽样，
  prompt_intent 是大模型标注的弱标签，映射到本项目意图后评估。
缺少的数据文件跳过对应评测集。大模型结果按（模型, 提示词版本, 文本）缓存在 data/intent/cache/，重复运行不再计费。
密钥只从环境变量读取，接口与模型同服务端配置（AG_INTENT_LLM_URL / AG_INTENT_LLM_MODEL）。
"""

import argparse
import hashlib
import json
import os
import pathlib
import random
import re
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.detection import anomaly as A  # noqa: E402
from agentguard.detection import behavior as B  # noqa: E402
from agentguard.detection import intent as I  # noqa: E402

DATA = ROOT / "data" / "intent"
# SWE-chat 标签 → 本项目意图；other 视为“无明确意图”（None）。
LABEL_MAP = {"test": "test", "debug": "debug", "refactor": "refactor", "understand": "docs",
             "create new code": "code", "git": "vcs", "connect": "ops", "other": None}
EXPECTED = A.INTENT_EXPECTED
INTENTS = list(EXPECTED)
ZH = ("CHINESE", "CHINESE_T")
# SWE-chat 的“用户提示词”里混有注入的技能 / 系统文本、贴回的工具输出和自动化评审模板，不是用户输入的意图。
INJECTED = re.compile(r"^\s*(<[a-z_]+[ >]|\[\d+\] |\{\s*\"|# (AGENTS\.md|Global Agent)|## (SKILL|What to Look For|Output)|"
                      r"You are reviewing the changes|Review the changes on branch|>>> TRANSCRIPT|"
                      r"The Codex agent has requested|<subagent|You are (Agent|part of))")


def fraction(key: str) -> float:
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) / 0x100000000


def text_of(row: dict) -> str:
    return (row.get("content") or row.get("text") or "")[:500]


def swechat_sets(path: pathlib.Path, size: int, seed: int = 23) -> dict:
    """按会话哈希取 test 侧，英文 / 中文各抽 size 条，去掉注入文本。"""
    if not path.exists():
        return {}
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("prompt_intent") in LABEL_MAP and fraction(row["session_id"]) >= 0.5 \
                    and not INJECTED.match(text_of(row)):
                rows.append({**row, "gold": LABEL_MAP[row["prompt_intent"]]})
    rng = random.Random(seed)
    sets = {}
    for name, match in (("en", lambda lang: lang == "ENGLISH"), ("zh", lambda lang: lang in ZH)):
        pool = [row for row in rows if match(row["language"])]
        sets[name] = rng.sample(pool, min(size, len(pool)))
    return sets


def eval_sets(size: int) -> dict:
    sets = {}
    annotated = DATA / "gold_annotated.json"
    if annotated.exists():
        sets["gold"] = [row for row in json.loads(annotated.read_text(encoding="utf-8"))
                        if not INJECTED.match(text_of(row))]
    sets["synth"] = json.loads((ROOT / "tools" / "intent_synthetic.json").read_text(encoding="utf-8"))
    sets.update(swechat_sets(DATA / "swechat_prompts.jsonl", size))
    return sets


# ---------- 指标 ----------

def allowed(intents) -> set:
    return set().union(*(EXPECTED[name] for name in intents)) if intents else set()


def gold_set(row: dict) -> set:
    gold = row["gold"]
    return set(gold) if isinstance(gold, list) else ({gold} if gold else set())


def evaluate(rows: list[dict], preds: list[list[str]], min_n: int = 20) -> dict:
    """gold 可以是单标签（SWE-chat 弱标签）或多标签列表（人工标注集、合成集）。"""
    per = defaultdict(Counter)
    covered = labelled = none_ok = none_total = loose = strict = 0
    for row, pred in zip(rows, preds):
        gold = gold_set(row)
        for name in pred:
            per[name]["tp" if name in gold else "fp"] += 1
        for name in gold - set(pred):
            per[name]["fn"] += 1
        if not gold:
            none_total += 1
            none_ok += not pred
            continue
        labelled += 1
        covered += bool(pred)
        # 安全相关：预测意图放行了金标意图不预期的敏感类别（偏离会被漏掉）；
        # 或预测非空却缺少金标意图预期的类别（偏离误报）。
        loose += bool(allowed(pred) - allowed(gold))
        strict += bool(pred) and bool(allowed(gold) - allowed(pred))
    f1 = {}
    for name in INTENTS:
        c = per[name]
        p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 0.0
        r = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0.0
        f1[name] = {"f1": round(2 * p * r / (p + r), 3) if p + r else 0.0, "n": c["tp"] + c["fn"]}
    macro = [item["f1"] for item in f1.values() if item["n"] >= min_n]
    return {"macro_f1": round(sum(macro) / len(macro), 3) if macro else 0.0,
            "coverage": round(covered / labelled, 3) if labelled else 0.0,
            "none_acc": round(none_ok / none_total, 3) if none_total else None,
            "over_permissive": round(loose / labelled, 3) if labelled else 0.0,
            "over_strict": round(strict / labelled, 3) if labelled else 0.0,
            "per_class": {name: item for name, item in f1.items() if item["n"]}}


# ---------- 大模型 ----------

class CachedClassifier:
    """包装服务端分类器：失败重试两次，结果与延迟按文本缓存（同一模型与提示词版本）。"""

    def __init__(self, classifier: I.LlmIntentClassifier, workers: int) -> None:
        self.classifier, self.workers = classifier, workers
        self.path = DATA / "cache" / f"llm-{classifier.model}-{I.PROMPT_VERSION}.json"
        self.cache = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    @staticmethod
    def digest(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:20]

    def _call(self, text: str) -> dict | None:
        for attempt in range(3):
            started = time.time()
            labels = self.classifier.classify(text)
            if labels is not None:
                return {"intents": labels, "latency": time.time() - started}
            time.sleep(1 + attempt)
        return None

    def predict(self, texts: list[str]) -> list[list[str] | None]:
        todo = sorted({text for text in texts if self.digest(text) not in self.cache})
        if todo:
            with ThreadPoolExecutor(self.workers) as pool:
                for text, item in zip(todo, pool.map(self._call, todo)):
                    if item is not None:   # 失败不缓存，下次重试
                        self.cache[self.digest(text)] = item
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.cache), encoding="utf-8")
        return [(self.cache.get(self.digest(text)) or {}).get("intents") for text in texts]

    def latencies(self) -> list[float]:
        return sorted(item["latency"] for item in self.cache.values()
                      if item.get("latency") is not None and item["latency"] == item["latency"])


def fixture_report(label: str) -> None:
    meta = B.evaluate(A.Baseline.load(), [])
    rate = lambda part, whole: f"{meta[part]}/{meta[whole]}"
    print(f"  {label:6s} AUC {meta['auc']}  正常步超阈值 {rate('fixture_benign_over_threshold', 'fixture_benign_steps')}"
          f"  风险点超阈值 {rate('fixture_risk_over_threshold', 'fixture_risk_steps')}"
          f"  分量 {meta['auc_components']}")


def fixtures(llm: CachedClassifier) -> None:
    """评测夹具上的端到端影响：内置基线不变，只替换意图来源（空结果沿用上一轮、失败回退关键词，同线上）。"""
    from agentguard.agents.cc_fixtures import fixtures as load

    prompts = sorted({step["prompt"] for fixture in load() for step in fixture["steps"] if "prompt" in step})
    labels = dict(zip(prompts, llm.predict(prompts)))
    print(f"\n评测夹具（{len(prompts)} 条不同的提示词）：")
    fixture_report("关键词")
    keyword = A.infer_intent
    A.infer_intent = lambda text: keyword(text) if labels.get(text) is None else labels[text]
    try:
        fixture_report("大模型")
    finally:
        A.infer_intent = keyword
    for text in prompts:
        if keyword(text) != (labels.get(text) or []):
            print(f"    {text[:70]!r}: 关键词 {keyword(text)} → 大模型 {labels.get(text)}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--swe", type=int, default=300, help="SWE-chat 英文 / 中文 test 各抽多少条")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--fixtures", action="store_true", help="比较对评测夹具异常检测的影响")
    args = parser.parse_args(argv)
    key = os.environ.get("AG_INTENT_LLM_KEY", "")
    if not key:
        print("需要环境变量 AG_INTENT_LLM_KEY", file=sys.stderr)
        return 2
    classifier = I.LlmIntentClassifier(os.environ.get("AG_INTENT_LLM_URL") or I.DEFAULT_URL,
                                       os.environ.get("AG_INTENT_LLM_MODEL") or I.DEFAULT_MODEL, key, timeout=20)
    llm = CachedClassifier(classifier, args.workers)
    min_n = {"gold": 2, "synth": 2}
    failed = 0
    for name, rows in eval_sets(args.swe).items():
        texts = [text_of(row) for row in rows]
        predicted = llm.predict(texts)
        failed += sum(item is None for item in predicted)
        methods = {"关键词": [A.infer_intent(text) for text in texts],
                   classifier.model: [item or [] for item in predicted]}
        print(f"\n[{name}] {len(rows)} 条   {'macroF1':>8s} {'覆盖率':>7s} {'无意图准确':>9s} {'越权':>6s} {'过严':>6s}")
        for method, preds in methods.items():
            r = evaluate(rows, preds, min_n.get(name, 10))
            print(f"     {method:16s} {r['macro_f1']:8.3f} {r['coverage']:7.3f} {r['none_acc'] or 0:9.3f} "
                  f"{r['over_permissive']:6.3f} {r['over_strict']:6.3f}")
            if name in min_n:
                print("       " + " ".join(f"{label}:{v['f1']:.2f}" for label, v in r["per_class"].items()))
    valid = llm.latencies()
    if valid:
        pct = lambda q: valid[min(len(valid) - 1, int(q * (len(valid) - 1)))]
        print(f"\n{classifier.model} 延迟（缓存中 {len(valid)} 次）：P50 {pct(0.5):.2f}s · P90 {pct(0.9):.2f}s · "
              f"P99 {pct(0.99):.2f}s · 最大 {valid[-1]:.2f}s；本次失败 {failed} 条")
    if args.fixtures:
        fixtures(llm)
    return 0


if __name__ == "__main__":
    sys.exit(main())
