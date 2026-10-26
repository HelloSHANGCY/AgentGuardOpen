"""规则建议回放：在独立进程中加载指定规则目录，回放 Claude Code 夹具，输出逐步决策（JSON 到 stdout）。

    python -m agentguard.rules.replay <规则目录>

独立进程的原因：规则特征是进程内全局状态，在服务进程里试装候选规则会影响正在处理的真实请求。
回放进程只在内存中运行（不读写数据目录），关闭大模型研判与意图识别，结果确定、不产生外部调用；
其余配置沿用服务进程的环境变量，与线上判定保持一致。
"""

import json
import os
import sys

TOKENS = {"developer": "agd_replay_dev", "strict": "agd_replay_strict"}
DEVICES = {"developer": "rr-dev", "strict": "rr-strict"}


def run(rules_dir: str) -> dict:
    disabled = {item for item in os.environ.get("AG_DISABLED_FEATURES", "").split(",") if item}
    os.environ.update({
        "AG_RULES_DIR": rules_dir, "AG_DATA_DIR": "", "AG_AGENT_DEVICE_DIR": "", "AG_RUNTIME_DB": "",
        "AG_BEHAVIOR_DIR": "", "AG_STATIC_ENABLED": "0", "AG_LOCAL_TEST": "1", "AG_INTENT_LLM_KEY": "",
        "AG_DISABLED_FEATURES": ",".join(sorted(disabled | {"intent_llm", "llm_judge"})),
        "AG_AGENT_DEVICES": json.dumps({TOKENS[p]: {"device_id": DEVICES[p], "profile": p} for p in TOKENS}),
    })
    from fastapi.testclient import TestClient

    from ..agents.cc_fixtures import fixtures
    from ..agents.cc_replay import HookTransport, replay_fixture
    from ..main import create_app
    from .library import library

    transport = HookTransport("http://testserver", TestClient(create_app()))
    rows = []
    for fixture in fixtures():
        profile = fixture["profile"]
        row = replay_fixture(fixture, transport, TOKENS[profile], DEVICES[profile], "rr")
        # 回放结果的步骤与夹具中的调用前判定步骤一一对应，补上调用参数便于说明哪一步受了影响。
        inputs = [step.get("input") or step.get("arguments") or {} for step in fixture["steps"]
                  if "pre" in step or "relay" in step]
        rows.append({"fixture": row["fixture"], "scenario": row["scenario"], "malicious": row["malicious"],
                     "outcome": row["outcome"],
                     "steps": [{"tool": step["tool"], "expect": step["expect"], "got": step["got"],
                                "reason": step.get("reason", ""), "risk": bool(step.get("risk")),
                                "input": json.dumps(arguments, ensure_ascii=False)[:300]}
                               for step, arguments in zip(row["steps"], inputs)]})
    return {"digest": library().digest()[:8], "errors": list(library().errors), "rows": rows}


if __name__ == "__main__":
    json.dump(run(sys.argv[1]), sys.stdout, ensure_ascii=False)
