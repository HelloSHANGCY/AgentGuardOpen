#!/usr/bin/env bash
# 从任意目录运行；不启动外部服务，不安装依赖，不调用攻击回放。
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
SUITE="${1:-all}"
case "$SUITE" in
  all) targets=(tests) ;;
  runtime) targets=(tests/test_engine.py tests/test_guards.py tests/test_integration.py tests/test_mutation_robustness.py tests/test_evaluation.py tests/test_claude_code.py tests/test_cc_hook_client.py tests/test_mcp_relay.py tests/test_endpoint_mcp.py tests/test_cc_fixture_replay.py tests/test_test_corpus.py tests/test_codex.py) ;;
  static) targets=(tests/static_scan) ;;
  corpus) targets=(tests/test_test_corpus.py) ;;
  benchmark) targets=(tests/static_scan/test_benchmark.py) ;;
  lint)
    # 规则见 agentguard/pyproject.toml；RUFF 可指定可执行文件。
    cd -- "$ROOT_DIR/agentguard"
    if [[ -n "${RUFF:-}" ]]; then exec "$RUFF" check . "${@:2}"; fi
    exec "$PYTHON_BIN" -m ruff check . "${@:2}" ;;
  -h|--help)
    echo '用法：./scripts/test.sh [all|runtime|static|corpus|benchmark|lint] [pytest 参数...]'
    echo '环境变量：PYTHON 指定解释器；AG_TEST_OUTPUT_DIR 指定报告根目录。'
    exit 0 ;;
  *) echo "未知测试组：$SUITE（可选 all/runtime/static/corpus/benchmark/lint）" >&2; exit 2 ;;
esac
if (( $# > 0 )); then shift; fi
if ! "$PYTHON_BIN" -c 'import pytest, fastapi, httpx, yaml, uvicorn' >/dev/null 2>&1; then
  echo '测试依赖缺失，请使用选定的 Python 安装 agentguard/requirements-test.txt。' >&2
  exit 2
fi

OUTPUT_ROOT="${AG_TEST_OUTPUT_DIR:-$ROOT_DIR/.test-results}"
mkdir -p -- "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd -- "$OUTPUT_ROOT" && pwd)"
RUN_DIR="$(mktemp -d "$OUTPUT_ROOT/$(date +%Y%m%d-%H%M%S)-${SUITE}-XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
# 避免导入应用时写入正在运行的静态扫描数据库。
export AG_STATIC_DB="$RUN_DIR/static-scan.db"
export AG_EVAL_DB="$RUN_DIR/evaluation.db"
export AG_DATA_DIR="$RUN_DIR/runtime-data"
cd -- "$ROOT_DIR/agentguard"
echo "测试组：$SUITE"
echo "报告目录：$RUN_DIR"
set +e
"$PYTHON_BIN" -m pytest -q -p no:cacheprovider "${targets[@]}" "$@" \
  --junitxml="$RUN_DIR/junit.xml" 2>&1 | tee "$RUN_DIR/pytest.log"
statuses=("${PIPESTATUS[@]}")
set -e
status="${statuses[0]}"
if (( status == 0 && statuses[1] != 0 )); then status="${statuses[1]}"; fi
printf '%s\n' "$status" > "$RUN_DIR/exit-code.txt"
echo "测试退出码：$status；日志：$RUN_DIR/pytest.log"
exit "$status"
