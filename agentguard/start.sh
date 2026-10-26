#!/bin/sh
# AgentGuard 容器入口：主网关、静态扫描 worker 和可选评测 worker。
# 事件统一汇聚到主网关 :8080；不启动外部测试服务。
#
# 注意：容器 /bin/sh 是 dash，不能使用 wait -n 等 bash 特性；
# 用 POSIX 轮询守护：任一关键进程退出即让容器退出，健康检查接管失败态。
set -u

cd /app

uvicorn --factory agentguard.main:create_app --host 0.0.0.0 --port 8080 &

# 评测 worker：本地测试模式或配置令牌后启用。
if [ "${AG_LOCAL_TEST:-0}" = "1" ] || [ -n "${AG_EVAL_ADMIN_TOKEN:-}" ]; then
    (
        while :; do
            python -m agentguard.evaluation
            echo "agentguard: evaluation worker exited, restarting" >&2
            sleep 3
        done
    ) &
fi

# 静态扫描 worker：独立进程，异常退出由守护循环重启，不拖垮网关。
(
    while :; do
        python -m agentguard.static_scan.worker
        code=$?
        echo "agentguard: static-scan worker exited with $code, restarting" >&2
        sleep 2
    done
) &

term() {
    kill $(jobs -p) 2>/dev/null
    exit 0
}
trap term TERM INT

while :; do
    sleep 2
    for pid in $(jobs -p); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "agentguard: critical process $pid exited, stopping container" >&2
            exit 1
        fi
    done
done
