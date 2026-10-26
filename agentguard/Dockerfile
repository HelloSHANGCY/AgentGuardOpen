FROM python:3.12-slim

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agentguard ./agentguard
# 控制台只需要 Vite 构建产物（make console-build 生成并随仓库提交）。
COPY console/dist ./console/dist
# 评测 worker 经 tools/replay_hook_client.py 回放 Claude Code 套件（只依赖标准库）。
COPY tools ./tools
# 随 Git 分发的符号训练包与候选基线，按需导入，不自动启用。
COPY resources/behavior ./resources/behavior
# 固定离线回归数据，独立于外部服务与语料生成器。
COPY resources/testing ./resources/testing
# 终端客户端（/v1/agents/client 下载）：源码现场打包为脚本包；endpoint/dist 中的预构建包一并提供。
COPY endpoint ./endpoint
COPY start.sh .
RUN chmod +x start.sh

ENV AG_HOOK_SECRET=agentguard-dev-secret
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=12 \
    CMD curl -fsS http://localhost:8080/health >/dev/null || exit 1

CMD ["./start.sh"]
