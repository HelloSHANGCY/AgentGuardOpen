# AgentGuard 独立服务与离线测试快捷入口
SOURCE ?= agentguard/tests/static_scan/fixtures/benign
COMPOSE := docker compose -f docker-compose.agentguard.yml

.PHONY: up down logs smoke corpus-check test-corpus test test-runtime test-static test-benchmark lint static-scan eval-worker console console-build console-dev behavior-assets behavior-assets-check

up:            ## 启动 AgentGuard 服务与独立 worker
	$(COMPOSE) up -d --build

down:          ## 停止并移除服务容器（保留数据卷）
	$(COMPOSE) down

logs:          ## 跟踪 AgentGuard 日志
	$(COMPOSE) logs -f agentguard

smoke:         ## 主网关健康检查
	curl -fsS http://localhost:18080/health && echo

console:       ## 打开控制台（浏览器）
	echo "AgentGuard 控制台: http://localhost:18080/console"

console-build: ## 构建前端控制台（Vite → agentguard/console/dist，产物随镜像分发）
	cd agentguard/console && npm ci && npm run build

console-dev:   ## 前端开发服务器（Vite，API 代理到本机 8080）
	cd agentguard/console && npm run dev

behavior-assets-check: ## 校验共享行为模型与符号训练数据
	$(or $(PYTHON),python3) agentguard/tools/behavior_assets.py check

behavior-assets: ## 导入共享候选模型和训练数据（BEHAVIOR_DIR 可指定服务数据目录）
	$(or $(PYTHON),python3) agentguard/tools/behavior_assets.py install $(if $(BEHAVIOR_DIR),--directory "$(BEHAVIOR_DIR)")

eval-worker:   ## 本地评测 worker（设置 AG_LOCAL_TEST=1 或令牌，与网关使用同一 AG_EVAL_DB）
	cd agentguard && python3 -m agentguard.evaluation

corpus-check:  ## 校验固定的 5,200 条离线测试数据
	$(or $(PYTHON),python3) agentguard/tools/check_test_corpus.py

test-corpus:   ## 运行完整固定语料的离线回归测试
	bash scripts/test.sh corpus

test:          ## 全部回归测试并生成报告（无需 Docker）
	bash scripts/test.sh all

test-runtime:  ## 运行时规则、Guard 与网关集成测试
	bash scripts/test.sh runtime

test-static:   ## 静态扫描完整回归测试
	bash scripts/test.sh static

test-benchmark: ## 静态扫描固定样本指标测试
	bash scripts/test.sh benchmark

lint:          ## 代码规范检查（ruff，规则见 agentguard/pyproject.toml）
	bash scripts/test.sh lint

static-scan:   ## 离线静态扫描 SOURCE 目录，生成资产/风险与 Markdown 报告
	cd agentguard && python3 -m agentguard.static_scan.cli scan \
		--source "$(abspath $(SOURCE))" --project local --db /tmp/ag-static/scan.db \
		--report /tmp/ag-static/report.md --format md
