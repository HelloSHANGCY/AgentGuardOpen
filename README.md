# AgentGuard

> AgentGuardOpen 开源仓库：面向 AI Coding Agent 的运行时安全网关与审计平台。

AgentGuard 在 Agent 真正执行工具调用之前完成风险判定，按 **ALLOW / ASK / DENY** 三种结论放行、请求确认或阻断，并把事件、决策、证据和攻击链统一写入审计库，供控制台查询与复盘。

项目支持 Claude Code、Codex、Trae、Qoder、ZCode、WorkBuddy、CodeBuddy；终端覆盖 Windows、Linux，并兼容 macOS。运行时既支持通用 Agent Hook，也提供 stdio MCP 包装器和 HTTP MCP 网关。仓库自带一份固定的 5,200 条离线回归数据，部署和构建不需要靶场源码、原始压缩包或靶场容器。

## 1. 项目简介

AI Coding Agent 已经能读代码、执行命令、访问 MCP 服务、修改配置并连接外部网络。仅靠模型侧提示词约束，无法可靠回答“这次调用是否应该发生”“数据有没有被带出”“多个会话之间是否已经串扰”。AgentGuard 把这些问题收敛到执行前的确定性决策，再用审计与评测验证效果。

### 1.1 核心能力

| 能力 | 说明 |
| --- | --- |
| 运行时管控 | Hook 与 MCP 中转共用同一套检查器，在副作用发生前给出 ALLOW / ASK / DENY；返回给模型的内容只包含原因码和决策 ID，不回显命令正文或策略细节。 |
| 多层检测 | YAML 特征规则、任务污点、来源归因、数据流溯源、行为基线、意图识别和可选的大模型研判共同参与决策；规则不依赖模型服务即可运行。 |
| 终端快速判定 | 终端客户端按服务端签名的规则包做无状态、高置信本地拒绝；服务端仍是权威判定方，终端拒绝一定是服务端拒绝的子集。服务不可达时按配置降级并缓冲事件。 |
| MCP 安全网关 | `/mcp/{server}` 强制代理，上游只能由管理员通过环境变量登记；客户端不能指定任意转发地址。有副作用的 MCP 服务在清单不可用时默认拒绝。 |
| 静态资产扫描 | 扫描 Agent 配置、指令、Skill、MCP 声明与依赖，支持服务端目录扫描和已接入设备的只读采集；采集端先脱敏再上传，报告保留覆盖缺口。 |
| 审计与控制台 | 威胁中心、运行审计、会话链路、评测与指标、部署架构、规则库、静态资产、终端管控、行为基线、大模型研判和模型管理。 |
| 离线评测 | 固定 5,200 条样本（5,120 条正常、80 条攻击，覆盖 11 个场景）；支持命令行回归、Hook 夹具回放和控制台评测任务，不访问靶场或模型服务。 |
| 独立部署 | 单个 Compose 服务即可运行主网关、静态扫描 worker 和按条件启用的评测 worker；前端构建产物随仓库提交，运行时不需要 Node.js 或 GPU。 |

### 1.2 支持范围

| Agent | trace 前缀 | 说明 |
| --- | --- | --- |
| Claude Code | `cc-` | Hook 与受管 MCP；完整事件集 |
| Codex | `cx-` | Hook；PreToolUse 只支持 deny，ASK 会渲染为 deny |
| Trae | `tr-` | Hook；没有 SessionEnd，会话随信封过期结束 |
| Qoder | `qd-` | IDE / JetBrains 插件 / CLI；兼容 Claude Code Hook 信封 |
| ZCode | `zc-` | Hook；没有 SessionEnd，输出按 schema 校验 |
| WorkBuddy | `wb-` | Hook；部分事件不带 `tool_use_id`，按顺序关联 ASK 与 Post |
| CodeBuddy | `cb-` | IDE Hook；文件参数可能使用 `filePath` / `new_str` |

终端客户端支持 Windows 和 Linux，兼容 macOS。各 Agent 的 Hook 差异、安装命令、MCP 中转、自检和卸载见 [终端接入说明](agentguard/endpoint/README.md)。

### 1.3 系统架构

```text
Claude Code / Codex / Trae / Qoder / ZCode / WorkBuddy / CodeBuddy
                    │  Hook / MCP
                    ▼
        AgentGuard Endpoint（可选）
        本地高置信拒绝 · 事件缓冲 · 设备令牌
                    │  HTTPS
                    ▼
┌─────────────────────────────────────────────────────────────┐
│ AgentGuard Gateway (:8080)                                  │
│                                                             │
│  Hook API          MCP 强制代理          管理 / 控制台 API   │
│        └────────────────┬────────────────┘                  │
│                         ▼                                   │
│                RuntimeDecisionEngine                        │
│   特征规则 · 污点 · 来源归因 · 数据流 · 行为基线 · 意图      │
│                  · 可选大模型研判                            │
│                         │                                   │
│                RuntimeStore (SQLite)                        │
│                                                             │
│  静态扫描 worker          评测 worker（按配置启用）           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                  Vue 3 控制台（/console/）
```

服务端是权威判定方：需要跨事件、跨会话状态的检测都放在网关侧。终端只承担服务端在任何情况下都会拒绝的高置信判定，避免把完整规则和模型密钥下发到可能已被注入的终端。

### 1.4 仓库结构

```text
.
├── agentguard/
│   ├── agentguard/            # FastAPI 网关、检测引擎、规则库、存储与静态扫描
│   ├── console/               # Vue 3 + Vite 控制台（dist 构建产物随仓库提交）
│   ├── endpoint/              # 终端客户端：Hook 安装、本地快检、设备接入
│   ├── resources/
│   │   ├── behavior/          # 共享行为基线、候选模型与符号训练数据
│   │   └── testing/range-v1/  # 固定 5,200 条离线回归数据
│   ├── tests/                 # Python 回归测试
│   └── tools/                 # 评测、回放、训练与资源校验工具
├── docs/                      # 部署指南与界面截图
├── scripts/test.sh            # 回归测试入口
├── docker-compose.agentguard.yml
├── Makefile
└── .env.example
```

### 1.5 界面预览

**威胁中心**：汇总阻断、待确认和复核记录，展示风险趋势、类型分布与来源热点。

![威胁中心](docs/images/threat-center.png)

**实时风险记录**：按处置和级别查看详细告警，包含风险评分、来源、触发次数和大模型研判状态。

![实时风险记录](docs/images/threat-records.png)

**告警详情**：查看触发行为、原始参数、返回给 Agent 的提示和数据流证据。

![告警详情](docs/images/alert-detail.png)

**检测证据与行为基线**：查看命中规则、数据流证据，以及行为基线的异常分、阈值和评分维度。

![检测证据与行为基线](docs/images/alert-evidence.png)

**会话链路**：把一次会话中的凭证访问、数据外发等阶段串成可追溯的攻击链。

![会话链路](docs/images/session-chain.png)

**规则库**：内置与自定义 YAML 规则包，支持启停、样本测试和变更记录。

![规则库](docs/images/rules.png)

**静态资产**：扫描 Agent 配置、Skill、MCP 与依赖，汇总风险资产、类型分布和覆盖缺口。

![静态资产](docs/images/static-assets.png)

**行为基线**：查看当前模型、真实行为数据、异常阈值与候选模型版本。

![行为基线](docs/images/behavior-baseline.png)

> 截图来自本地演示实例，设备名、事件和风险记录均为测试夹具，不包含真实凭证或业务数据。

## 2. 快速开始

### 2.1 环境要求

Docker 部署需要 Git、Docker Engine 和 Docker Compose v2；首次构建需联网安装依赖。仓库已包含前端构建产物，运行时无需 Node.js 或 GPU。本地 Python 开发使用 Python 3.12；前端开发使用 Node.js 20+ 与 npm。

```bash
git clone https://github.com/HelloSHANGCY/AgentGuardOpen.git
cd AgentGuardOpen
```

Linux、macOS 或 Windows WSL2 / Docker Desktop Linux 容器环境可使用以下命令。

### 2.2 启动

```bash
cp .env.example .env
docker compose -f docker-compose.agentguard.yml config -q
make up
make smoke
```

打开 **<http://127.0.0.1:18080/console/>**。编排仅启动 `agentguard` 服务，容器内运行主网关、静态扫描 worker，以及满足配置条件时启用的评测 worker。

### 2.3 访问地址

| 地址 | 用途 |
| --- | --- |
| `http://127.0.0.1:18080/console/` | 控制台 |
| `http://127.0.0.1:18080/health` | 健康检查 |
| `http://127.0.0.1:18080/docs` | API 文档 |

容器内网关端口为 `8080`，宿主机默认仅绑定 `127.0.0.1:18080`。团队部署、远程访问、HTTP MCP 上游、日常维护与数据保留见 [部署指南](docs/AgentGuard-部署指南.md)。

## 3. 终端 Agent 接入

1. 打开控制台“终端管控 → 客户端部署”，设置终端可访问的服务端地址、需要接入的 Agent 和安装范围。
2. 在目标终端执行页面生成的安装命令。Linux / macOS 可使用 Python 脚本包，目标终端需有 Python 3.8+；Windows 一键安装需要先发布 Windows 客户端包。
3. 安装时未提供预签发令牌，会自动提交接入申请。管理员在“待认证设备”核对终端输出的核对码，再批准认证。
4. 重新打开目标 Agent 的新会话，执行正常工具调用，在终端管控与运行审计中确认上报。

控制台「终端管控 → 客户端部署」页面可统一设置服务端地址、接入的 Agent 和安装方式：

![终端客户端部署](docs/images/terminal-client-deploy.png)

本机 Linux / macOS 安装入口示例：

```bash
curl -fsSL http://127.0.0.1:18080/v1/agents/install.sh | sh
```

控制台页面说明、安装包选择与下载见 [部署指南的终端客户端部署](docs/AgentGuard-部署指南.md#5-终端客户端部署)。仓库不分发终端预构建二进制，Windows 部署需按 [终端接入说明](agentguard/endpoint/README.md) 构建 Windows 包，再重建 AgentGuard 镜像。该文档也包含各 Agent 的 Hook 安装、MCP 中转、认证、自检和卸载命令。

## 4. 配置大模型研判

AgentGuard 的意图识别、危险审批、异步分析使用另外配置的真实模型服务；共享行为基线也不包含大语言模型权重。

1. 进入“模型管理 → 新增模型”，填写供应商、完整接口地址（例如 `https://api.example.com/v1/chat/completions`）、模型名和 API Key，进行连接测试并保存。填写 API Key 后可点击“获取模型”从供应商的模型列表接口拉取可用模型；DeepSeek、OpenRouter 等提供元数据的供应商会同时带出支持的思考强度。
2. 在模型详情中分配“意图识别”“危险审批”“异步分析”用途，可分别绑定不同模型。
3. 进入“大模型研判 → 运行配置”，开启需要的危险审批和异步分析模式。用途绑定后还需单独启用功能。
4. 产生新的会话流量后，在“大模型研判 → 分析记录”和“威胁中心 → 实时风险记录”查看分析及告警标签；已有会话可使用“手动分析”。

模型配置与密钥保存在设备数据卷中，重建容器后保留。连接测试会请求真实模型服务；服务地址需能从容器内访问，容器里的 `127.0.0.1` 指容器自身。

危险审批针对执行前命中规则、处于审批范围内的工具调用，不会为所有事件生成审批记录。观察模式跳过危险审批；正常放行、未开启功能或未绑定可用模型时，没有审批记录属于预期情况。异步分析需等待后台完成，尚未分析、排队或分析失败的告警不会直接得到研判结论，可在运行配置查看状态并对对应会话手动分析。

## 5. 导入团队共享行为模型与训练数据

镜像包含六个历史候选模型、符号化训练 / 验证数据和评估记录。按当前 Compose 默认目录执行：

```bash
docker compose -f docker-compose.agentguard.yml exec -T agentguard \
  python tools/behavior_assets.py check
docker compose -f docker-compose.agentguard.yml exec -T agentguard \
  python tools/behavior_assets.py install --directory /app/data/agent-devices/behavior
```

导入后刷新“行为基线”，查看候选模型和数据源 `swechat-quality-20261017`。重复导入相同资源不会重复写入；导入不会切换当前模型，启用需要单独操作。

这些候选原评估均为 `reject`，没有达到既定启用标准；其异常触发率不能当作误报率。数据包含行为符号和哈希标识，不含原始会话文本。详细来源、许可、数据分区和重新训练方式见 [共享行为资源说明](agentguard/resources/behavior/README.md) 与 [来源与许可](agentguard/resources/behavior/NOTICE.md)。

宿主机执行 `make behavior-assets` 的默认目录为 `agentguard/data/benign/team-behavior/`，不会自动写入 Docker 数据卷。Docker 部署请使用上面的容器内导入命令；自定义 `AG_BEHAVIOR_DIR` 时，导入目标必须与服务实际配置一致。

## 6. 离线数据集与评测

固定快照位于 [`agentguard/resources/testing/range-v1/`](agentguard/resources/testing/range-v1/README.md)，包含 5,120 条正常样本和 80 条攻击样本，覆盖 11 个场景。原始输入、轨迹和标签保持完整；工具描述、Skill 文本和 HTTP 测试载荷以数据形式保存。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r agentguard/requirements-test.txt
make corpus-check PYTHON="$PWD/.venv/bin/python"
make test-corpus PYTHON="$PWD/.venv/bin/python"
.venv/bin/python agentguard/tools/replay_test_corpus.py \
  --out .test-results/offline-corpus.json
```

这些命令不启动靶场、不执行样本中的命令、不发出攻击请求，也不写入在线审计或训练数据。输出衡量本地请求检查；不验证工具结果、真实副作用、业务成功、网络隔离或启动 Beacon。

控制台“评测与指标 → 评测任务 → 新建评测”可选择“靶场离线数据集”，默认检测全部 5,200 条，也可选择场景和条数。评测 worker 使用独立的内置规则副本在本地执行检测，无需靶场或模型服务；页面提供进度、取消、任务历史和完整 JSON 报告下载。在线详情保留最近 100 条样本，下载报告包含本次全部结果。原有 Claude Code Hook 夹具回放仍可独立选择，需主网关和评测 worker 在线。

## 7. 本地开发运行

### 7.1 Python 服务端

启动 AgentGuard 主服务：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r agentguard/requirements.txt
export AG_LOCAL_TEST=1
export AG_DATA_DIR="$HOME/.local/share/agentguard-dev"
export AG_STATIC_DB="$AG_DATA_DIR/static-scan.db"
export AG_STATIC_SOURCES="{\"local\":\"$PWD/agentguard/tests/static_scan/fixtures/benign\"}"
cd agentguard
../.venv/bin/python -m uvicorn --factory agentguard.main:create_app \
  --host 127.0.0.1 --port 8080
```

本地控制台地址为 `http://127.0.0.1:8080/console/`。直接运行 Python 不会自动加载根目录 `.env`，需要通过环境变量配置。

此方式不会自动启动静态扫描 worker 或评测 worker。需要时在同一环境变量下另开终端：

```bash
cd agentguard
../.venv/bin/python -m agentguard.static_scan.worker
../.venv/bin/python -m agentguard.evaluation
```

评测 worker 需与网关使用同一 `AG_EVAL_DB`；未设置时两者都使用默认路径。没有对应上游时，MCP 转发不可用。

### 7.2 前端开发

使用 Node.js 20+ 与 npm，另开终端从仓库根目录执行：

```bash
cd agentguard/console
npm ci
npm run dev
```

打开 `http://127.0.0.1:5173/console/`。Vite 默认将 `/v1`、`/health` 代理到本机 **8080**，适配上面的 Python 服务；若连接 Docker 后端，应将 [vite.config.js](agentguard/console/vite.config.js) 中两处代理目标改为 `http://127.0.0.1:18080`，再重启开发服务器。

前端改动完成后构建，并更新镜像内的控制台：

```bash
cd agentguard/console
npm run build
cd ../..
docker compose -f docker-compose.agentguard.yml up -d --build --no-deps agentguard
```

`npm run build` 输出到 `agentguard/console/dist/`；该构建产物需要随前端变更一起提交，供团队无需 Node.js 部署。

### 7.3 回归测试

从仓库根目录执行：

```bash
.venv/bin/python -m pip install -r agentguard/requirements-test.txt
PYTHON="$PWD/.venv/bin/python" bash scripts/test.sh all
PYTHON="$PWD/.venv/bin/python" bash scripts/test.sh lint
```

前端测试：

```bash
cd agentguard/console
npm test
```

Python 测试报告写入被 Git 忽略的 `.test-results/`，无需启动外部靶场。测试分组包括 `all`、`runtime`、`static`、`corpus`、`benchmark` 和 `lint`，可用 `bash scripts/test.sh --help` 查看。

## 8. 安全边界与常见问题

### 8.1 安全边界

- `AG_LOCAL_TEST=1` 且管理令牌留空时，部分管理接口免令牌，只适合本机开发；团队部署必须关闭本地测试并设置独立令牌。
- 运行时审计查询接口目前没有统一令牌鉴权。跨不可信网络访问时，需要 HTTPS、反向代理或外层访问控制。
- 服务端静态扫描只读取管理员登记的目录；设备采集只读取当前用户的 Agent 资产，且为只读，不执行目标代码、不启动 MCP、不采集聊天历史、设备令牌或 SSH 凭证。外部 MCP 源码只按声明建立资产，未审计其实现。
- 意图识别只发送经过凭证掩码和长度截断的用户提示词，不发送工具参数或文件内容；模型密钥保存在设备数据卷中。
- 离线语料用于固定合成数据的回归，不验证真实业务后端、网络隔离、真实副作用或部署性能。历史靶场验收结果不由该数据集改写。
- 终端本地规则只覆盖服务端必然拒绝的高置信场景；最终判定仍以服务端为准。

### 8.2 常见问题

| 现象 | 排查方法 |
| --- | --- |
| 新部署没有风险 / 研判记录 | 启动本身不产生业务流量；先接入终端或启动 Hook 夹具评测。研判还需要模型用途绑定、功能启用和实际触发。 |
| 危险审批一直为空 | 检查审批开关、模型连接、审批范围和终端拦截配置；观察模式与正常放行不会触发危险审批。 |
| 导入后看不到共享候选 | 检查是否导入了实际行为目录，Docker 部署使用容器内命令；刷新页面，导入不会自动启用模型。 |

部署、端口、令牌和构建相关问题见 [部署指南的排查章节](docs/AgentGuard-部署指南.md#8-部署排查)。

## 9. 更多文档

- [部署指南：Compose、团队配置、远程访问、升级与数据保留](docs/AgentGuard-部署指南.md)
- [终端接入、MCP 中转、客户端构建与卸载](agentguard/endpoint/README.md)
- [共享行为基线资源、训练数据与重新训练](agentguard/resources/behavior/README.md)
- [共享行为数据的来源与许可](agentguard/resources/behavior/NOTICE.md)
- [固定离线测试数据的字段、校验与评测边界](agentguard/resources/testing/range-v1/README.md)
- 启动服务后的 API 文档：`http://127.0.0.1:18080/docs`
