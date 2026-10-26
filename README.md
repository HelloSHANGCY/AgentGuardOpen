# AgentGuard

AgentGuard 用于 AI Agent 的运行时风险检测、工具调用管控、静态扫描与审计。控制台提供威胁中心、会话链路、设备管理、规则管理、行为基线、大模型研判及部署架构。

项目独立运行，保留通用 Agent Hook、stdio MCP 包装器和 HTTP MCP 网关。仓库包含一份固定的 5,200 条离线回归数据；部署和构建不需要靶场源码、原始压缩包或靶场容器。

## 1. 环境准备

Docker 部署需要 Git、Docker Engine 和 Docker Compose v2；首次构建需联网安装依赖。仓库已包含前端构建产物，运行时无需 Node.js 或 GPU。本地 Python 开发使用 Python 3.12；前端开发使用 Node.js 20+ 与 npm。

```bash
git clone https://github.com/HelloSHANGCY/AgentGuard.git
cd AgentGuard
```

Linux、macOS 或 Windows WSL2 / Docker Desktop Linux 容器环境可使用以下命令。

## 2. 首次部署

```bash
cp .env.example .env
docker compose -f docker-compose.agentguard.yml config -q
make up
make smoke
```

打开 **<http://127.0.0.1:18080/console/>**。编排仅启动 `agentguard` 服务，容器内运行主网关、静态扫描 worker，以及满足配置条件时启用的 评测 worker。

控制台“部署架构”展示组件和调用链路；“部署方式”提供 Docker Compose、源码运行和相关接入配置，可逐项复制命令。原 `#/range` 书签会转到 `#/deployment`。

默认配置面向本机开发，`AG_LOCAL_TEST=1` 且管理令牌留空时，部分管理操作免令牌。团队部署在 `.env` 中配置：

```dotenv
AG_LOCAL_TEST=0
AG_HOOK_SECRET=替换为独立生成的随机长字符串
AG_AGENT_ADMIN_TOKEN=替换为独立生成的管理令牌
AG_EVAL_ADMIN_TOKEN=替换为独立生成的评测管理令牌
```

`.env` 被 Git 忽略。设备、规则和模型页面使用 `AG_AGENT_ADMIN_TOKEN`，评测页面使用 `AG_EVAL_ADMIN_TOKEN`；页面刷新后需重新输入。静态扫描专用令牌留空时回退到统一管理鉴权。

HTTP MCP 上游默认为空。需要转发时，由管理员在 `.env` 中登记，再重新创建容器：

```dotenv
AG_EXTRA_UPSTREAMS={"docs":"http://your-mcp-host:8000/mcp"}
```

客户端使用 `/mcp/docs` 访问该上游；请求参数不能指定任意转发地址。静态扫描远程项目时，应自行只读挂载目录，并配置 `AG_STATIC_SOURCES`、`AG_STATIC_ROOTS` 指向容器内实际路径。终端本地扫描也可通过设备接入使用。

## 3. 访问地址与远程部署

| 地址 | 用途 |
| --- | --- |
| `http://127.0.0.1:18080/console/` | 控制台 |
| `http://127.0.0.1:18080/health` | 健康检查 |
| `http://127.0.0.1:18080/docs` | API 文档 |

容器内网关端口为 `8080`，宿主机默认仅绑定 `127.0.0.1:18080`。远程访问可使用隧道：

```bash
ssh -N -L 18080:127.0.0.1:18080 user@server
```

局域网部署时，将端口映射改为受控网卡地址，并在“客户端部署”中填写终端实际可达的服务地址。运行时审计查询接口目前没有统一令牌鉴权，跨不可信网络访问需配置 HTTPS 和外层访问控制。

## 4. 终端 Agent 接入

1. 打开控制台“设备管理 → 客户端部署”，设置终端可访问的服务端地址、需要接入的 Agent 和安装范围。
2. 在目标终端执行页面生成的安装命令。Linux / macOS 可使用 Python 脚本包，目标终端需有 Python 3.8+；Windows 一键安装需要先发布 Windows 客户端包。
3. 安装时未提供预签发令牌，会自动提交接入申请。管理员在“待认证设备”核对终端输出的核对码，再批准认证。
4. 重新打开目标 Agent 的新会话，执行正常工具调用，在设备管理与会话审计中确认上报。

本机 Linux / macOS 安装入口示例：

```bash
curl -fsSL http://127.0.0.1:18080/v1/agents/install.sh | sh
```

仓库不分发终端预构建二进制，Windows 部署需按 [终端接入说明](agentguard/endpoint/README.md) 构建 Windows 包，再重建 AgentGuard 镜像。该文档也包含各 Agent 的 Hook 安装、MCP 中转、认证、自检和卸载命令。

## 5. 配置大模型研判

AgentGuard 的意图识别、危险审批、异步分析使用另外配置的真实模型服务；共享行为基线也不包含大语言模型权重。

1. 进入“模型管理 → 新增模型”，填写供应商、完整接口地址（例如 `https://api.example.com/v1/chat/completions`）、模型名和 API Key，进行连接测试并保存。
2. 在模型详情中分配“意图识别”“危险审批”“异步分析”用途，可分别绑定不同模型。
3. 进入“大模型研判 → 运行配置”，开启需要的危险审批和异步分析模式。用途绑定后还需单独启用功能。
4. 产生新的会话流量后，在“大模型研判 → 分析记录”和“威胁中心 → 实时风险记录”查看分析及告警标签；已有会话可使用“手动分析”。

模型配置与密钥保存在设备数据卷中，重建容器后保留。连接测试会请求真实模型服务；服务地址需能从容器内访问，容器里的 `127.0.0.1` 指容器自身。

危险审批针对执行前命中规则、处于审批范围内的工具调用，不会为所有事件生成审批记录。观察模式跳过危险审批；正常放行、未开启功能或未绑定可用模型时，没有审批记录属于预期情况。异步分析需等待后台完成，尚未分析、排队或分析失败的告警不会直接得到研判结论，可在运行配置查看状态并对对应会话手动分析。

## 6. 导入团队共享行为模型与训练数据

镜像包含六个历史候选模型、符号化训练 / 验证数据和评估记录。按当前 Compose 默认目录执行：

```bash
docker compose -f docker-compose.agentguard.yml exec -T agentguard \
  python tools/behavior_assets.py check
docker compose -f docker-compose.agentguard.yml exec -T agentguard \
  python tools/behavior_assets.py install --directory /app/data/agent-devices/behavior
```

导入后刷新“行为基线”，查看候选模型和数据源 `swechat-quality-20261017`。重复导入相同资源不会重复写入；导入不会切换当前模型，启用需要单独操作。

这些候选原评估均为 `reject`，没有达到既定启用标准；其异常触发率不能当作误报率。数据包含行为符号和哈希标识，不含原始会话文本。详细来源、许可、数据分区和重新训练方式见 [共享行为资源说明](agentguard/resources/behavior/NOTICE.md)。

宿主机执行 `make behavior-assets` 的默认目录为 `agentguard/data/benign/team-behavior/`，不会自动写入 Docker 数据卷。Docker 部署请使用上面的容器内导入命令；自定义 `AG_BEHAVIOR_DIR` 时，导入目标必须与服务实际配置一致。

## 7. 离线数据集与评测

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

## 8. 本地开发运行

### Python 服务端

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

本地控制台地址为 `http://127.0.0.1:8080/console/`。直接运行 Python 不会自动加载根目录 `.env`，需要通过环境变量配置。此方式不会自动启动静态扫描 worker 或评测 worker；静态扫描 worker 等独立进程的启动命令见 [技术说明书](docs/AgentGuard-技术说明书.md)。没有对应上游时，MCP 转发不可用。

### 前端开发

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

### 回归测试

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

Python 测试报告写入被 Git 忽略的 `.test-results/`，无需启动外部靶场。测试分组和验收边界见 [测试运行说明](docs/AgentGuard-测试运行说明.md)。

## 9. 日常维护与数据保留

```bash
# 查看日志
docker compose -f docker-compose.agentguard.yml logs --tail 100 -f agentguard

# 停止 / 恢复已有容器
docker compose -f docker-compose.agentguard.yml stop
docker compose -f docker-compose.agentguard.yml start

# 拉取更新后重新构建（先处理本地未提交改动）
git pull --ff-only
docker compose -f docker-compose.agentguard.yml up -d --build
```

当前编排明确持久化的 AgentGuard 数据：

| 命名卷 | 容器目录 | 内容 |
| --- | --- | --- |
| `agent-device-data` | `/app/data/agent-devices` | 设备、运行时审计库、规则配置、模型接入配置、行为基线等 |
| `static-scan-data` | `/app/data/static-scan` | 静态扫描数据库 |
| `evaluation-data` | `/app/data/evaluations` | 评测任务与结果 |

Docker 实际卷名还带有 Compose 项目前缀。升级时保持相同的项目目录 / 项目名，否则可能连接到新卷而显示为空。运行时审计默认保留最近 7 天。

`make down` 停止并移除服务容器，保留命名数据卷。迁移时停止写入后备份数据卷及 `.env`；需要清空数据时再显式使用 `docker compose -f docker-compose.agentguard.yml down -v`。

## 10. 常见问题

| 现象 | 排查方法 |
| --- | --- |
| 控制台打不开 | 检查 `docker compose ... ps` 和日志；Docker 宿主机访问 `18080`，本地 Python 服务才使用 `8080`；远程访问需隧道或可达的网卡绑定。 |
| 启动提示端口占用 | 检查是否已有服务占用 `18080`；调整端口映射时同步修改终端服务地址。 |
| 构建失败或一直下载 | 查看构建日志，检查 Docker 镜像源、容器构建网络和 Python 包源。 |
| 管理接口返回 401 / 503 | 401 通常是令牌缺失或错误；关闭本地测试后未设置所需管理令牌会返回 503。修改 `.env` 后执行 `up -d`，单纯 `restart` 不会更新容器环境变量。 |
| 新部署没有风险 / 研判记录 | 启动本身不产生业务流量；先接入终端或启动 Hook 夹具评测。研判还需要模型用途绑定、功能启用和实际触发。 |
| 危险审批一直为空 | 检查审批开关、模型连接、审批范围和终端拦截配置；观察模式与正常放行不会触发危险审批。 |
| 容器中模型连接失败 | 检查完整接口地址、密钥、超时与容器网络；模型服务在宿主机时不能直接填容器的 `localhost`。 |
| 导入后看不到共享候选 | 检查是否导入了实际行为目录，Docker 部署使用容器内命令；刷新页面，导入不会自动启用模型。 |
| Windows 客户端下载 404 | 先构建 Windows 客户端包并重建服务镜像；预构建包没有随 Git 分发。 |
| 前端改动没有生效 | 执行 `npm run build` 后重建并更新 `agentguard` 容器，再刷新浏览器。 |

## 11. 更多文档

- [技术说明书：架构、检测机制、配置和边界](docs/AgentGuard-技术说明书.md)
- [当前项目架构图](docs/AgentGuard-当前项目架构图.md)
- [终端接入、MCP 中转与客户端构建](agentguard/endpoint/README.md)
- [共享行为基线与符号训练数据](agentguard/resources/behavior/NOTICE.md)
- [测试运行说明](docs/AgentGuard-测试运行说明.md)
