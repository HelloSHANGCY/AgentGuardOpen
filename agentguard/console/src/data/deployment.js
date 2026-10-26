// Standard deployment facts. Keep these aligned with Compose, start.sh and the actual entry points.
export const deploymentDefaults = {
  service: 'agentguard',
  binding: '127.0.0.1:18080:8080',
  console: 'http://127.0.0.1:18080/console/',
  localConsole: 'http://127.0.0.1:8080/console/',
  compose: 'docker-compose.agentguard.yml',
};

export const deploymentVolumes = [
  { name: 'agent-device-data', path: '/app/data/agent-devices', content: '设备、运行时审计、规则、模型配置与行为基线' },
  { name: 'static-scan-data', path: '/app/data/static-scan', content: '静态扫描任务、资产、风险与报告' },
  { name: 'evaluation-data', path: '/app/data/evaluations', content: '评测任务、逐样本结果与汇总' },
];

// Logical client/server architecture. Response arrows are separate from outbound requests.
export const deploymentDiagram = {
  width: 900, height: 600,
  zones: [
    { id: 'client', label: '客户端', x: 10, y: 18, width: 260, height: 570 },
    { id: 'server', label: 'AgentGuard 服务端', x: 302, y: 18, width: 350, height: 570 },
    { id: 'remote', label: '远程服务', x: 687, y: 18, width: 204, height: 430 },
  ],
  integration: { x: 26, y: 195, width: 238, height: 261, label: '配置与调用链介入', members: ['hook', 'stdio'] },
  core: { x: 313, y: 74, width: 330, height: 507, members: ['gateway', 'request-check', 'result-check', 'scanner'] },
};

// Shared management relationships, separate from request/response traffic.
export const deploymentCoreLinks = [
  { id: 'core-request', from: 'gateway', to: 'request-check', relation: '运行时策略与上下文', path: 'M 475 180 V 210 Q 475 218 467 218 H 342 Q 334 218 334 226 V 278 H 350' },
  { id: 'core-result', from: 'gateway', to: 'result-check', relation: '返回检查与审计关联', path: 'M 475 180 V 210 Q 475 218 467 218 H 342 Q 334 218 334 226 V 398 H 350' },
  { id: 'core-scan', from: 'gateway', to: 'scanner', relation: '设备管理与静态风险汇总', path: 'M 475 180 V 210 Q 475 218 467 218 H 342 Q 334 218 334 226 V 554 H 350' },
];

export const deploymentNodes = [
  {
    id: 'agent', title: '客户端 Agent', caption: '原生工具 · MCP · 模型交互', icon: 'Monitor',
    zone: 'client', x: 40, y: 90, width: 210, height: 76,
    description: 'Agent 在客户端处理任务、调用工具并使用返回内容。Hook 和 MCP 接入层将可观测调用与返回内容接入 AgentGuard。',
    facts: [['运行位置', '开发者终端'], ['执行主体', 'Agent 及其原生工具'], ['运行时接入', 'Hook / MCP'], ['静态资产', 'Skills、MCP 配置、依赖与源码']],
    sources: ['agentguard/endpoint/agentguard_endpoint/', 'agentguard/agentguard/agents/'], action: 'terminals',
  },
  {
    id: 'hook', title: '终端 Hook', caption: '注册回调 · 介入工具执行', icon: 'Connection', integration: 'config',
    zone: 'client', x: 40, y: 245, width: 210, height: 68,
    description: '在客户端 Agent 配置中注册 Hook 命令，挂接工具执行前后事件。执行前等待安全判定，再交由 Agent 处理工具；执行后上报结果与状态。',
    facts: [['接入改动', '安装终端组件，并写入 Agent 的 Hook 配置'], ['介入位置', '原有工具执行链的前后事件'], ['服务接口', '/v1/agents/{agent}/hook'], ['执行影响', '增加判定等待，按管控配置允许、询问或拒绝；故障时按降级策略处理']],
    sources: ['agentguard/endpoint/agentguard_endpoint/install.py', 'agentguard/endpoint/agentguard_endpoint/hook.py', 'agentguard/agentguard/agents/claude_code.py'], action: 'terminals',
  },
  {
    id: 'stdio', title: 'MCP 接入层', caption: '包装启动命令 / 改写 URL', icon: 'Share', integration: 'transport',
    zone: 'client', x: 40, y: 360, width: 210, height: 76,
    description: '改写客户端 MCP 配置，将安全检查插入原有通信路径。stdio 使用包装器启动原 MCP 子进程；HTTP 将原服务 URL 改为 AgentGuard 网关地址。请求与返回均经过检查。',
    facts: [['stdio 改动', '原 command / args → AgentGuard 包装命令 → 原 MCP 子进程'], ['HTTP 改动', '原 MCP URL → AgentGuard /mcp/{server}'], ['介入位置', 'Agent 与 MCP 服务之间的请求、返回链路'], ['执行影响', '增加请求与返回检查，按配置阻断调用或替换投毒原文']],
    sources: ['agentguard/endpoint/agentguard_endpoint/mcp.py', 'agentguard/agentguard/gateway/mcp.py'], action: 'terminals',
  },
  {
    id: 'assets', title: '客户端资产采集', caption: 'Skills · MCP 配置 · 源码', icon: 'Folder',
    zone: 'client', x: 40, y: 500, width: 210, height: 68,
    description: '客户端只采集允许范围内的 Agent 资产，脱敏后回传快照。服务端不直接遍历远程客户端文件系统。',
    facts: [['采集范围', '按 Agent 与授权工作区限定'], ['回传内容', '脱敏资产快照与覆盖信息'], ['分析位置', 'AgentGuard 服务端隔离子进程'], ['结果查看', '控制台静态资产与风险报告']],
    sources: ['agentguard/endpoint/agentguard_endpoint/static_scan.py', 'agentguard/agentguard/static_scan/device_api.py'],
  },
  {
    id: 'gateway', title: '统一策略与审计', caption: '身份与上下文 · 策略决策 · 证据关联', icon: 'ShieldCheck', role: 'core',
    zone: 'server', x: 325, y: 90, width: 300, height: 90,
    description: '服务端的安全管理核心，组织运行时请求检查、返回检查和静态扫描管理。运行时共用身份、上下文、检测引擎与审计；静态扫描独立执行，在平台内汇总资产与风险。',
    facts: [['请求与返回', '统一身份、上下文、策略判定和审计关联'], ['运行时证据', '贯通请求、返回、决策与执行反馈'], ['静态扫描', '共用设备管理入口，独立 worker 与数据库，汇总资产和风险'], ['管理入口', '控制台与管理 API']],
    sources: ['agentguard/agentguard/main.py', 'agentguard/agentguard/detection/engine.py', 'agentguard/agentguard/storage/'],
  },
  {
    id: 'request-check', title: '请求安全检查', caption: '权限 · 参数 · 工具能力边界', icon: 'ShieldCheck',
    zone: 'server', x: 350, y: 245, width: 275, height: 68,
    description: 'Hook 与 MCP 调用进入服务端后，先检查身份、任务上下文、工具清单和风险参数，再按 ALLOW、ASK、DENY 处理。',
    facts: [['Hook 请求', '将判定返回客户端 Hook'], ['HTTP MCP 请求', '获准后转发到已登记上游'], ['stdio MCP 请求', '获准后由本地包装器转发'], ['执行主体', '客户端原生工具或 MCP 服务']],
    sources: ['agentguard/agentguard/gateway/inspector.py', 'agentguard/agentguard/gateway/mcp.py', 'agentguard/agentguard/agents/api.py'],
  },
  {
    id: 'result-check', title: '返回内容安全检查', caption: '注入 · 敏感内容 · 来源标记', icon: 'Search',
    zone: 'server', x: 350, y: 360, width: 275, height: 76,
    description: 'MCP 工具返回先进行内容检查、污点和来源标记，再交付客户端 Agent。开启返回内容拦截时，命中投毒的原文替换为拦截说明。',
    facts: [['检查内容', '提示注入、敏感内容与结果来源'], ['HTTP MCP', '上游返回 → 网关检查 → 客户端 Agent'], ['stdio MCP', '子进程返回 → 服务端检查 → 包装器 → Agent'], ['管控方式', '按设备管控与返回拦截配置处理；观测模式记录检测结果']],
    sources: ['agentguard/agentguard/gateway/inspector.py', 'agentguard/agentguard/gateway/mcp.py', 'agentguard/endpoint/agentguard_endpoint/mcp.py'],
  },
  {
    id: 'scanner', title: '静态扫描分析', caption: '资产 · AST · 配置 · 依赖', icon: 'Files',
    zone: 'server', x: 350, y: 500, width: 275, height: 68,
    description: '接收客户端资产快照，或读取服务器已授权的项目目录，隔离解析资产、代码、配置和依赖风险，生成报告。',
    facts: [['客户端扫描', '设备采集并上传脱敏快照'], ['服务端扫描', '读取管理员登记的目录'], ['分析方式', '独立 worker 与隔离解析子进程'], ['产出', '资产清单、风险发现、证据与报告']],
    sources: ['agentguard/agentguard/static_scan/device_api.py', 'agentguard/agentguard/static_scan/worker.py', 'agentguard/agentguard/static_scan/scanner.py'],
  },
  {
    id: 'remote-mcp', title: '远程 MCP 服务', caption: '工具调用与工具返回', icon: 'Share',
    zone: 'remote', x: 705, y: 245, width: 170, height: 68,
    description: '远程 MCP 执行获准的工具调用。返回内容先进入服务端安全检查，再交付客户端 Agent。',
    facts: [['上游登记', 'AG_EXTRA_UPSTREAMS'], ['请求路径', 'Agent → 请求检查 → MCP'], ['返回路径', 'MCP → 返回内容检查 → Agent'], ['协议', 'JSON / Streamable HTTP']],
    sources: ['agentguard/agentguard/gateway/mcp.py', 'agentguard/agentguard/gateway/manifest.py'],
  },
  {
    id: 'model', title: '远程 LLM', caption: '返回内容接入示意', icon: 'Brain', status: 'design',
    zone: 'remote', x: 705, y: 90, width: 170, height: 76,
    description: '客户端保持原有模型交互方式。图中展示返回内容经 AgentGuard 安全检查后，再供 Agent 使用的接入关系。',
    facts: [['模型交互', '由客户端 Agent 与模型服务进行'], ['图示重点', '返回内容 → 安全检查 → Agent'], ['接入范围', '取决于客户端可用的响应事件与接入能力'], ['当前状态', '接入示意；尚未覆盖所有客户端的原始模型响应']],
    sources: [],
  },
];

export const deploymentEdges = [
  { id: 'agent-hook', from: 'agent', to: 'hook', kind: 'request', path: 'M 180 166 V 245', label: 'Hook 事件', x: 168, y: 205 },
  { id: 'hook-request', from: 'hook', to: 'request-check', kind: 'request', path: 'M 250 264 H 350', label: '调用检查', x: 286, y: 250 },
  { id: 'request-hook', from: 'request-check', to: 'hook', kind: 'response', path: 'M 350 298 H 250', label: '处理决策', x: 286, y: 322 },
  { id: 'hook-agent', from: 'hook', to: 'agent', kind: 'response', path: 'M 104 245 V 166', label: '', x: 0, y: 0 },
  { id: 'agent-stdio', from: 'agent', to: 'stdio', kind: 'request', path: 'M 40 136 H 30 Q 18 136 18 148 V 382 Q 18 394 30 394 H 40', label: 'MCP 请求', x: 48, y: 180 },
  { id: 'stdio-request', from: 'stdio', to: 'request-check', kind: 'request', path: 'M 250 378 H 280 Q 292 378 292 366 V 296 Q 292 284 304 284 H 350', label: '接入检查', x: 286, y: 350 },
  { id: 'request-stdio', from: 'request-check', to: 'stdio', kind: 'response', path: 'M 350 305 H 318 Q 306 305 306 317 V 388 Q 306 400 294 400 H 250', label: '', x: 0, y: 0 },
  { id: 'stdio-result', from: 'stdio', to: 'result-check', kind: 'response', path: 'M 250 412 H 350', label: '子进程返回', x: 286, y: 478 },
  { id: 'result-stdio', from: 'result-check', to: 'stdio', kind: 'response', path: 'M 350 426 H 250', label: '检查后返回', x: 286, y: 448 },
  { id: 'stdio-agent', from: 'stdio', to: 'agent', kind: 'response', path: 'M 76 360 V 344 H 264 Q 276 344 276 332 V 158 Q 276 146 264 146 H 250', label: '', x: 0, y: 0 },
  { id: 'request-mcp', from: 'request-check', to: 'remote-mcp', kind: 'request', path: 'M 625 268 H 705', label: '工具请求', x: 665, y: 251 },
  { id: 'mcp-result', from: 'remote-mcp', to: 'result-check', kind: 'response', path: 'M 705 298 H 676 Q 664 298 664 310 V 400 Q 664 412 652 412 H 625', label: '原始工具返回', x: 710, y: 352 },
  { id: 'result-agent', from: 'result-check', to: 'agent', kind: 'response', path: 'M 350 379 H 298 Q 286 379 286 367 V 150 Q 286 138 274 138 H 250', label: '检查后交付 Agent', x: 285, y: 228 },
  { id: 'llm-result', from: 'model', to: 'result-check', kind: 'response', status: 'design', path: 'M 705 134 H 694 Q 682 134 682 146 V 370 Q 682 382 670 382 H 625', label: '返回内容接入示意', x: 771, y: 193 },
  { id: 'assets-scan', from: 'assets', to: 'scanner', kind: 'data', path: 'M 250 534 H 350', label: '脱敏资产快照', x: 286, y: 485 },
];

export const deploymentFlows = [
  { id: 'all', label: '总览', nodes: deploymentNodes.map(node => node.id), edges: ['agent-hook', 'hook-request', 'request-hook', 'hook-agent', 'agent-stdio', 'stdio-request', 'request-mcp', 'mcp-result', 'result-stdio', 'stdio-agent', 'result-agent', 'llm-result', 'assets-scan'], focus: 'gateway', steps: [] },
  { id: 'hook', label: '终端 Hook', nodes: ['agent', 'hook', 'request-check', 'gateway'], edges: ['agent-hook', 'hook-request', 'request-hook', 'hook-agent'], focus: 'hook', steps: ['Agent 触发 Hook', '服务端安全判定', '处理决策返回客户端', '执行后上报结果'] },
  { id: 'stdio', label: 'stdio MCP', nodes: ['agent', 'stdio', 'request-check', 'result-check', 'gateway'], edges: ['agent-stdio', 'stdio-request', 'request-stdio', 'stdio-result', 'result-stdio', 'stdio-agent'], focus: 'stdio', steps: ['包装器接收调用', '请求检查与本地 MCP 执行', '工具返回先做内容检查', '检查后交付 Agent'] },
  { id: 'http', label: 'HTTP MCP', nodes: ['agent', 'stdio', 'request-check', 'result-check', 'remote-mcp', 'gateway'], edges: ['agent-stdio', 'stdio-request', 'request-mcp', 'mcp-result', 'result-stdio', 'stdio-agent'], focus: 'stdio', steps: ['MCP URL 指向网关', '请求检查后调用远程 MCP', '远程返回先经内容检查', '沿接入链路交付 Agent'] },
  { id: 'response', label: '返回检查', nodes: ['agent', 'stdio', 'result-check', 'remote-mcp', 'gateway'], edges: ['mcp-result', 'result-stdio', 'stdio-agent'], focus: 'result-check', steps: ['远程 MCP 返回', 'AgentGuard 内容检查', '按管控返回内容或拦截说明', '客户端 Agent 使用结果'] },
  { id: 'llm', label: 'LLM 返回', status: 'design', nodes: ['agent', 'model', 'result-check', 'gateway'], edges: ['llm-result', 'result-agent'], focus: 'model', steps: ['返回内容接入示意', 'AgentGuard 检查关系', '返回检查处理结果', '客户端 Agent 使用结果'] },
  { id: 'scan', label: '静态扫描', nodes: ['assets', 'scanner', 'gateway'], edges: ['assets-scan'], focus: 'scanner', steps: ['客户端采集授权资产', '上传脱敏资产快照', '服务端隔离分析', '控制台查看资产与风险'] },
];

const localEnvironment = [
  'export AG_LOCAL_TEST=1',
  'export AG_DATA_DIR="$HOME/.local/share/agentguard-dev"',
  'export AG_STATIC_DB="$AG_DATA_DIR/static-scan.db"',
  'export AG_EVAL_DB="$AG_DATA_DIR/evaluation.db"',
].join('\n');

export const deploymentMethods = [
  {
    id: 'docker', title: 'Docker Compose', icon: 'Boxes', summary: '单容器运行网关与独立 worker',
    requirements: ['Docker Engine', 'Docker Compose v2'],
    address: deploymentDefaults.console,
    facts: [['执行位置', '仓库根目录'], ['前端资源', '使用已入库的 dist 构建产物'], ['进程启动', '由 start.sh 统一启动'], ['数据保留', '3 个 Docker 命名数据卷']],
    steps: [
      { title: '准备配置', context: '仓库根目录', code: 'cp .env.example .env', format: 'bash' },
      { title: '构建并启动服务', context: '仓库根目录', code: 'docker compose -f docker-compose.agentguard.yml up -d --build', format: 'bash' },
      { title: '检查网关健康状态', context: '宿主机', code: 'curl -fsS http://127.0.0.1:18080/health', format: 'bash' },
    ],
    configurations: [
      { title: '团队服务配置', context: '根目录 .env', format: 'dotenv', code: 'AG_LOCAL_TEST=0\nAG_HOOK_SECRET=<独立生成的随机密钥>\nAG_AGENT_ADMIN_TOKEN=<管理令牌>\nAG_EVAL_ADMIN_TOKEN=<评测管理令牌>' },
      { title: '远程控制台访问', context: '本机终端 · 替换服务器账号', format: 'bash', code: 'ssh -N -L 18080:127.0.0.1:18080 user@server' },
      { title: '登记 HTTP MCP 上游', context: '根目录 .env · 替换上游地址后重新创建容器', format: 'dotenv', code: 'AG_EXTRA_UPSTREAMS={"docs":"http://your-mcp-host:8000/mcp"}' },
    ],
  },
  {
    id: 'source', title: '源码运行', icon: 'Document', summary: '主网关与 worker 分别启动',
    requirements: ['Python 3.12', 'Node.js 20+ / npm（仅前端开发）'],
    address: deploymentDefaults.localConsole,
    facts: [['执行位置', '各终端从仓库根目录开始'], ['前端资源', '可使用现有 dist，修改后再构建'], ['进程启动', '网关与 worker 分别运行'], ['配置方式', '读取环境变量，不自动加载根目录 .env'], ['数据保留', '$HOME/.local/share/agentguard-dev']],
    steps: [
      { title: '安装服务端依赖', context: '仓库根目录', code: 'python3 -m venv .venv\n.venv/bin/python -m pip install -r agentguard/requirements.txt', format: 'bash' },
      { title: '启动主网关', context: '独立终端 · 仓库根目录', code: localEnvironment + '\ncd agentguard\n../.venv/bin/python -m uvicorn --factory agentguard.main:create_app \\\n  --host 127.0.0.1 --port 8080', format: 'bash' },
      { title: '启动静态扫描 worker', context: '另开终端 · 仓库根目录', code: localEnvironment + '\ncd agentguard\n../.venv/bin/python -m agentguard.static_scan.worker', format: 'bash' },
      { title: '启动 评测 worker', context: '按需另开终端 · 仓库根目录', code: localEnvironment + '\ncd agentguard\n../.venv/bin/python -m agentguard.evaluation', format: 'bash' },
    ],
    configurations: [
      { title: '前端开发', context: '另开终端 · 仓库根目录', format: 'bash', code: 'cd agentguard/console\nnpm ci\nnpm run dev' },
      { title: '构建控制台', context: '仓库根目录', format: 'bash', code: 'cd agentguard/console\nnpm run build' },
      { title: '登记扫描目录', context: '主网关与扫描 worker 启动前，分别设置实际授权路径', format: 'bash', code: 'export AG_STATIC_SOURCES=\'{"project":"/absolute/path/to/project"}\'' },
      { title: '登记 HTTP MCP 上游', context: '主网关启动前 · 替换上游地址', format: 'bash', code: 'export AG_EXTRA_UPSTREAMS=\'{"docs":"http://your-mcp-host:8000/mcp"}\'' },
    ],
  },
];
