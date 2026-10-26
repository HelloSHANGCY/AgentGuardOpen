// 静态扫描相关枚举的中文显示；未知值原样返回，保证后端新增枚举时不丢信息。
import { themeColor } from "./theme";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const sevRank = (s) => { const i = SEVERITIES.indexOf(s); return i < 0 ? SEVERITIES.length : i; };
export const severityName = (s) => ({ CRITICAL: "严重", HIGH: "高危", MEDIUM: "中危", LOW: "低危", INFO: "提示" }[s] || s);

// 规则标题与后端 static_scan/rules/*.py 中的 title 保持一致；列表接口只返回单条 finding 的实例标题。
const RULE_TITLES = {
  "AG-STATIC-CODE-001": "外部参数未经约束进入 shell/eval/exec",
  "AG-STATIC-CODE-002": "敏感文件/环境变量进入外发 sink",
  "AG-STATIC-MCP-001": "隐藏但可调用的危险工具",
  "AG-STATIC-MCP-002": "启动回调读取敏感环境并外发",
  "AG-STATIC-MCP-003": "工具描述投毒诱导跨工具访问或泄密",
  "AG-STATIC-CFG-001": "默认弱密钥或固定明文密钥",
  "AG-STATIC-CFG-002": "自动登录或鉴权关闭",
  "AG-STATIC-CFG-003": "特权容器或宿主敏感目录挂载",
  "AG-STATIC-CFG-004": "Agent 可绕开网关直连原始服务",
  "AG-STATIC-CFG-005": "远程高风险端点使用不安全传输",
  "AG-STATIC-CFG-006": "Skill 权限缺失、通配或声明与使用不一致",
  "AG-STATIC-CFG-007": "模型/数据不受控动态加载",
  "AG-STATIC-CFG-008": "依赖或镜像未固定版本/摘要",
  "AG-STATIC-SKILL-001": "Skill 指令要求读凭证外传、隐藏操作或覆盖用户指令",
  "AG-STATIC-SKILL-002": "常量解码内容流入 exec/eval/shell",
  "AG-STATIC-SKILL-003": "下载内容进入命令执行或含下载执行线索",
  "AG-STATIC-SUPPLY-001": "依赖命中已知漏洞",
  "AG-STATIC-CC-001": "Agent 权限过宽：跳过确认或通配授权高危工具",
  "AG-STATIC-CC-002": "自动启用项目内全部 MCP server",
  "AG-STATIC-CC-003": "Agent Hook 命令包含下载执行或网络外发",
  "AG-STATIC-CC-004": "MCP server 未经 AgentGuard 中转",
  "AG-STATIC-CC-005": "Agent 指令文件包含提示注入",
};
export const ruleTitle = (id) => RULE_TITLES[id] || id;

export const categoryName = (c) => ({
  config: "配置", code: "代码", mcp_malicious: "MCP 恶意行为", skill_malicious: "Skill 恶意行为",
  instruction_clue: "指令线索", supply_chain: "供应链", agent_config: "Agent 配置",
}[c] || c || "-");

export const confidenceName = (c) => ({ high: "高", medium: "中", low: "低" }[c] || c || "-");

// 资产类型按安全相关性排序：Agent 与其可调用能力在前，配置文件与普通依赖在后。
export const KIND_ORDER = ["AgentApplication", "MCPServer", "Tool", "Skill", "SecretReference", "Endpoint",
                           "ModelReference", "Framework", "Dependency", "ConfigArtifact"];
export const kindRank = (k) => { const i = KIND_ORDER.indexOf(k); return i < 0 ? KIND_ORDER.length : i; };
export const kindName = (k) => ({
  AgentApplication: "Agent 应用", MCPServer: "MCP 服务", Tool: "工具", Skill: "Skill",
  SecretReference: "密钥引用", Endpoint: "外部端点", ModelReference: "模型引用",
  Framework: "框架", Dependency: "依赖", ConfigArtifact: "配置文件",
}[k] || k);

export const discoveryName = (m) => ({
  agent_config: "Agent 配置", agent_route_table: "Agent 路由表", compose_service: "Compose 服务",
  dependency: "依赖声明", requirements: "requirements", dockerfile: "Dockerfile", entry_and_config: "入口与配置",
  env_read: "环境变量读取", file_index: "文件索引", flow_json: "Flow 定义", import: "代码导入",
  mcp_config: "MCP 配置", skill_md: "SKILL.md", source_registration: "源码注册", device_snapshot: "设备快照",
  claude_code_config: "Claude Code 配置",
}[m] || m || "-");

export const relationName = (r) => ({
  EXPOSES_TOOL: "暴露工具", CONNECTS_TO: "连接", HANDLED_BY: "由…处理", CONFIGURED_BY: "配置来源",
  LOADS_SKILL: "加载 Skill", USES_FRAMEWORK: "使用框架", USES_MODEL: "使用模型", READS_SECRET: "读取密钥",
}[r] || r);

export const scanStatusName = (s) => ({
  QUEUED: "排队中", RUNNING: "扫描中", COMPLETED: "已完成", PARTIAL: "部分完成",
  FAILED: "失败", CANCELLED: "已取消", INTERRUPTED: "已中断",
}[s] || s);

export const scanPhaseName = (p) => ({
  QUEUED: "排队", WAITING_ENDPOINT: "等待终端", COLLECTING: "终端采集", SNAPSHOTTING: "制作快照", DISCOVERING: "发现资产", ANALYZING: "分析",
  RUNNING: "运行", FINALIZING: "汇总结果",
}[p] || p);

export const scanChannelState = (device, agent = '', now = Date.now()) => {
  const channel = device?.scan_channel;
  if (!channel?.last_seen || device?.uninstalled_at) return { label: '未连接', type: 'info' };
  if (agent && !channel.agents?.includes(agent)) return { label: '未启用', type: 'info' };
  const elapsed = now - Date.parse(channel.last_seen);
  return elapsed >= 0 && elapsed < 120000
    ? { label: '在线', type: 'success' } : { label: '离线', type: 'warning' };
};

const LIMIT_NAMES = {
  decode_operations: "解码操作次数上限", max_depth: "目录深度上限",
  max_files: "文件数量上限", max_total_bytes: "总字节数上限",
  max_file_parse_bytes: "单文件大小上限", collection_timeout: "终端采集时间上限",
};
// 限额命中：{limit, count} 或 {limit, path}；老数据可能是字符串。
export const limitHitText = (h) => {
  if (typeof h === "string") return LIMIT_NAMES[h] || h;
  const name = LIMIT_NAMES[h.limit] || h.limit;
  if (h.count !== undefined) return `${name}（触达 ${h.count} 次）`;
  if (h.path) return `${name}：${h.path}`;
  return name;
};

export const coverageNoteText = (note) => {
  if (note.startsWith('parse_error:')) {
    const match = /^parse_error:(.*?):(ast:)?(.*)$/.exec(note);
    if (match) {
      const reason = { SyntaxError: '语法错误', IndentationError: '缩进错误', TabError: '缩进混用',
        RecursionError: '嵌套深度超限' }[match[3]] || match[3];
      return `文件解析失败：${match[1]} · ${reason}`;
    }
  }
  if (note.startsWith('read_failed:')) return '文件读取失败：' + note.slice(12);
  if (note.startsWith('collection_gap:')) {
    const gap = note.slice(15), i = gap.lastIndexOf(':');
    const reason = { file_too_large: '超过单文件大小上限', total_bytes: '超过总大小上限',
      max_files: '超过文件数量上限', max_depth: '超过目录深度上限',
      symlink: '符号链接或目录链接', special_file: '特殊文件', binary: '非文本文件',
      read_failed: '读取失败', invalid_config: '无法安全解析或脱敏',
      workspace_unavailable: '当前项目不可用', collection_timeout: '采集超时',
    }[gap.slice(i + 1)];
    return '采集跳过：' + (reason ? `${gap.slice(0, i)} · ${reason}` : gap);
  }
  return note;
};

// 资产类型配色：图谱节点与列表中的类型圆点共用。
const KIND_COLORS = {
  AgentApplication: "--asset-agent", MCPServer: "--asset-mcp", Tool: "--asset-tool", Skill: "--asset-skill",
  ModelReference: "--asset-model", Framework: "--asset-framework", Dependency: "--asset-dependency", ConfigArtifact: "--asset-config",
  SecretReference: "--asset-secret", Endpoint: "--asset-endpoint",
};
export const kindColor = (k) => themeColor(KIND_COLORS[k] || "--asset-dependency");
