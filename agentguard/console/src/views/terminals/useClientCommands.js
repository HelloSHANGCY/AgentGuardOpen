import { computed, ref } from "vue";
import { ElMessage } from "element-plus";
import { AGENT_NAMES } from "../../store/runtime";
import { deviceData } from "../../store/devices";

export function useClientCommands(issued = ref(null)) {
  const origin = location.origin;
  // 客户端从服务端下载（/v1/agents/client）：有预构建包（Windows exe / Linux x64 二进制）时用它，
  // 否则 Linux / macOS 用脚本包（python3 3.8+）；Windows 没有发布 exe 时在手动解压的目录中执行。
  const platform = ref(navigator.userAgent.includes("Windows") ? "windows"
    : (navigator.userAgent.includes("Mac OS") ? "macos" : "linux"));
  const clientUrl = (name) => `${location.origin}/v1/agents/client/${name}`;
  const published = (name) => (deviceData.value.clients || []).some((c) => c.name === name);
  const setup = computed(() => {
    if (platform.value === "windows") {
      const zip = "agentguard-endpoint-windows-x64.zip";
      if (!published(zip)) {
        return { lines: [], exe: ".\\agentguard-endpoint.exe" };
      }
      return { lines: [`iwr ${clientUrl(zip)} -OutFile $env:TEMP\\agentguard-endpoint.zip`,
        "Expand-Archive $env:TEMP\\agentguard-endpoint.zip $env:TEMP\\agentguard-setup -Force",
        "cd $env:TEMP\\agentguard-setup\\agentguard-endpoint"],
      exe: ".\\agentguard-endpoint.exe" };
    }
    const binary = "agentguard-endpoint-linux-x64.tar.gz";
    if (platform.value === "linux" && published(binary)) {
      return { lines: [`cd "$(mktemp -d)" && curl -fsSL ${clientUrl(binary)} | tar xz`],
        exe: "./agentguard-endpoint/agentguard-endpoint" };
    }
    return { lines: [`cd "$(mktemp -d)" && curl -fsSL ${clientUrl("agentguard-endpoint.tar.gz")} | tar xz`],
      exe: "python3 agentguard-endpoint/agentguard-endpoint.py" };
  });

  function commandBlock(installs, agents) {
    const { lines, exe } = setup.value;
    return lines.concat(installs.map((args, i) => `${exe} install --agent ${agents[i]} ${args}`))
      .concat(agents.map((a) => `${exe} self-test --agent ${a}`)).join("\n");
  }
  const installCommand = computed(() => {
    if (!issued.value) return "";
    const { agents } = issued.value.device;
    const args = `--url ${location.origin} --token ${issued.value.token}`;
    return commandBlock(agents.map(() => args), agents);
  });
  const deployAgentsText = computed(() => (deviceData.value.deploy?.agents || []).map((a) => AGENT_NAMES[a] || a).join("、") || "—");
  // 一键命令中的地址取部署配置（终端访问服务端所用的地址），下载链接用当前地址。
  const oneClick = computed(() => {
    const url = deviceData.value.deploy?.effective_url || origin;
    const machine = deviceData.value.deploy?.scope === "machine";
    if (platform.value === "windows") {
      return {
        install: `irm ${url}/v1/agents/install.ps1 | iex`,
        uninstall: `irm ${url}/v1/agents/uninstall.ps1 | iex`,
        warning: published("agentguard-endpoint-windows-x64.zip") ? ""
          : "未发布 Windows 客户端包",
      };
    }
    const sh = machine ? "sudo sh" : "sh";
    return {
      install: `curl -fsSL ${url}/v1/agents/install.sh | ${sh}`,
      uninstall: `curl -fsSL ${url}/v1/agents/uninstall.sh | ${sh}`,
      warning: platform.value === "linux" && !published("agentguard-endpoint-linux-x64.tar.gz")
        ? "未发布 Linux 二进制包" : "",
    };
  });

  async function copyCommand(text, label = "命令") {
    try {
      await navigator.clipboard.writeText(text);
      ElMessage.success("已复制" + label);
    } catch {
      ElMessage.warning("复制失败，请手动选择文本");
    }
  }

  return { platform, origin, installCommand, deployAgentsText, oneClick, copyCommand };
}
