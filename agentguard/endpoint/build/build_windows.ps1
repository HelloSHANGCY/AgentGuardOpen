# 构建 Windows 版 AgentGuard 终端客户端（PyInstaller onedir）。
#
#   powershell -ExecutionPolicy Bypass -File endpoint\build\build_windows.ps1 [-Python py] [-Out D:\out]
#
# 选 onedir 而非 onefile：Hook 每个事件启动一次进程，onefile 每次都要先解压到临时目录
# （再叠加杀毒扫描），冷启动 0.5–1.5 s；onedir 约 0.1–0.2 s。
# 构建在临时 venv 中进行，不改动系统 Python；源码先复制到本地临时目录（PyInstaller 不支持
# \\wsl.localhost 这类 UNC 路径作为工作目录）。产物：<Out>\agentguard-endpoint\ 与同名 zip。

param(
    [string]$Python = "python",
    [string]$Out = "",
    [string]$PyInstallerVersion = "6.16.0"
)
$ErrorActionPreference = "Stop"

$endpoint = Split-Path -Parent $PSScriptRoot
if (-not $Out) { $Out = Join-Path $env:TEMP "agentguard-endpoint-dist" }
$work = Join-Path $env:TEMP "agentguard-endpoint-build"
$src = Join-Path $work "src"
$venv = Join-Path $work "venv"

if (Test-Path $src) { Remove-Item -Recurse -Force $src }
New-Item -ItemType Directory -Force -Path $src | Out-Null
Copy-Item (Join-Path $endpoint "agentguard-endpoint.py") $src
Copy-Item -Recurse (Join-Path $endpoint "agentguard_endpoint") $src
Get-ChildItem -Path $src -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force

if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
    & $Python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
}
$vpy = Join-Path $venv "Scripts\python.exe"
& $vpy -m pip install --disable-pip-version-check -q "pyinstaller==$PyInstallerVersion"
if ($LASTEXITCODE -ne 0) { throw "pip install pyinstaller failed" }

Push-Location $src
try {
    & $vpy -m PyInstaller --noconfirm --clean --onedir --console --name agentguard-endpoint `
        --distpath $Out --workpath (Join-Path $work "pyi") --specpath $work --paths $src `
        --collect-submodules agentguard_endpoint agentguard-endpoint.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
} finally {
    Pop-Location
}

$dir = Join-Path $Out "agentguard-endpoint"
$zip = Join-Path $Out "agentguard-endpoint-windows-x64.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $dir -DestinationPath $zip
& (Join-Path $dir "agentguard-endpoint.exe") --version
Write-Host "built $dir"
Write-Host "zip   $zip"
