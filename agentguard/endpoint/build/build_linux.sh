#!/bin/sh
# 构建 Linux 版 AgentGuard 终端客户端（PyInstaller onedir，x86_64）。
#
#   sh endpoint/build/build_linux.sh [--local] [--out DIR]
#
# 默认在 python:3.12-slim-bullseye 容器中构建：产物只依赖 glibc 2.31+（Ubuntu 20.04+ / Debian 11+ /
# RHEL 9+），不受构建机发行版影响；--local 用本机 python3 构建（产物要求的 glibc 不低于本机）。
# 选 onedir 的原因同 build_windows.ps1：Hook 每个事件启动一次进程，onefile 每次都要先解压。
# 产物：<out>/agentguard-endpoint-linux-x64.tar.gz（解压为 agentguard-endpoint/），默认 out 为
# endpoint/dist——服务端 /v1/agents/client 从这里提供下载（重建服务端镜像后生效）。
# 有 python3（3.8+）的主机也可以直接用脚本包，不需要构建：/v1/agents/client/agentguard-endpoint.tar.gz。
# 容器内连不上 deb.debian.org 时用 APT_MIRROR 指定镜像站，例如 APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn。
set -eu

ENDPOINT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ENDPOINT/dist"
LOCAL=0
PYINSTALLER_VERSION=6.16.0
IMAGE=python:3.12-slim-bullseye
while [ $# -gt 0 ]; do
    case "$1" in
        --local) LOCAL=1 ;;
        --out) OUT=$2; shift ;;
        *) echo "usage: $0 [--local] [--out DIR]" >&2; exit 2 ;;
    esac
    shift
done
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
NAME=agentguard-endpoint-linux-x64.tar.gz

# 在 $1（含 agentguard-endpoint.py 与 agentguard_endpoint/ 的源码副本）中构建，产物写到 $2。
BUILD='set -eu
src=$1; out=$2; work=$(mktemp -d)
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install --disable-pip-version-check -q "pyinstaller==$PYINSTALLER_VERSION"
cp -r "$src/agentguard-endpoint.py" "$src/agentguard_endpoint" "$work/"
find "$work/agentguard_endpoint" -name __pycache__ -prune -exec rm -rf {} +
cd "$work"
"$work/venv/bin/pyinstaller" --noconfirm --clean --onedir --console --name agentguard-endpoint \
    --distpath "$work/dist" --workpath "$work/pyi" --specpath "$work" --paths "$work" \
    --collect-submodules agentguard_endpoint agentguard-endpoint.py >"$work/pyinstaller.log" 2>&1 \
    || { tail -30 "$work/pyinstaller.log"; exit 1; }
"$work/dist/agentguard-endpoint/agentguard-endpoint" --version
tar -C "$work/dist" -czf "$out/'"$NAME"'" agentguard-endpoint
rm -rf "$work"'

if [ "$LOCAL" = 1 ]; then
    PYINSTALLER_VERSION=$PYINSTALLER_VERSION sh -c "$BUILD" build "$ENDPOINT" "$OUT"
else
    # PyInstaller 在 Linux 上需要 objdump（binutils）；容器内以 root 安装后构建，产物属主改回当前用户。
    docker run --rm -e PYINSTALLER_VERSION="$PYINSTALLER_VERSION" -e PIP_NO_CACHE_DIR=1 \
        -e PIP_ROOT_USER_ACTION=ignore -e OWNER="$(id -u):$(id -g)" -e BUILD="$BUILD" \
        -e APT_MIRROR="${APT_MIRROR:-}" -v "$ENDPOINT:/src:ro" -v "$OUT:/out" "$IMAGE" sh -c '
            [ -z "$APT_MIRROR" ] || sed -i "s|http://deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list
            apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends binutils >/dev/null
            sh -c "$BUILD" build /src /out && chown "$OWNER" /out/'"$NAME"
fi
echo "built $OUT/$NAME"
