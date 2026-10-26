"""主机网络信息：访问服务端所用网卡的 IPv4 地址与 MAC（只用标准库，Windows / Linux / macOS）。

只用于控制台展示，不参与鉴权或决策（终端自报的值可被伪造；服务端另记它看到的来源地址）。
- IP：向服务端地址 connect 一个 UDP 套接字取本端地址（不发包），即实际出网网卡的地址；
  服务端在本机时取默认路由网卡的地址；
- MAC：按该 IP 找到网卡再取物理地址——Windows 用 iphlpapi.GetAdaptersInfo，Linux 用
  ioctl(SIOCGIFADDR) + /sys/class/net/<if>/address，macOS 解析 ifconfig；都失败时退回
  uuid.getnode()（随机生成的值不采用）。
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import urllib.parse
import uuid

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _format_mac(raw: bytes) -> str:
    mac = ":".join(f"{byte:02x}" for byte in raw[:6])
    return mac if MAC_RE.match(mac) and mac != "00:00:00:00:00:00" else ""


def outbound_ip(server_url: str) -> str:
    """访问服务端所用的本机地址；服务端在本机（回环）时取默认路由网卡的地址。"""
    ip = _local_address(server_url)
    if not ip or ip.startswith("127."):
        ip = _local_address("http://192.0.2.1:80") or ip   # TEST-NET 地址：只用于选路，不发包
    return ip


def _local_address(server_url: str) -> str:
    parsed = urllib.parse.urlsplit(server_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        family = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(family[4])
            return probe.getsockname()[0]
    except OSError:
        return ""


def _windows_mac(ip: str) -> str:
    import ctypes
    from ctypes import wintypes

    class IP_ADDR_STRING(ctypes.Structure):
        pass

    IP_ADDR_STRING._fields_ = [("Next", ctypes.POINTER(IP_ADDR_STRING)), ("IpAddress", ctypes.c_char * 16),
                               ("IpMask", ctypes.c_char * 16), ("Context", wintypes.DWORD)]

    class IP_ADAPTER_INFO(ctypes.Structure):
        pass

    IP_ADAPTER_INFO._fields_ = [
        ("Next", ctypes.POINTER(IP_ADAPTER_INFO)), ("ComboIndex", wintypes.DWORD),
        ("AdapterName", ctypes.c_char * 260), ("Description", ctypes.c_char * 132),
        ("AddressLength", wintypes.UINT), ("Address", ctypes.c_ubyte * 8), ("Index", wintypes.DWORD),
        ("Type", wintypes.UINT), ("DhcpEnabled", wintypes.UINT), ("CurrentIpAddress", ctypes.c_void_p),
        ("IpAddressList", IP_ADDR_STRING), ("GatewayList", IP_ADDR_STRING), ("DhcpServer", IP_ADDR_STRING),
        ("HaveWins", wintypes.BOOL), ("PrimaryWinsServer", IP_ADDR_STRING),
        ("SecondaryWinsServer", IP_ADDR_STRING), ("LeaseObtained", ctypes.c_int64), ("LeaseExpires", ctypes.c_int64)]

    get_info = ctypes.windll.iphlpapi.GetAdaptersInfo
    size = wintypes.ULONG(0)
    get_info(None, ctypes.byref(size))
    if not size.value:
        return ""
    buffer = ctypes.create_string_buffer(size.value)
    if get_info(buffer, ctypes.byref(size)) != 0:
        return ""
    adapter = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_INFO))
    first = ""
    while adapter:
        info = adapter.contents
        mac = _format_mac(bytes(info.Address[:info.AddressLength]))
        first = first or mac
        entry = info.IpAddressList
        while True:
            if entry.IpAddress.decode("ascii", "ignore") == ip and mac:
                return mac
            if not entry.Next:
                break
            entry = entry.Next.contents
        adapter = info.Next
    return first if not ip else ""


def _linux_mac(ip: str) -> str:
    import fcntl
    import struct

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for _, name in socket.if_nameindex():
            try:
                packed = fcntl.ioctl(probe.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))  # SIOCGIFADDR
            except OSError:
                continue
            if socket.inet_ntoa(packed[20:24]) == ip:
                try:
                    with open(f"/sys/class/net/{name}/address", encoding="ascii") as handle:
                        mac = handle.read().strip().lower()
                    return mac if MAC_RE.match(mac) and mac != "00:00:00:00:00:00" else ""
                except OSError:
                    return ""
    return ""


def _mac_ifconfig(ip: str) -> str:
    try:
        text = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    for block in re.split(r"\n(?=\S)", text):
        if re.search(rf"\binet {re.escape(ip)}\b", block):
            match = re.search(r"\bether ([0-9a-f:]{17})\b", block)
            return match.group(1) if match else ""
    return ""


def _fallback_mac() -> str:
    node = uuid.getnode()
    # 第 41 位（组播位）置 1 表示 uuid 取不到真实网卡、随机生成的值。
    if node >> 40 & 1:
        return ""
    return _format_mac(node.to_bytes(6, "big"))


def mac_for(ip: str) -> str:
    try:
        if sys.platform == "win32":
            mac = _windows_mac(ip)
        elif sys.platform.startswith("linux") and os.path.isdir("/sys/class/net"):
            mac = _linux_mac(ip)
        else:
            mac = _mac_ifconfig(ip)
    except Exception:  # noqa: BLE001 — 取不到 MAC 不影响 Hook
        mac = ""
    return mac or _fallback_mac()
