"""端口采集核心模块。

基于 psutil 读取本机 TCP/UDP 监听端口，并关联到占用进程。
提供：端口清单采集、单个端口查询、两次快照的差异比对。
"""

from __future__ import annotations

import datetime as dt
import socket
from typing import Any

import psutil

UNKNOWN = "<未知>"


def _process_info(pid: int | None, cache: dict[int, tuple[str, str, str]]) -> tuple[str, str, str]:
    """安全读取进程信息，带缓存，权限不足时降级为未知。"""
    if not pid:
        return UNKNOWN, "", ""
    if pid in cache:
        return cache[pid]
    try:
        proc = psutil.Process(pid)
        info = (proc.name(), proc.exe(), " ".join(proc.cmdline()))
    except (psutil.Error, OSError):
        try:
            info = (psutil.Process(pid).name(), "", "")
        except (psutil.Error, OSError):
            info = (f"PID {pid} (无权访问)", "", "")
    cache[pid] = info
    return info


def _scope(ip: str) -> str:
    """判断监听地址的作用范围。"""
    if not ip or ip == "*":
        return "未知"
    if ip in ("0.0.0.0", "::"):
        return "所有网卡（对外）"
    if ip.startswith("127.") or ip == "::1":
        return "仅本机"
    if ip.startswith("169.254."):
        return "链路本地"
    return "指定地址"


def _protocol(conn: psutil._common.sconn) -> str:
    if conn.type == socket.SOCK_STREAM:
        return "TCP"
    if conn.type == socket.SOCK_DGRAM:
        return "UDP"
    return getattr(conn.type, "name", str(conn.type))


def _connections() -> list[psutil._common.sconn]:
    try:
        return psutil.net_connections(kind="inet")
    except (psutil.Error, OSError):
        return []


def _is_listening(conn: psutil._common.sconn) -> bool:
    """TCP 看 LISTEN 状态；UDP 看是否为绑定端口（无远端地址）。"""
    if conn.type == socket.SOCK_STREAM:
        return conn.status == psutil.CONN_LISTEN
    if conn.type == socket.SOCK_DGRAM:
        return not conn.raddr
    return False


def port_key(item: dict[str, Any]) -> str:
    """生成唯一键，用于快照差异比对。"""
    return f"{item['protocol']}|{item['address']}|{item['port']}"


def collect_ports() -> list[dict[str, Any]]:
    """采集所有被占用的监听端口（TCP LISTEN + UDP 绑定）。"""
    cache: dict[int, tuple[str, str, str]] = {}
    seen: set[tuple[str, str, int]] = set()
    result: list[dict[str, Any]] = []
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for conn in _connections():
        if not conn.laddr or not _is_listening(conn):
            continue
        address = conn.laddr.ip or ""
        port = int(conn.laddr.port)
        proto = _protocol(conn)
        identity = (proto, address, port)
        if identity in seen:
            continue
        seen.add(identity)

        pid = conn.pid or 0
        name, exe, cmdline = _process_info(pid, cache)
        result.append(
            {
                "port": port,
                "protocol": proto,
                "address": address or "*",
                "scope": _scope(address),
                "state": "监听中" if proto == "TCP" else "已绑定",
                "pid": pid,
                "process": name,
                "exe": exe,
                "cmdline": cmdline,
                "observed_at": now,
            }
        )

    result.sort(key=lambda x: (x["port"], x["protocol"], x["address"]))
    return result


def query_port(port: int, protocol: str | None = None) -> dict[str, Any]:
    """查询任意端口是否被使用（含已建立的连接）。"""
    if not 0 < int(port) < 65536:
        return {"in_use": False, "error": "端口号须在 1-65535 之间"}

    cache: dict[int, tuple[str, str, str]] = {}
    matches: list[dict[str, Any]] = []
    for conn in _connections():
        proto = _protocol(conn)
        if protocol and proto != protocol.upper():
            continue
        laddr = conn.laddr
        raddr = conn.raddr
        hit_local = bool(laddr and int(laddr.port) == int(port))
        hit_remote = bool(raddr and int(raddr.port) == int(port))
        if not (hit_local or hit_remote):
            continue

        if hit_local and _is_listening(conn):
            role = "本地监听" if proto == "TCP" else "本地绑定"
        elif hit_local:
            role = "本地连接占用"
        else:
            role = "远端连接端口"

        pid = conn.pid or 0
        name, exe, cmdline = _process_info(pid, cache)
        matches.append(
            {
                "port": int(port),
                "protocol": proto,
                "role": role,
                "address": (laddr.ip if laddr else "") or "",
                "state": conn.status or "",
                "pid": pid,
                "process": name,
                "exe": exe,
                "cmdline": cmdline,
            }
        )

    return {
        "in_use": bool(matches),
        "port": int(port),
        "protocol": protocol or "全部",
        "matches": matches,
    }


def diff_keys(previous: set[str], current: set[str]) -> tuple[set[str], set[str]]:
    """返回 (新增键, 消失键)。首次采集时新增为空。"""
    if not previous:
        return set(), set()
    return current - previous, previous - current


class PortMonitor:
    """供桌面窗口与网页共用的监控状态容器。"""

    def __init__(self, interval: int = 3) -> None:
        self.interval = max(1, int(interval))
        self.ports: list[dict[str, Any]] = []
        self.keys: set[str] = set()
        self.added: set[str] = set()
        self.removed: dict[str, int] = {}
        self.removed_items: dict[str, dict[str, Any]] = {}
        self.updated_at = ""
        self.refresh_count = 0
        self.paused = False

    def refresh(self) -> list[dict[str, Any]]:
        ports = collect_ports()
        current = {port_key(p) for p in ports}
        added, removed = diff_keys(self.keys, current)

        self.added = added
        previous_items = {port_key(p): p for p in self.ports}
        for key in removed:
            self.removed[key] = 3  # 保留 3 次刷新，便于看到端口消失
            if key in previous_items:
                self.removed_items[key] = dict(previous_items[key], change="gone")
        for key in list(self.removed):
            self.removed[key] -= 1
            if self.removed[key] <= 0:
                self.removed.pop(key, None)
                self.removed_items.pop(key, None)

        for port in ports:
            key = port_key(port)
            if key in added:
                port["change"] = "new"
            elif key in self.removed:
                port["change"] = "gone"
            else:
                port["change"] = "same"

        self.ports = ports
        self.keys = current
        self.updated_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.refresh_count += 1
        return ports
