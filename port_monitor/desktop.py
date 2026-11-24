"""桌面窗口：用系统浏览器应用模式（无地址栏）打开监控页。

窗口是独立进程，关闭窗口只结束窗口本身，
主进程与系统托盘继续在后台常驻。
"""

from __future__ import annotations

import subprocess
import webbrowser
from pathlib import Path

_BROWSERS = [
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
]


def open_app_window(url: str) -> bool:
    """打开（或复用）一个应用窗口，立即返回，不阻塞主程序。"""
    for exe in _BROWSERS:
        if exe.exists():
            try:
                subprocess.Popen(
                    [str(exe), f"--app={url}", "--window-size=1360,840"]
                )
                return True
            except OSError:
                continue
    webbrowser.open(url)
    return False


def start_gui(url: str, title: str = "本机端口监控") -> bool:
    """兼容旧入口。"""
    return open_app_window(url)
