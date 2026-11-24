"""入口：系统托盘常驻 + 本地网页 + 独立监控窗口。"""

from __future__ import annotations

import argparse
import subprocess
import threading
import time
import webbrowser
from pathlib import Path

if __package__ in (None, ""):
    from port_monitor.core import PortMonitor
    from port_monitor.web import start_web, CertError
    from port_monitor.desktop import open_app_window
    from port_monitor import config
    from port_monitor.tray import TrayController
else:
    from .core import PortMonitor
    from .web import start_web, CertError
    from .desktop import open_app_window
    from . import config
    from .tray import TrayController


def _refresher(monitor: PortMonitor, stop: threading.Event) -> None:
    last = 0.0
    while not stop.wait(0.2):
        if monitor.paused:
            continue
        if time.time() - last >= monitor.interval:
            monitor.refresh()
            last = time.time()


def main() -> None:
    parser = argparse.ArgumentParser(description="本机端口占用检测工具")
    parser.add_argument("--mode", choices=["tray", "web"], default="tray",
                        help="tray=托盘常驻（默认）, web=仅网页服务")
    parser.add_argument("--host", default=None,
                        help="网页监听地址，默认读配置(0.0.0.0=允许局域网, 127.0.0.1=仅本机)")
    parser.add_argument("--port", type=int, default=0, help="网页端口，默认读配置(8765)")
    parser.add_argument("--no-window", action="store_true", help="启动时不自动打开监控窗口")
    args = parser.parse_args()

    cfg = config.load_config()
    port = args.port or int(cfg.get("port", 8765) or 8765)
    bind_host = args.host or cfg.get("host", "0.0.0.0") or "0.0.0.0"
    https = bool(cfg.get("https", False))
    # 首次生成密码后 load_config 会写好"初始登录信息.txt"，这里在托盘提示一次
    initial_note = config.CONFIG_DIR / "初始登录信息.txt"
    try:
        fresh_password = initial_note.exists() and "密　码：" in initial_note.read_text(encoding="utf-8")
    except OSError:
        fresh_password = False
    monitor = PortMonitor(int(cfg.get("interval", 3) or 3))
    monitor.refresh()

    stop = threading.Event()
    threading.Thread(target=_refresher, args=(monitor, stop), daemon=True).start()

    # 本机窗口/浏览器始终走 127.0.0.1，绑定地址可与访问地址不同
    scheme = "https" if https else "http"
    url = f"{scheme}://127.0.0.1:{port}/"
    try:
        server = start_web(monitor, bind_host, port, open_browser=False, blocking=False, https=https)
    except CertError as exc:
        # 证书路径填错会在启动时失败；windowed 模式没有控制台，用系统弹窗告知
        print(f"[错误] HTTPS 证书配置错误: {exc}")
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0, f"HTTPS 证书配置错误，程序未能启动：\n\n{exc}\n\n请在设置中修正证书路径或改回内置证书。",
                "端口监控", 0x10)
        except Exception:
            pass
        return
    except OSError as exc:
        # 端口被占用通常意味着已有实例在托盘运行：直接打开它的界面，
        # 避免 windowed 模式下静默退出让用户误以为"双击没反应/程序没起来"。
        print(f"[提示] 已有实例在运行（端口 {port} 被占用），正在打开其界面: {exc}")
        try:
            open_app_window(url)
        except Exception:
            webbrowser.open(url)
        return

    def open_window() -> None:
        try:
            open_app_window(url)
        except Exception as exc:
            print(f"[提示] 打开窗口失败: {exc}")
            webbrowser.open(url)

    def open_settings() -> None:
        webbrowser.open(url + "#settings")

    def quit_app() -> None:
        stop.set()
        tray.stop()

    tray = TrayController(open_window, open_settings, quit_app)

    if bind_host in ("0.0.0.0", "::"):
        lan_hint = f"；局域网 https://设备IP:{port}" if https else f"；局域网 http://设备IP:{port}"
        print(f"[提示] 服务运行中：本机 {url}{lan_hint}")
    else:
        print(f"[提示] 服务运行中：{url}")

    if args.mode == "web":
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        if not args.no_window and cfg.get("open_window_on_start", True):
            open_window()
        if fresh_password:
            tray.notify("已生成初始密码，见程序目录「初始登录信息.txt」", "端口监控 · 首次启动")
        elif https:
            tray.notify("HTTPS 已启用，浏览器提示证书时请选择继续", "端口监控")
        else:
            tray.notify("已在托盘运行，右键可设置或退出", "端口监控已启动")
        # 托盘主循环阻塞；关闭窗口只关窗口，不影响此处
        tray.run()

    server.shutdown()
    server.server_close()


if __name__ == "__main__":
    main()
