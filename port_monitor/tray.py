"""系统托盘：双击打开界面、右键菜单（打开 / 自启 / 设置 / 退出）。

托盘常驻在主进程，监控窗口是独立的应用窗口；
关闭窗口只结束窗口进程，主进程与托盘继续在后台运行。
"""

from __future__ import annotations

import threading
from typing import Callable

from PIL import Image, ImageDraw
import pystray

from . import config


def _make_icon_image() -> Image.Image:
    """生成一个简洁的端口监控托盘图标（蓝色圆底 + 白色端口点阵）。"""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((2, 2, size - 2, size - 2), fill="#2563eb")
    # 3x3 点阵，中间一格高亮为橙色，象征"某个端口被占用"
    for r in range(3):
        for c in range(3):
            x, y = 15 + c * 17, 15 + r * 17
            color = "#f59e0b" if (r, c) == (1, 1) else "#ffffff"
            d.ellipse((x, y, x + 10, y + 10), fill=color)
    return img


class TrayController:
    """由外部注入具体行为，便于主程序统一控制生命周期。"""

    def __init__(
        self,
        open_window: Callable[[], None],
        open_settings: Callable[[], None],
        quit_app: Callable[[], None],
    ) -> None:
        self.open_window = open_window
        self.open_settings = open_settings
        self.quit_app = quit_app

    def toggle_autostart(self, _icon=None, _item=None) -> None:
        target = not config.is_autostart()
        config.set_autostart(target)
        cfg = config.load_config()
        cfg["autostart"] = target
        config.save_config(cfg)
        if self._icon:
            self._icon.update_menu()
            self._icon.notify(
                f"开机自启已{'开启' if target else '关闭'}", "端口监控"
            )

    def set_interval(self, seconds: int) -> None:
        cfg = config.load_config()
        cfg["interval"] = seconds
        config.save_config(cfg)

    _icon: "pystray.Icon | None" = None

    def build_menu(self) -> "pystray.Menu":
        return pystray.Menu(
            pystray.MenuItem("打开监控界面", lambda *_: self.open_window(), default=True),
            pystray.MenuItem("设置...", lambda *_: self.open_settings()),
            pystray.MenuItem(
                "开机自启动",
                self.toggle_autostart,
                checked=lambda _item: config.is_autostart(),
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", lambda *_: self.quit_app()),
        )

    def run(self) -> None:
        icon = pystray.Icon("PortMonitor", _make_icon_image(), "本机端口监控", self.build_menu())
        self._icon = icon
        icon.run()

    def notify(self, message: str, title: str = "端口监控") -> None:
        if self._icon:
            try:
                self._icon.notify(message, title)
            except Exception:
                pass

    def stop(self) -> None:
        if self._icon:
            threading.Thread(target=self._icon.stop, daemon=True).start()
