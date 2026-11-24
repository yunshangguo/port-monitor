"""配置持久化与 Windows 开机自启动（注册表 Run 项）。"""

from __future__ import annotations

import json
import os
import sys
import hashlib
import secrets
from pathlib import Path

APP_NAME = "PortMonitor"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def app_dir() -> Path:
    """程序所在目录：打包后为 exe 所在文件夹，源码运行为项目根目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


_PRIMARY_DIR = app_dir()
_LEGACY_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME


def _writable_dir() -> Path:
    """优先把配置放在程序所在文件夹；不可写（如只读目录）时回退到 APPDATA。"""
    try:
        _PRIMARY_DIR.mkdir(parents=True, exist_ok=True)
        probe = _PRIMARY_DIR / ".write_probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        return _PRIMARY_DIR
    except OSError:
        return _LEGACY_DIR


CONFIG_DIR = _writable_dir()
CONFIG_PATH = CONFIG_DIR / "config.json"
LEGACY_CONFIG = _LEGACY_DIR / "config.json"

DEFAULTS = {
    "interval": 3,
    "autostart": False,
    "open_window_on_start": True,
    "port": 8765,
    "host": "0.0.0.0",  # 0.0.0.0=允许局域网访问，127.0.0.1=仅本机
    "https": False,             # 是否启用 HTTPS（需重启生效）
    "cert_path": "",            # 自定义证书 .crt/.pem 路径，空=用内置自签证书（需重启生效）
    "key_path": "",             # 自定义私钥 .key 路径，空=用内置自签证书（需重启生效）
    "require_login": True,      # 远程访问是否强制登录（本机 127.0.0.1 始终免登录）
    "username": "admin",
    "password_salt": "",
    "password_hash": "",
}

_PBKDF2_ROUNDS = 200_000


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """返回 (hex_hash, hex_salt)；salt 为空时随机生成。"""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ROUNDS
    )
    return digest.hex(), salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    if not salt or not expected_hash:
        return False
    actual, _ = hash_password(password, salt)
    return secrets.compare_digest(actual, expected_hash)


def ensure_credentials(cfg: dict) -> tuple[dict, str | None]:
    """确保有可用账号密码；首次生成随机密码并返回明文供展示。"""
    if cfg.get("password_hash") and cfg.get("password_salt"):
        return cfg, None
    password = secrets.token_urlsafe(9)
    digest, salt = hash_password(password)
    cfg["password_hash"] = digest
    cfg["password_salt"] = salt
    return cfg, password


def _migrate_legacy() -> None:
    """首次运行时，把旧版存在 APPDATA 的配置搬到程序目录，避免用户设置丢失。"""
    if CONFIG_PATH.exists() or not LEGACY_CONFIG.exists() or CONFIG_PATH == LEGACY_CONFIG:
        return
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(LEGACY_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    except OSError:
        pass


def load_config() -> dict:
    _migrate_legacy()
    cfg = dict(DEFAULTS)
    try:
        if CONFIG_PATH.exists():
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    # 自启状态以注册表为准
    try:
        cfg["autostart"] = is_autostart()
    except Exception:
        pass
    # 首次运行生成随机管理员密码并落盘，同时留一份明文提示供首次登录
    if not (cfg.get("password_hash") and cfg.get("password_salt")):
        cfg, generated = ensure_credentials(cfg)
        save_config(cfg)
        if generated:
            try:
                note = CONFIG_DIR / "初始登录信息.txt"
                note.write_text(
                    "端口监控 · 初始登录信息\n"
                    "========================\n"
                    f"用户名：{cfg.get('username', 'admin')}\n"
                    f"密　码：{generated}\n\n"
                    "本机 127.0.0.1 访问无需登录；局域网其他设备访问需输入以上账号密码。\n"
                    "请在「设置 → 修改密码」中改为自己的密码，之后本文件会自动失效。\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
    return cfg


def save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {k: cfg.get(k, v) for k, v in DEFAULTS.items()}
    CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def resolve_cert_paths(cfg: dict | None = None) -> tuple[Path | None, Path | None]:
    """解析 HTTPS 证书/私钥路径。

    返回 (证书路径, 私钥路径)；两者皆空表示使用内置自签证书（返回 None, None）。
    相对路径按程序所在目录（exe 目录）解析，支持 %VAR% 环境变量和首尾引号。
    """
    cfg = cfg if cfg is not None else load_config()
    cert_raw = str(cfg.get("cert_path") or "").strip().strip('"').strip("'")
    key_raw = str(cfg.get("key_path") or "").strip().strip('"').strip("'")

    def expand(raw: str) -> Path:
        raw = os.path.expandvars(raw)
        p = Path(raw).expanduser()
        return p if p.is_absolute() else (app_dir() / p)

    cert = expand(cert_raw) if cert_raw else None
    key = expand(key_raw) if key_raw else None
    return cert, key


def app_command() -> str:
    """写入注册表的启动命令。打包后为 exe 自身，源码运行时为 python + 脚本。"""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    script = Path(__file__).resolve().parent.parent / "main.py"
    return f'"{sys.executable}" "{script}" --mode both'


def is_autostart() -> bool:
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_QUERY_VALUE) as key:
        try:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
            return bool(value)
        except FileNotFoundError:
            return False


def set_autostart(enabled: bool) -> bool:
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, app_command())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
    return True
