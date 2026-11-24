"""本地网页服务：登录鉴权、JSON 接口、监控页面、可选 HTTPS。"""

from __future__ import annotations

import json
import secrets
import ssl
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import sys
from .core import PortMonitor, query_port
from . import config

_BASE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
PAGE_PATH = _BASE / "port_monitor" / "web_page.html"
if not PAGE_PATH.exists():
    PAGE_PATH = Path(__file__).with_name("web_page.html")
CERT_PATH = _BASE / "port_monitor" / "server.crt"
KEY_PATH = _BASE / "port_monitor" / "server.key"
if not CERT_PATH.exists():
    CERT_PATH = Path(__file__).with_name("server.crt")
    KEY_PATH = Path(__file__).with_name("server.key")

COOKIE_NAME = "pm_session"
SESSION_TTL = 12 * 60 * 60  # 12 小时
LOCAL_IPS = {"127.0.0.1", "::1", "localhost"}


class CertError(Exception):
    """HTTPS 证书配置或加载失败。"""


def _build_ssl_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def _validate_cert_pair(cert_raw: str, key_raw: str) -> str | None:
    """校验自定义证书/私钥对；返回错误信息或 None（None 表示可用或留空用内置）。"""
    cert, key = config.resolve_cert_paths({"cert_path": cert_raw, "key_path": key_raw})
    if not cert and not key:
        return None  # 留空 → 用内置证书
    if not cert or not key:
        return "证书文件和私钥文件必须同时填写，或同时留空使用内置证书"
    if not cert.is_file():
        return f"证书文件不存在：{cert}"
    if not key.is_file():
        return f"私钥文件不存在：{key}"
    try:
        _build_ssl_context(cert, key)
    except (OSError, ssl.SSLError) as exc:
        return f"证书或私钥加载失败，请确认两者匹配且格式正确：{exc}"
    return None

# token -> 过期时间戳
_sessions: dict[str, float] = {}
_sessions_lock = threading.Lock()
# ip -> [失败次数, 锁定截止时间]
_failed: dict[str, list[float]] = {}
_failed_lock = threading.Lock()


def _new_session() -> str:
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = time.time() + SESSION_TTL
    return token


def _valid_session(token: str | None) -> bool:
    if not token:
        return False
    with _sessions_lock:
        expiry = _sessions.get(token)
        if not expiry:
            return False
        if expiry < time.time():
            _sessions.pop(token, None)
            return False
        return True


def _drop_session(token: str | None) -> None:
    if token:
        with _sessions_lock:
            _sessions.pop(token, None)


def _cleanup_sessions() -> None:
    now = time.time()
    with _sessions_lock:
        for k in [k for k, v in _sessions.items() if v < now]:
            _sessions.pop(k, None)


def _is_locked(ip: str) -> bool:
    with _failed_lock:
        rec = _failed.get(ip)
        return bool(rec and rec[1] > time.time())


def _record_failure(ip: str) -> int:
    with _failed_lock:
        rec = _failed.setdefault(ip, [0, 0.0])
        rec[0] += 1
        if rec[0] >= 5:
            rec[1] = time.time() + 60  # 连错 5 次锁 60 秒
            rec[0] = 0
        return rec[0]


def _clear_failure(ip: str) -> None:
    with _failed_lock:
        _failed.pop(ip, None)


def _client_ip(handler: "PortHandler") -> str:
    try:
        return handler.client_address[0]
    except Exception:
        return ""


def _cookies(handler: "PortHandler") -> dict[str, str]:
    raw = handler.headers.get("Cookie", "")
    out: dict[str, str] = {}
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out


def _login_page() -> bytes:
    html = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 · 端口监控</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6fa;color:#1f2937;
font-family:system-ui,-apple-system,"Microsoft YaHei",sans-serif}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:34px 36px;width:min(380px,92vw);
box-shadow:0 18px 50px rgba(16,24,40,.10)}
h1{margin:0 0 6px;font-size:21px}p.sub{margin:0 0 24px;color:#6b7280;font-size:13px}
label{display:block;font-size:12px;color:#6b7280;margin:14px 0 6px}
input{width:100%;padding:11px 13px;border:1px solid #d1d5db;border-radius:9px;font-size:14px;outline:none}
input:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.12)}
button{width:100%;margin-top:22px;padding:11px;border:0;border-radius:9px;background:#2563eb;color:#fff;
font-size:14px;font-weight:600;cursor:pointer}button:hover{background:#1d4ed8}
.msg{margin-top:14px;font-size:12px;color:#b91c1c;min-height:16px}
.tip{margin-top:18px;font-size:11px;color:#9ca3af;line-height:1.6;border-top:1px solid #eef0f3;padding-top:12px}
</style></head><body><div class="card">
<h1>🔒 端口监控</h1><p class="sub">远程访问需要登录验证</p>
<form id="f"><label>用户名</label><input id="u" autocomplete="username" value="admin">
<label>密码</label><input id="p" type="password" autocomplete="current-password" placeholder="请输入访问密码">
<button type="submit">登录</button></form><div class="msg" id="m"></div>
<div class="tip">本机 127.0.0.1 访问无需登录。连续输错 5 次将锁定 60 秒。</div></div>
<script>
const $=id=>document.getElementById(id);
$('f').onsubmit=async e=>{e.preventDefault();$('m').textContent='正在验证…';
 try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({username:$('u').value.trim(),password:$('p').value})});
  const d=await r.json();
  if(d.ok){location.href='/';}else{$('m').textContent=d.error||'登录失败';$('p').value='';}
 }catch(err){$('m').textContent='网络错误：'+err.message;}};
</script></body></html>"""
    return html.encode("utf-8")


class PortHandler(BaseHTTPRequestHandler):
    monitor: PortMonitor = None  # type: ignore[assignment]
    https_enabled: bool = False
    cert_active: str = ""  # 当前进程实际加载的证书路径（用于判断是否需重启）

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # 静默，避免控制台刷屏

    def _send(self, body: bytes, content_type: str, status: int = 200,
              extra_headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: object, status: int = 200,
                   extra_headers: list[tuple[str, str]] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(body, "application/json; charset=utf-8", status, extra_headers)

    def _set_cookie_header(self, token: str, clear: bool = False) -> str:
        if clear:
            return f"{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        secure = "; Secure" if self.https_enabled else ""
        return f"{COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax{secure}"

    # ---------- 鉴权 ----------
    def _is_local(self) -> bool:
        return _client_ip(self) in LOCAL_IPS

    def _auth_required(self) -> bool:
        if self._is_local():
            return False
        try:
            return bool(config.load_config().get("require_login", True))
        except Exception:
            return True

    def _authenticated(self) -> bool:
        if not self._auth_required():
            return True
        return _valid_session(_cookies(self).get(COOKIE_NAME))

    def _deny(self) -> None:
        if self.path.split("?")[0].rstrip("/") in ("/api/login", "/api/session"):
            self._send_json({"ok": False, "error": "需要登录"}, 401)
            return
        self._send_json({"error": "未授权访问", "need_login": True}, 401)

    # ---------- GET ----------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # 健康检查与登录接口不需要鉴权
        if path == "/api/health":
            self._send_json({"ok": True})
            return
        if path == "/api/session":
            need = self._auth_required() and not _valid_session(_cookies(self).get(COOKIE_NAME))
            self._send_json({
                "authenticated": self._authenticated(),
                "need_login": need,
                "local": self._is_local(),
                "https": self.https_enabled,
            })
            return
        if not self._authenticated():
            if path.startswith("/api/"):
                self._send_json({"error": "未授权访问", "need_login": True}, 401)
            else:
                self._send(_login_page(), "text/html; charset=utf-8")
            return

        if path in ("/", "/index.html"):
            try:
                body = PAGE_PATH.read_bytes()
            except OSError as exc:
                self._send_json({"error": f"页面读取失败: {exc}"}, 500)
                return
            self._send(body, "text/html; charset=utf-8")
            return

        if path == "/api/ports":
            mon = self.monitor
            payload = {
                "ports": mon.ports,
                "removed_ports": list(mon.removed_items.values()),
                "total": len(mon.ports),
                "tcp": sum(1 for p in mon.ports if p["protocol"] == "TCP"),
                "udp": sum(1 for p in mon.ports if p["protocol"] == "UDP"),
                "added": len(mon.added),
                "removed": len(mon.removed),
                "updated_at": mon.updated_at,
                "interval": mon.interval,
            }
            self._send_json(payload)
            return

        if path == "/api/query":
            params = parse_qs(parsed.query)
            raw = (params.get("port") or [""])[0].strip()
            protocol = (params.get("protocol") or [""])[0].strip()
            try:
                port = int(raw)
            except ValueError:
                self._send_json({"in_use": False, "error": "请输入有效端口号"}, 400)
                return
            self._send_json(query_port(port, protocol or None))
            return

        if path == "/api/settings":
            cfg = config.load_config()
            self._send_json({
                "interval": cfg.get("interval", 3),
                "autostart": config.is_autostart(),
                "open_window_on_start": cfg.get("open_window_on_start", True),
                "port": cfg.get("port", 8765),
                "host": cfg.get("host", "0.0.0.0"),
                "lan_access": cfg.get("host", "0.0.0.0") not in ("127.0.0.1", "localhost", "::1"),
                "https": bool(cfg.get("https", False)),
                "cert_path": cfg.get("cert_path", ""),
                "key_path": cfg.get("key_path", ""),
                "cert_active": PortHandler.cert_active,
                "require_login": bool(cfg.get("require_login", True)),
                "username": cfg.get("username", "admin"),
            })
            return

        self._send_json({"error": "Not Found"}, 404)

    # ---------- POST ----------
    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path not in ("/api/settings", "/api/login", "/api/logout"):
            self._send_json({"error": "Not Found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"ok": False, "error": "请求格式错误"}, 400)
            return

        if path == "/api/login":
            self._handle_login(data)
            return
        if path == "/api/logout":
            _drop_session(_cookies(self).get(COOKIE_NAME))
            self._send_json({"ok": True}, extra_headers=[("Set-Cookie", self._set_cookie_header("", clear=True))])
            return

        # 以下为 /api/settings，需要鉴权
        if not self._authenticated():
            self._send_json({"error": "未授权访问", "need_login": True}, 401)
            return
        self._handle_settings(data)

    def _handle_login(self, data: dict) -> None:
        ip = _client_ip(self)
        if _is_locked(ip):
            self._send_json({"ok": False, "error": "尝试次数过多，请 60 秒后再试"}, 429)
            return
        cfg = config.load_config()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        ok = (
            secrets.compare_digest(username, str(cfg.get("username", "admin")))
            and config.verify_password(password, str(cfg.get("password_salt", "")),
                                       str(cfg.get("password_hash", "")))
        )
        if not ok:
            n = _record_failure(ip)
            msg = "账号或密码错误"
            if n >= 3:
                msg += f"（还可尝试 {5 - n} 次）"
            self._send_json({"ok": False, "error": msg}, 401)
            return
        _clear_failure(ip)
        token = _new_session()
        self._send_json({"ok": True, "username": username},
                        extra_headers=[("Set-Cookie", self._set_cookie_header(token))])

    def _handle_settings(self, data: dict) -> None:
        result = {"ok": True, "restart_required": False}
        if "interval" in data:
            try:
                sec = max(1, min(600, int(data["interval"])))
                self.monitor.interval = sec
                cfg = config.load_config()
                cfg["interval"] = sec
                config.save_config(cfg)
                result["interval"] = sec
            except (TypeError, ValueError):
                self._send_json({"ok": False, "error": "刷新间隔须为整数秒"}, 400)
                return
        if "autostart" in data:
            try:
                enabled = bool(data["autostart"])
                config.set_autostart(enabled)
                cfg = config.load_config()
                cfg["autostart"] = enabled
                config.save_config(cfg)
                result["autostart"] = enabled
            except Exception as exc:
                self._send_json({"ok": False, "error": f"设置自启失败: {exc}"}, 500)
                return
        if "open_window_on_start" in data:
            cfg = config.load_config()
            cfg["open_window_on_start"] = bool(data["open_window_on_start"])
            config.save_config(cfg)
        if "port" in data:
            try:
                new_port = int(data["port"])
            except (TypeError, ValueError):
                self._send_json({"ok": False, "error": "服务端口须为 1-65535 的整数"}, 400)
                return
            if new_port < 1 or new_port > 65535:
                self._send_json({"ok": False, "error": "服务端口须在 1-65535 之间"}, 400)
                return
            cfg = config.load_config()
            cfg["port"] = new_port
            config.save_config(cfg)
            result["port"] = new_port
            result["restart_required"] = True
        if "lan_access" in data:
            host = "0.0.0.0" if bool(data["lan_access"]) else "127.0.0.1"
            cfg = config.load_config()
            cfg["host"] = host
            config.save_config(cfg)
            result["lan_access"] = bool(data["lan_access"])
            result["restart_required"] = True
        if "https" in data:
            cfg = config.load_config()
            cfg["https"] = bool(data["https"])
            config.save_config(cfg)
            result["https"] = bool(data["https"])
            result["restart_required"] = True
        if "cert_path" in data or "key_path" in data:
            cfg = config.load_config()
            cert_raw = str(data.get("cert_path", cfg.get("cert_path", "")) or "").strip()
            key_raw = str(data.get("key_path", cfg.get("key_path", "")) or "").strip()
            err = _validate_cert_pair(cert_raw, key_raw)
            if err:
                self._send_json({"ok": False, "error": err}, 400)
                return
            if cert_raw != str(cfg.get("cert_path", "")) or key_raw != str(cfg.get("key_path", "")):
                cfg["cert_path"] = cert_raw
                cfg["key_path"] = key_raw
                config.save_config(cfg)
                result["cert_path"] = cert_raw
                result["key_path"] = key_raw
                result["cert_changed"] = True
                result["restart_required"] = True
        if "require_login" in data:
            cfg = config.load_config()
            cfg["require_login"] = bool(data["require_login"])
            config.save_config(cfg)
            result["require_login"] = bool(data["require_login"])
        if "username" in data:
            name = str(data["username"]).strip()
            if not name or len(name) > 32:
                self._send_json({"ok": False, "error": "用户名须为 1-32 个字符"}, 400)
                return
            cfg = config.load_config()
            cfg["username"] = name
            config.save_config(cfg)
            result["username"] = name
        if "password" in data:
            new_pwd = str(data["password"])
            if len(new_pwd) < 6:
                self._send_json({"ok": False, "error": "密码至少 6 位"}, 400)
                return
            # 修改密码需要提供当前密码（本机首次设置可用 config 里初始密码）
            cfg = config.load_config()
            old = str(data.get("old_password", ""))
            if not config.verify_password(old, str(cfg.get("password_salt", "")),
                                          str(cfg.get("password_hash", ""))):
                self._send_json({"ok": False, "error": "当前密码不正确"}, 403)
                return
            digest, salt = config.hash_password(new_pwd)
            cfg["password_hash"] = digest
            cfg["password_salt"] = salt
            config.save_config(cfg)
            result["password_changed"] = True
            # 改密码后失效所有会话
            with _sessions_lock:
                _sessions.clear()
            # 清理可能存在的初始密码提示文件
            try:
                note = config.CONFIG_DIR / "初始登录信息.txt"
                if note.exists():
                    note.write_text("密码已在设置中修改。\n", encoding="utf-8")
            except OSError:
                pass
        if result["restart_required"]:
            final = config.load_config()
            result["port"] = final.get("port", 8765)
            result["lan_access"] = final.get("host", "0.0.0.0") not in ("127.0.0.1", "localhost", "::1")
            result["https"] = bool(final.get("https", False))
        self._send_json(result)


def create_server(monitor: PortMonitor, host: str, port: int,
                  https: bool = False) -> ThreadingHTTPServer:
    PortHandler.monitor = monitor
    server = ThreadingHTTPServer((host, port), PortHandler)
    server.daemon_threads = True
    PortHandler.https_enabled = bool(https)
    if https:
        cert, key = config.resolve_cert_paths()
        if cert and key:
            cert_file, key_file = cert, key
        else:
            cert_file, key_file = CERT_PATH, KEY_PATH
        if not cert_file.is_file() or not key_file.is_file():
            raise CertError(f"HTTPS 证书文件不存在：{cert_file} / {key_file}")
        try:
            ctx = _build_ssl_context(cert_file, key_file)
        except (OSError, ssl.SSLError) as exc:
            raise CertError(f"HTTPS 证书加载失败：{exc}") from exc
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        # 记录实际加载的证书路径；用内置证书时记为空串
        PortHandler.cert_active = str(cert) if (cert and key) else ""
    else:
        PortHandler.cert_active = ""
    return server


def start_web(
    monitor: PortMonitor,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
    blocking: bool = True,
    https: bool = False,
) -> ThreadingHTTPServer:
    """启动网页服务。blocking=False 时在后台线程运行，供双模式调用。"""
    server = create_server(monitor, host, port, https=https)
    scheme = "https" if https else "http"
    url = f"{scheme}://127.0.0.1:{port}/"
    print(f"[网页] 监控页面: {url}")

    if not monitor.updated_at:
        monitor.refresh()

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    if blocking:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    else:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
