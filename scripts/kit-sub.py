#!/usr/bin/env python3
"""Подписка с учётом приложения — посредник перед подпиской 3X-UI.

https://github.com/itsnotkubrick/3X-UI_KIT

Слушает публичный адрес подписки (HTTPS) и ходит в подписку 3X-UI на 127.0.0.1:
  * Clash / Mihomo (Clash Verge, FlClash, Mihomo Party…) — конфиг 3X-UI плюс AmneziaWG
    из подписки «<id>-awg»: Mihomo умеет AmneziaWG, а остальные приложения нет;
  * остальные приложения и браузер — ответ 3X-UI как есть (ссылки или страница);
  * заголовок Subscription-Userinfo: expire=0 («бессрочно») убирается — иначе
    приложения показывают срок «01.01.1970».

Настройки — /etc/kit-sub/config.json. Сертификат перечитывается сам после продления.
"""

import base64
import http.client
import http.server
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from typing import Optional
import urllib.error
import urllib.request
import urllib.parse

import yaml

CONFIG = os.environ.get("KIT_SUB_CONFIG", "/etc/kit-sub/config.json")
CLASH_UA = re.compile(r"clash|mihomo|flclash|stash|nyanpasu|meta", re.I)
# AmneziaWG добавляем только приложениям на ядре Mihomo. Karing, Hiddify и другие на sing-box
# тоже могут просить формат Clash (Karing так и делает), но AmneziaWG не умеют.
NO_AWG_UA = re.compile(r"karing|hiddify|nekobox|sing-?box|husi|stash|shadowrocket|v2box|streisand|happ|loon|surge|quantumult", re.I)
SUB_ID = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
UPSTREAM_ID = re.compile(r"[A-Za-z0-9_.@-]{1,64}(?:-awg)?")
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_WORKERS = 8
MAX_YAML_NODES = 20000
MAX_YAML_DEPTH = 32
PASS_HEADERS = ("content-type", "content-disposition", "profile-title", "profile-update-interval",
                "profile-web-page-url", "subscription-userinfo", "support-url", "cache-control")

def load_config():
    """Read bounded, root-managed configuration; errors must never disclose it."""
    with open(CONFIG, encoding="utf-8") as f:
        raw = f.read(65537)
    if len(raw) > 65536:
        raise ValueError("configuration too large")
    conf = json.loads(raw)
    if not isinstance(conf, dict):
        raise ValueError("configuration must be an object")
    origin = urllib.parse.urlsplit(conf["upstream"])
    if (origin.scheme != "http" or origin.username is not None or origin.password is not None
            or origin.path not in ("", "/") or origin.query or origin.fragment
            or not ipaddress.ip_address(origin.hostname).is_loopback
            or "%" in origin.hostname or not origin.port):
        raise ValueError("upstream must be a literal loopback HTTP origin")
    path = conf["path"].strip("/")
    if (not path or len(path) > 256 or not re.fullmatch(r"[A-Za-z0-9_.@/-]+", path)
            or any(p in ("", ".", "..") for p in path.split("/"))):
        raise ValueError("invalid subscription path")
    if type(conf["port"]) is not int or not 1 <= conf["port"] <= 65535:
        raise ValueError("invalid listener port")
    cert, key = conf.get("cert"), conf.get("key")
    if bool(cert) != bool(key):
        raise ValueError("certificate and key must be configured together")
    if cert and any(not isinstance(p, str) or not os.path.isabs(p) or any(ord(c) < 32 for c in p)
                    for p in (cert, key)):
        raise ValueError("invalid TLS file paths")
    listen = ipaddress.ip_address(conf.get("listen", "0.0.0.0" if cert else "127.0.0.1"))
    if not cert and not listen.is_loopback:
        raise ValueError("plaintext listener must be loopback")
    host = conf.get("host", origin.netloc)
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9.\[\]:-]{1,255}", host):
        raise ValueError("invalid upstream Host")
    conf["host"] = host
    return conf


try:
    CONF = load_config()
except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
    raise SystemExit("kit-sub: invalid or unreadable configuration") from None
PATH = "/" + CONF["path"].strip("/") + "/"


def log(msg):
    print(msg, flush=True)


def safe_header(value, limit=2048):
    return (isinstance(value, str) and len(value) <= limit
            and all(32 <= ord(c) < 127 or 160 <= ord(c) <= 255 for c in value))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Even a loopback backend may redirect to metadata or another bearer URL.
        return None


UPSTREAM_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def upstream(sub_id, ua, host, accept):
    """GET к подписке 3X-UI. Возвращает (код, заголовки, тело) или (None, {}, b"")."""
    if not UPSTREAM_ID.fullmatch(sub_id) or sub_id in (".", ".."):
        return None, {}, b""
    if not safe_header(ua) or not safe_header(accept):
        return None, {}, b""
    req = urllib.request.Request(CONF["upstream"].rstrip("/") + PATH + sub_id, headers={
        "User-Agent": ua, "Host": CONF["host"], "Accept": accept or "*/*"})
    try:
        try:
            r = UPSTREAM_OPENER.open(req, timeout=15)
        except urllib.error.HTTPError as e:
            r = e
        with r:
            body = r.read(MAX_BODY_BYTES + 1)
            if len(body) <= MAX_BODY_BYTES:
                return r.status, {k.lower(): v for k, v in r.getheaders()}, body
    except (urllib.error.URLError, OSError, socket.timeout, http.client.HTTPException, ValueError):
        # Exception messages may contain the complete bearer subscription URL.
        log("upstream недоступен")
        return None, {}, b""
    log("upstream ответ слишком большой")
    return None, {}, b""


def fix_userinfo(value):
    # «expire=0» значит «бессрочно», но приложения рисуют 01.01.1970 — убираем.
    parts = [p.strip() for p in value.split(";") if p.strip() and p.strip() != "expire=0"]
    return "; ".join(parts)


def strip_links(body):
    """Список ссылок (base64 или текст) без vpn:// и tg:// — их не умеет ни одно VPN-приложение
    со ссылками: vpn:// — конфиг для AmneziaVPN, tg:// — прокси для Telegram."""
    text = body.decode("utf-8", "replace").strip()
    encoded = "://" not in text
    if encoded:
        try:
            compact = "".join(text.split())
            text = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True).decode("utf-8")
        except ValueError:
            return body
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith(("vpn://", "tg://"))]
    out = "\n".join(lines)
    return base64.b64encode(out.encode()).decode().encode() if encoded else out.encode()


class BoundedLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.node_count = 0
        self.node_depth = 0

    def compose_node(self, parent, index):
        self.node_count += 1
        self.node_depth += 1
        try:
            if self.node_count > MAX_YAML_NODES or self.node_depth > MAX_YAML_DEPTH:
                raise ValueError("YAML composition limit")
            return super().compose_node(parent, index)
        finally:
            self.node_depth -= 1


def check_graph(root):
    """Bound logical alias expansion BEFORE SafeLoader flattens YAML merge keys."""
    active = set()
    count = 0

    def visit(value, depth):
        nonlocal count
        count += 1
        if count > MAX_YAML_NODES or depth > MAX_YAML_DEPTH:
            raise ValueError("YAML expansion limit")
        if isinstance(value, (yaml.MappingNode, dict)):
            items = value.value if isinstance(value, yaml.MappingNode) else value.items()
            children = (child for pair in items for child in pair)
        elif isinstance(value, (yaml.SequenceNode, list)):
            children = value.value if isinstance(value, yaml.SequenceNode) else value
        else:
            return
        identity = id(value)
        if identity in active:
            raise ValueError("recursive YAML alias")
        active.add(identity)
        try:
            for child in children:
                visit(child, depth + 1)
        finally:
            active.remove(identity)

    visit(root, 1)


def load_clash(body):
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("subscription too large")
    loader = BoundedLoader(body)
    try:
        node = loader.get_single_node()
        check_graph(node)
        cfg = loader.construct_document(node) if node is not None else None
    finally:
        loader.dispose()
    if not isinstance(cfg, dict):
        raise ValueError("Clash must be a mapping")
    check_graph(cfg)
    proxies = cfg.get("proxies")
    groups = cfg.get("proxy-groups")
    proxies = [] if proxies is None else proxies
    groups = [] if groups is None else groups
    if not isinstance(proxies, list) or not isinstance(groups, list):
        raise ValueError("invalid Clash lists")
    for proxy in proxies:
        if (not isinstance(proxy, dict) or not isinstance(proxy.get("name"), str)
                or not 1 <= len(proxy["name"]) <= 256):
            raise ValueError("invalid proxy name")
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("invalid proxy group")
        members = group.get("proxies", [])
        if not isinstance(members, list) or any(not isinstance(p, str) for p in members):
            raise ValueError("invalid group members")
    cfg["proxies"] = proxies
    return cfg


def dump_clash(cfg):
    check_graph(cfg)
    body = yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False).encode()
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("transformed subscription too large")
    return body


def strip_awg(clash_yaml):
    """Clash-конфиг без AmneziaWG — для приложений, которые его не умеют."""
    cfg = load_clash(clash_yaml)
    awg = {p.get("name") for p in cfg.get("proxies") or [] if isinstance(p, dict) and "amnezia-wg-option" in p}
    if not awg:
        return clash_yaml
    cfg["proxies"] = [p for p in cfg["proxies"] if p.get("name") not in awg]
    for g in cfg.get("proxy-groups") or []:
        if isinstance(g.get("proxies"), list):
            g["proxies"] = [x for x in g["proxies"] if x not in awg]
    return dump_clash(cfg)


def merge_awg(main_yaml, awg_yaml):
    """Добавляет прокси AmneziaWG в Clash-конфиг и во все группы, где перечислены прокси."""
    main = load_clash(main_yaml)
    awg = load_clash(awg_yaml)
    extra = [p for p in (awg.get("proxies") or []) if isinstance(p, dict) and p.get("name")]
    if not extra:
        return main_yaml
    names = {p.get("name") for p in main.get("proxies") or []}
    for p in extra:
        # 3X-UI дописывает к имени запись-«двойника» («AmneziaWG-3.1-sasha-awg») — убираем хвост.
        p["name"] = re.sub(r"-[^-\s]+-awg\d*$", "", p["name"]) or p["name"]
        base, n = p["name"], 2
        while p["name"] in names:
            p["name"] = f"{base} {n}"
            n += 1
        names.add(p["name"])
    main.setdefault("proxies", []).extend(extra)
    added = [p["name"] for p in extra]
    for g in main.get("proxy-groups") or []:
        lst = g.get("proxies")
        if isinstance(lst, list) and any(x in names for x in lst):
            pos = lst.index("DIRECT") if "DIRECT" in lst else len(lst)
            g["proxies"] = lst[:pos] + added + lst[pos:]
    return dump_clash(main)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""
    timeout = 20  # зависшие соединения не держим

    def setup(self):
        # TLS-рукопожатие — в потоке запроса, а не в общем цикле приёма соединений.
        # Без сертификата (за nginx, на 127.0.0.1) работаем по обычному HTTP.
        self.request.settimeout(self.timeout)
        if self.server.ssl_ctx is not None:
            self.request = self.server.ssl_ctx.wrap_socket(self.request, server_side=True)
        super().setup()

    def handle(self):
        try:
            super().handle()
        except (ssl.SSLError, ConnectionError, socket.timeout, OSError):
            pass

    def log_message(self, fmt, *args):  # без IP клиентов в логах
        pass

    def finish(self):
        try:
            super().finish()
        finally:
            # socketserver still owns the detached pre-TLS socket, not this wrapper.
            self.request.close()

    def send_plain(self, code, text=""):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if not path.startswith(PATH):
            return self.send_plain(404, "404 page not found")
        sub_id = path[len(PATH):]
        if not SUB_ID.fullmatch(sub_id) or sub_id in (".", ".."):
            return self.send_plain(404, "404 page not found")
        ua = self.headers.get("User-Agent", "")
        host = CONF["host"]
        accept = self.headers.get("Accept", "")
        if (not safe_header(ua) or not safe_header(accept)
                or any(len(self.headers.get_all(k, [])) > 1 for k in ("User-Agent", "Accept"))):
            return self.send_plain(400, "invalid request headers")
        code, headers, body = upstream(sub_id, ua, host, accept)
        if code is None:
            return self.send_plain(502, "subscription backend is unavailable")
        if any(not safe_header(headers[k], 8192) for k in PASS_HEADERS if k in headers):
            return self.send_plain(502, "invalid subscription backend response")

        clash = bool(CLASH_UA.search(ua)) and "yaml" in headers.get("content-type", "")
        awg = clash and not NO_AWG_UA.search(ua)
        # Never log attacker-controlled headers, bearer paths or upstream content.
        log("subscription: " + ("clash+awg" if awg else "clash" if clash else "passthrough"))
        try:
            if code == 200 and clash:
                load_clash(body)  # Validate even when the optional legacy AWG subscription is missing.
            if code == 200 and clash and not awg:
                body = strip_awg(body)
            elif code == 200 and awg and not sub_id.endswith(("-awg", "-tg")):
                # Установки до kit 1.1 держали AmneziaWG в подписке «<id>-awg» — подмешиваем её.
                acode, _, abody = upstream(sub_id + "-awg", ua, host, accept)
                if acode == 200 and abody:
                    body = merge_awg(body, abody)
            elif code == 200 and "text/plain" in headers.get("content-type", ""):
                body = strip_links(body)
        except (yaml.YAMLError, UnicodeError, ValueError, TypeError, RecursionError):
            log("не удалось обработать подписку")
            return self.send_plain(502, "invalid subscription backend response")

        self.send_response(code)
        for k in PASS_HEADERS:
            if k in headers and k != "cache-control":
                v = fix_userinfo(headers[k]) if k == "subscription-userinfo" else headers[k]
                if v:
                    self.send_header(k.title(), v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    ssl_ctx: Optional[ssl.SSLContext] = None

    def __init__(self, *args, **kwargs):
        self.workers = threading.BoundedSemaphore(MAX_WORKERS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            # Before TLS handshake: do not write plaintext to a TLS client.
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.workers.release()
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.workers.release()

    def handle_error(self, request, client_address):  # обрывы TLS от сканеров — не ошибка
        pass
    address_family = socket.AF_INET6 if ":" in CONF.get("listen", "") else socket.AF_INET


def tls_stamp(cert, key):
    # Atomic replacement may keep mtime; detect both files, inode and nanoseconds.
    return tuple((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
                 for s in (os.stat(cert), os.stat(key)))


def tls_context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def reload_tls(srv, cert, key, stamp):
    try:
        new_stamp = tls_stamp(cert, key)
        if new_stamp != stamp:
            ctx = tls_context(cert, key)
            if tls_stamp(cert, key) != new_stamp:
                raise OSError("certificate pair changed during loading")
            # Existing requests retain their context; only new handshakes use it.
            srv.ssl_ctx = ctx
            log("сертификат обновлён")
            return new_stamp
    except (OSError, ssl.SSLError):
        log("не удалось перечитать сертификат")
    return stamp


def run_server():
    cert, key = CONF.get("cert"), CONF.get("key")
    srv = Server((CONF.get("listen", "0.0.0.0" if cert else "127.0.0.1"), CONF["port"]), Handler)
    try:
        if cert:
            stamp = tls_stamp(cert, key)
            srv.ssl_ctx = tls_context(cert, key)
            if tls_stamp(cert, key) != stamp:
                raise OSError("certificate pair changed during startup")

            def reload_cert():
                nonlocal stamp
                while True:
                    time.sleep(600)
                    stamp = reload_tls(srv, cert, key, stamp)

            threading.Thread(target=reload_cert, daemon=True).start()
        log("kit-sub: TLS listener ready" if cert else "kit-sub: HTTP listener ready (TLS terminates at nginx)")
        srv.serve_forever()
    finally:
        srv.server_close()


def main():
    if getattr(os, "geteuid", lambda: None)() == 0:
        log("kit-sub: refusing root identity")
        return 1
    try:
        run_server()
        return 0
    except Exception:
        # No startup traceback: config values or TLS file paths can be sensitive.
        log("kit-sub: startup failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
