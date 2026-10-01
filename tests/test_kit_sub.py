"""Isolated kit-sub security regressions; never contact external hosts."""
import contextlib
import importlib.util
import io
import http.client
import threading
import json
import ipaddress
import os
import shutil
import socket
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "kit-sub.py"
CONFIG = {"path": "/subscription/", "upstream": "http://127.0.0.1:2097",
          "listen": "127.0.0.1", "port": 2096, "host": "vpn.example.test"}


def setUpModule():
    global NETWORK_GUARD
    connect = socket.create_connection

    def loopback_only(address, *args, **kwargs):
        if not ipaddress.ip_address(address[0]).is_loopback:
            raise AssertionError("external network access is forbidden in kit-sub tests")
        return connect(address, *args, **kwargs)

    NETWORK_GUARD = mock.patch.object(socket, "create_connection", side_effect=loopback_only)
    NETWORK_GUARD.start()


def tearDownModule():
    NETWORK_GUARD.stop()


def load_module(config=None):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(config or CONFIG), encoding="utf-8")
        with mock.patch.dict(os.environ, {"KIT_SUB_CONFIG": str(path)}):
            spec = importlib.util.spec_from_file_location("kit_sub_test", SCRIPT)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module


@contextlib.contextmanager
def serving(module):
    server = module.Server(("127.0.0.1", 0), module.Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(server, path="/subscription/test-bearer", headers=None, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        conn.request(method, path, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


class IdentityTests(unittest.TestCase):
    def test_root_execution_is_refused_before_opening_a_listener(self):
        module = load_module()
        with mock.patch.object(module.os, "geteuid", return_value=0, create=True), \
             mock.patch.object(module, "Server") as server, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(), 1)
        server.assert_not_called()


class ConfigTests(unittest.TestCase):
    def test_upstream_is_a_fixed_loopback_origin(self):
        for origin in ("http://169.254.169.254:80", "http://example.test:80", "http://localhost:2097",
                       "https://127.0.0.1:2097", "http://user:password@127.0.0.1:2097",
                       "http://127.0.0.1:2097/private", "http://127.0.0.1:2097?token=synthetic",
                       "http://127.0.0.1:2097#fragment"):
            with self.subTest(origin=origin):
                with self.assertRaises(SystemExit) as raised:
                    load_module(dict(CONFIG, upstream=origin))
                self.assertNotIn(origin, str(raised.exception))
        self.assertEqual(load_module(dict(CONFIG, upstream="http://[::1]:2097")).CONF["upstream"],
                         "http://[::1]:2097")

    def test_plain_http_cannot_listen_on_a_public_interface(self):
        with self.assertRaises(SystemExit):
            load_module(dict(CONFIG, listen="0.0.0.0"))

    def test_invalid_configuration_is_rejected_without_printing_values(self):
        for change in ({"path": "/../"}, {"path": "/sub/?synthetic-secret"}, {"port": True},
                       {"port": 65536}, {"cert": "/cert.pem"}, {"host": "synthetic-secret\r\nInjected: yes"}):
            with self.subTest(change=change):
                with self.assertRaises(SystemExit) as raised:
                    load_module(dict(CONFIG, **change))
                self.assertNotIn("synthetic-secret", str(raised.exception))


class BoundedReply(io.BytesIO):
    def __init__(self, body, status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {"Content-Type": "text/plain"}
        self.read_sizes = []

    def getheaders(self):
        return list(self.headers.items())

    def read(self, size: int | None = -1):
        self.read_sizes.append(size)
        return super().read(size)


class CapacityTests(unittest.TestCase):
    def test_worker_capacity_closes_excess_connections_and_recovers_after_completion(self):
        module = load_module()
        accepted = mock.Mock()
        excess = mock.Mock()
        with mock.patch.object(module, "MAX_WORKERS", 1, create=True):
            server = module.Server(("127.0.0.1", 0), module.Handler)
        try:
            with mock.patch.object(module.http.server.ThreadingHTTPServer, "process_request") as dispatch, \
                 mock.patch.object(server, "shutdown_request") as close:
                server.process_request(accepted, ("127.0.0.1", 1))
                server.process_request(excess, ("127.0.0.1", 2))
                self.assertEqual(dispatch.call_count, 1)
                close.assert_called_once_with(excess)
            with mock.patch.object(module.http.server.ThreadingHTTPServer, "process_request_thread"):
                server.process_request_thread(accepted, ("127.0.0.1", 1))
            with mock.patch.object(module.http.server.ThreadingHTTPServer, "process_request") as dispatch:
                server.process_request(excess, ("127.0.0.1", 2))
                dispatch.assert_called_once()
        finally:
            server.server_close()


class UpstreamTests(unittest.TestCase):
    def test_error_response_read_failures_return_a_generic_failure(self):
        module = load_module()
        reply = BoundedReply(b"", 404)
        output = io.StringIO()
        error = module.urllib.error.HTTPError("http://127.0.0.1/synthetic", 404, "test", reply.headers, reply)
        with mock.patch.object(reply, "read", side_effect=OSError("synthetic-secret-read-error")), \
             mock.patch.object(module.UPSTREAM_OPENER, "open", side_effect=error), contextlib.redirect_stdout(output):
            try:
                result = module.upstream("synthetic", "test", "", "")
            except Exception:
                result = "unhandled exception"
        self.assertEqual(result, (None, {}, b""))
        self.assertTrue(reply.closed)
        self.assertNotIn("synthetic-secret", output.getvalue())

    def test_derived_awg_ids_support_a_maximum_length_main_bearer(self):
        module = load_module()
        reply = BoundedReply(b"ok")
        with mock.patch.object(module.UPSTREAM_OPENER, "open", return_value=reply) as opening:
            self.assertEqual(module.upstream("a" * 64 + "-awg", "Mihomo", "", "")[0], 200)
        self.assertTrue(opening.called)

    def test_response_reads_are_bounded_including_http_errors(self):
        module = load_module()
        for status in (200, 404):
            with self.subTest(status=status):
                reply = BoundedReply(b"x" * 33, status)
                with mock.patch.object(module, "MAX_BODY_BYTES", 32, create=True), \
                     mock.patch.object(module.UPSTREAM_OPENER, "open") as opening:
                    if status == 200:
                        opening.return_value = reply
                    else:
                        opening.side_effect = module.urllib.error.HTTPError(
                            "http://127.0.0.1/sub/synthetic", status, "test", reply.headers, reply)
                    self.assertEqual(module.upstream("synthetic", "test", "", ""), (None, {}, b""))
                self.assertTrue(reply.closed)
                self.assertTrue(all(0 < n <= 33 for n in reply.read_sizes))

    def test_redirects_never_fetch_another_resource(self):
        module = load_module()
        calls = []

        class Redirect(module.http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(self.path)
                self.send_response(302 if len(calls) == 1 else 200)
                self.send_header("Location", "/private-synthetic-resource")
                self.end_headers()
                self.wfile.write(b"private-content")

            def log_message(self, *args):
                pass

        server = module.http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            module = load_module(dict(CONFIG, upstream=f"http://127.0.0.1:{server.server_port}"))
            code, _, _ = module.upstream("synthetic-bearer", "test", "evil.example.test", "")
            self.assertEqual(code, 302)
            self.assertEqual(calls, ["/subscription/synthetic-bearer"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_environment_proxies_and_client_host_are_not_trusted(self):
        # A poisoned environment must not send bearer URLs to a configured proxy.
        with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1",
                                         "no_proxy": "", "NO_PROXY": ""}):
            module = load_module()
        self.assertTrue(hasattr(module, "UPSTREAM_OPENER"), "a private proxy-free opener is required")
        self.assertFalse(any(isinstance(h, module.urllib.request.ProxyHandler) and h.proxies
                             for h in module.UPSTREAM_OPENER.handlers))
        with mock.patch.object(module.UPSTREAM_OPENER, "open") as opening:
            opening.return_value.__enter__.return_value.status = 200
            opening.return_value.__enter__.return_value.getheaders.return_value = []
            opening.return_value.__enter__.return_value.read.return_value = b"ok"
            module.upstream("synthetic-bearer", "test", "evil.example.test", "")
        self.assertEqual(opening.call_args.args[0].get_header("Host"), CONFIG["host"])

    def test_invalid_ids_cannot_reach_the_backend(self):
        module = load_module()
        with mock.patch.object(module, "upstream", return_value=(200, {}, b"ok")) as backend, serving(module) as server:
            for suffix in (".", "..", "%2e%2e", "bad/extra", "bad%0a", "a" * 65):
                self.assertEqual(request(server, "/subscription/" + suffix)[0], 404)
            backend.assert_not_called()


class ParserTests(unittest.TestCase):
    def test_falsy_non_list_schema_fields_are_not_accepted(self):
        module = load_module()
        for body in (b"proxies: {}", b"proxies: false", b"proxy-groups: {}", b"proxy-groups: 0"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                module.load_clash(body)

    def test_yaml_depth_node_and_alias_expansion_are_bounded(self):
        module = load_module()
        payloads = (b"proxies: []\nextra: " + b"[" * 80 + b"0" + b"]" * 80,
                    b"proxies: []\nextra: [" + b"0," * 100 + b"]",
                    b"proxies: []\na: &a [*a]",
                    b"proxies: []\na: &a [1,2,3,4]\nb: &b [*a,*a,*a,*a]\nc: [*b,*b,*b,*b]")
        with mock.patch.object(module, "MAX_YAML_NODES", 32, create=True):
            for payload in payloads:
                with self.subTest(payload=payload[:20]), self.assertRaises((ValueError, module.yaml.YAMLError)):
                    module.strip_awg(payload)

    def test_malformed_yaml_shapes_fail_closed_without_payload_in_logs(self):
        module = load_module()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), serving(module) as server:
            for payload in (b"proxies: [synthetic-secret]", b"proxies: {name: bad}",
                            b"proxies: [{name: [bad]}]", b"proxy-groups: [bad]",
                            b"proxy-groups: [{proxies: [[bad]]}]", b"proxies: [broken"):
                with self.subTest(payload=payload), mock.patch.object(module, "upstream", return_value=(
                        200, {"content-type": "application/yaml"}, payload)):
                    status, _, body = request(server, headers={"User-Agent": "Clash Stash"})
                    self.assertEqual(status, 502)
                    self.assertNotIn(b"synthetic-secret", body)
        self.assertNotIn("synthetic-secret", output.getvalue())

    def test_parser_input_and_transformed_output_have_byte_limits(self):
        module = load_module()
        with mock.patch.object(module, "MAX_BODY_BYTES", 32, create=True):
            with self.assertRaises(ValueError):
                module.strip_awg(b"#" + b"x" * 32)
            with self.assertRaises(ValueError):
                module.merge_awg(b"rules: [1,2,3]\nproxies: []", b"proxies: [{name: a}]")


class TLSTests(unittest.TestCase):
    def test_handler_closes_the_wrapped_tls_socket_at_finish(self):
        module = load_module()
        handler = module.Handler.__new__(module.Handler)
        handler.request = mock.Mock()
        with mock.patch.object(module.http.server.BaseHTTPRequestHandler, "finish"):
            handler.finish()
        handler.request.close.assert_called_once()

    def test_startup_closes_bound_listener_if_tls_loading_fails(self):
        module = load_module()
        module.CONF.update(cert="/synthetic-cert", key="/synthetic-key")
        server = mock.Mock()
        with mock.patch.object(module, "Server", return_value=server), \
             mock.patch.object(module.os, "geteuid", return_value=1001, create=True), \
             mock.patch.object(module, "tls_stamp", return_value=("test",)), \
             mock.patch.object(module, "tls_context", side_effect=OSError("synthetic-secret")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(), 1)
        server.server_close.assert_called_once()

    @unittest.skipUnless(shutil.which("openssl"), "local openssl is needed for a synthetic TLS fixture")
    def test_real_tls_reload_changes_certificate_and_keeps_old_context_on_invalid_pair(self):
        module = load_module()
        openssl = shutil.which("openssl")
        assert openssl is not None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label in ("first", "second"):
                subprocess.run([openssl, "req", "-x509", "-newkey", "ec",
                                "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
                                "-subj", "/CN=localhost", "-keyout", str(root / (label + ".key")),
                                "-out", str(root / (label + ".pem"))], check=True, timeout=10,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cert, key = root / "current.pem", root / "current.key"
            shutil.copyfile(root / "first.pem", cert)
            shutil.copyfile(root / "first.key", key)
            stamp = module.tls_stamp(cert, key)
            with mock.patch.object(module, "upstream", return_value=(200, {"content-type": "text/html"}, b"test")), \
                 serving(module) as server, contextlib.redirect_stdout(io.StringIO()):
                server.ssl_ctx = module.tls_context(cert, key)
                self.assertEqual(server.ssl_ctx.minimum_version, module.ssl.TLSVersion.TLSv1_2)
                client_context = module.ssl._create_unverified_context()

                def peer_certificate():
                    conn = http.client.HTTPSConnection("127.0.0.1", server.server_port, timeout=3, context=client_context)
                    try:
                        conn.connect()
                        peer = conn.sock.getpeercert(binary_form=True)
                        conn.request("GET", "/subscription/synthetic")
                        response = conn.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.read(), b"test")
                        return peer
                    finally:
                        conn.close()

                old_peer = peer_certificate()
                shutil.copyfile(root / "second.pem", root / "new.pem")
                shutil.copyfile(root / "second.key", root / "new.key")
                os.replace(root / "new.pem", cert)
                os.replace(root / "new.key", key)
                stamp = module.reload_tls(server, cert, key, stamp)
                self.assertNotEqual(peer_certificate(), old_peer)
                live_context = server.ssl_ctx
                key.write_text("invalid synthetic private key", encoding="utf-8")
                self.assertEqual(module.reload_tls(server, cert, key, stamp), stamp)
                self.assertIs(server.ssl_ctx, live_context)
                self.assertNotEqual(peer_certificate(), old_peer)

    def test_key_only_renewal_replaces_context_without_mutating_live_context(self):
        module = load_module()
        self.assertTrue(hasattr(module, "reload_tls"), "atomic context reload is required")
        server = mock.Mock(ssl_ctx=object())
        old_context = server.ssl_ctx
        replacement = object()
        with mock.patch.object(module, "tls_stamp", return_value=("new-key",)), \
             mock.patch.object(module, "tls_context", return_value=replacement):
            stamp = module.reload_tls(server, "/cert", "/key", ("old-key",))
        self.assertEqual(stamp, ("new-key",))
        self.assertIs(server.ssl_ctx, replacement)
        self.assertIsNot(server.ssl_ctx, old_context)

    def test_failed_renewal_keeps_the_working_context_without_logging_paths(self):
        module = load_module()
        self.assertTrue(hasattr(module, "reload_tls"), "safe context reload is required")
        context = object()
        server = mock.Mock(ssl_ctx=context)
        output = io.StringIO()
        with mock.patch.object(module, "tls_stamp", return_value=("new",)), \
             mock.patch.object(module, "tls_context", side_effect=OSError("synthetic-secret-key-path")), \
             contextlib.redirect_stdout(output):
            self.assertEqual(module.reload_tls(server, "/cert", "/key", ("old",)), ("old",))
        self.assertIs(server.ssl_ctx, context)
        self.assertNotIn("synthetic-secret", output.getvalue())

    def test_startup_failure_does_not_emit_exception_details(self):
        module = load_module()
        output = io.StringIO()
        with mock.patch.object(module, "Server", side_effect=OSError("synthetic-secret-startup")), \
             mock.patch.object(module.os, "geteuid", return_value=1001, create=True), \
             contextlib.redirect_stdout(output):
            try:
                result = module.main()
            except Exception:
                result = "unhandled exception"
        self.assertEqual(result, 1)
        self.assertNotIn("synthetic-secret", output.getvalue())


class HeaderTests(unittest.TestCase):
    def test_oversized_or_duplicate_negotiation_headers_are_rejected_before_fetch(self):
        module = load_module()
        with mock.patch.object(module, "upstream", return_value=(200, {}, b"ok")) as backend, serving(module) as server:
            self.assertEqual(request(server, headers={"User-Agent": "x" * 2049})[0], 400)
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            try:
                conn.putrequest("GET", "/subscription/synthetic")
                conn.putheader("Accept", "one")
                conn.putheader("Accept", "two")
                conn.endheaders()
                reply = conn.getresponse()
                self.assertEqual(reply.status, 400)
                reply.read()
            finally:
                conn.close()
            backend.assert_not_called()

    def test_subscription_responses_cannot_be_cached_or_inject_headers(self):
        module = load_module()
        with serving(module) as server:
            with mock.patch.object(module, "upstream", return_value=(200, {
                    "content-type": "text/plain", "cache-control": "public, max-age=86400",
                    "subscription-userinfo": "upload=1; expire=0; total=9"}, b"vless://synthetic")):
                status, headers, body = request(server)
                self.assertEqual(status, 200)
                self.assertEqual(headers.get("Cache-Control"), "private, no-store")
                self.assertEqual(headers.get("Subscription-Userinfo"), "upload=1; total=9")
                self.assertEqual(body, b"vless://synthetic")
            with mock.patch.object(module, "upstream", return_value=(200, {
                    "profile-title": "synthetic\r\nInjected: yes"}, b"ok")):
                self.assertEqual(request(server)[0], 502)


class CompatibilityTests(unittest.TestCase):
    MAIN = b"""proxies:
- {name: Primary, type: vless, server: test.invalid}
- {name: AWG, type: wireguard, amnezia-wg-option: {jc: 4}}
proxy-groups:
- {name: Select, type: select, proxies: [Primary, AWG, DIRECT]}
rules: [MATCH,Select]
"""
    EXTRA = b"""proxies:
- {name: AWG-user-awg, type: wireguard, amnezia-wg-option: {jc: 4}}
"""

    def test_clash_merge_keeps_unique_names_and_group_order(self):
        module = load_module()
        cfg = module.yaml.safe_load(module.merge_awg(self.MAIN, self.EXTRA))
        self.assertEqual([p["name"] for p in cfg["proxies"]], ["Primary", "AWG", "AWG 2"])
        self.assertEqual(cfg["proxy-groups"][0]["proxies"], ["Primary", "AWG", "AWG 2", "DIRECT"])

    def test_mihomo_handler_fetches_only_the_matching_legacy_awg_subscription(self):
        module = load_module()
        with mock.patch.object(module, "upstream", side_effect=[
                (200, {"content-type": "text/yaml"}, self.MAIN),
                (200, {"content-type": "text/yaml"}, self.EXTRA)]) as backend, serving(module) as server:
            status, _, body = request(server, headers={"User-Agent": "Mihomo"})
        self.assertEqual(status, 200)
        self.assertEqual([call.args[0] for call in backend.call_args_list], ["test-bearer", "test-bearer-awg"])
        self.assertEqual([p["name"] for p in module.yaml.safe_load(body)["proxies"]],
                         ["Primary", "AWG", "AWG 2"])

    def test_non_mihomo_clients_have_awg_removed(self):
        module = load_module()
        with mock.patch.object(module, "upstream", return_value=(200, {"content-type": "text/yaml"}, self.MAIN)) as backend, \
             serving(module) as server:
            for ua in ("Clash Karing", "Clash Hiddify", "Stash"):
                status, _, body = request(server, headers={"User-Agent": ua})
                self.assertEqual(status, 200)
                cfg = module.yaml.safe_load(body)
                self.assertEqual([p["name"] for p in cfg["proxies"]], ["Primary"])
                self.assertEqual(cfg["proxy-groups"][0]["proxies"], ["Primary", "DIRECT"])
            self.assertEqual(backend.call_count, 3)

    def test_plain_and_base64_link_lists_preserve_supported_links(self):
        module = load_module()
        plain = b"vless://synthetic\nvpn://synthetic\ntg://synthetic\ntrojan://synthetic"
        expected = b"vless://synthetic\ntrojan://synthetic"
        self.assertEqual(module.strip_links(plain), expected)
        self.assertEqual(module.base64.b64decode(module.strip_links(module.base64.b64encode(plain))), expected)
        self.assertEqual(module.strip_links(b"not valid base64!"), b"not valid base64!")

    def test_benign_yaml_aliases_and_merge_keys_still_work(self):
        module = load_module()
        body = b"defaults: &base {type: vless, server: test.invalid}\nproxies: [{<<: *base, name: Primary}]"
        self.assertEqual(module.strip_awg(body), body)

    def test_backend_authorization_denial_never_fetches_awg(self):
        module = load_module()
        with mock.patch.object(module, "upstream", return_value=(403, {"content-type": "text/yaml"}, b"denied")) as backend, \
             serving(module) as server:
            self.assertEqual(request(server, headers={"User-Agent": "Mihomo"})[0], 403)
            backend.assert_called_once()

    def test_head_keeps_content_length_without_response_body(self):
        module = load_module()
        with mock.patch.object(module, "upstream", return_value=(200, {"content-type": "text/html"}, b"<html>test</html>")), \
             serving(module) as server:
            status, headers, body = request(server, method="HEAD")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Length"], str(len(b"<html>test</html>")))
            self.assertEqual(body, b"")

    def test_bad_main_yaml_cannot_bypass_validation_when_awg_is_absent(self):
        module = load_module()
        with mock.patch.object(module, "upstream", side_effect=[
                (200, {"content-type": "text/yaml"}, b"proxies: [broken"), (404, {}, b"")]), \
             serving(module) as server:
            self.assertEqual(request(server, headers={"User-Agent": "Mihomo"})[0], 502)

    def test_whitespace_cannot_hide_unsupported_link_schemes(self):
        module = load_module()
        self.assertEqual(module.strip_links(b" vpn://synthetic\n\ttg://synthetic\nvless://synthetic"),
                         b"vless://synthetic")


class PrivacyTests(unittest.TestCase):
    def test_request_metadata_and_yaml_errors_do_not_log_credentials(self):
        module = load_module()
        sentinel = "synthetic-bearer-for-privacy-test"
        output = io.StringIO()
        upstream_reply = (200, {"content-type": "application/yaml"},
                          ("proxies: [" + sentinel + ",\n  broken: [").encode())
        with mock.patch.object(module, "upstream", return_value=upstream_reply), \
             contextlib.redirect_stdout(output), serving(module) as server:
            request(server, headers={"User-Agent": "Mihomo " + sentinel})
        self.assertNotIn(sentinel, output.getvalue())

    def test_upstream_exception_does_not_log_subscription_credentials(self):
        module = load_module()
        sentinel = "synthetic-bearer-for-privacy-test"
        output = io.StringIO()
        with mock.patch.object(module.urllib.request, "urlopen", side_effect=module.urllib.error.URLError(sentinel)), \
             mock.patch.object(module, "UPSTREAM_OPENER", create=True) as opener, \
             contextlib.redirect_stdout(output):
            opener.open.side_effect = module.urllib.error.URLError(sentinel)
            self.assertEqual(module.upstream(sentinel, "test", "test", ""), (None, {}, b""))
        self.assertNotIn(sentinel, output.getvalue())
        self.assertIn("upstream", output.getvalue())


if __name__ == "__main__":
    unittest.main()
