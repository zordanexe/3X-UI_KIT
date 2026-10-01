"""Installer contracts and isolated helpers; never run an installer/service.

Windows can exercise Bash/publication with synthetic files and ownership shims.
Actual Linux DAC/capabilities/systemd acceptance is deliberately not claimed.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/3x-ui.sh"
BASH = shutil.which("bash")


def source():
    return SCRIPT.read_text(encoding="utf-8")


def function(name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{[^\n]*\n.*?^}(?=\n\n|\n?\Z)", source(), re.M | re.S)
    if not match:
        raise AssertionError("missing function: " + name)
    return match.group().rstrip()


def heredoc(target, delimiter="UNIT"):
    match = re.search(r"cat\s*>" + re.escape(target) + r"\s*<<'" + delimiter + r"'\n(.*?)^" + delimiter + r"$", source(), re.M | re.S)
    if not match:
        raise AssertionError("missing generated file: " + target)
    return match.group(1)


class IdentityTests(unittest.TestCase):
    def test_network_daemon_is_nonroot_without_home_or_capabilities(self):
        unit = heredoc("/etc/systemd/system/kit-sub.service")
        required = {
            "Type": "simple", "User": "kit-sub", "Group": "kit-sub",
            "ExecStart": "/usr/bin/python3 -B /usr/local/lib/kit-sub/kit_sub.py",
            "Environment": "KIT_SUB_CONFIG=/etc/kit-sub/config.json",
            "WorkingDirectory": "/usr/local/lib/kit-sub", "UMask": "0077",
            "NoNewPrivileges": "true", "ProtectSystem": "strict", "ProtectHome": "true",
            "PrivateTmp": "true", "PrivateDevices": "true", "ProtectKernelTunables": "true",
            "ProtectKernelModules": "true", "ProtectKernelLogs": "true", "ProtectControlGroups": "true",
            "RestrictNamespaces": "true", "RestrictSUIDSGID": "true", "RestrictRealtime": "true",
            "LockPersonality": "true", "MemoryDenyWriteExecute": "true",
            "SystemCallArchitectures": "native", "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
            "CapabilityBoundingSet": "", "AmbientCapabilities": "", "MemoryMax": "256M",
            "TasksMax": "32", "LimitNOFILE": "128",
        }
        settings = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
        for key, value in required.items():
            with self.subTest(setting=key):
                self.assertEqual(settings.get(key), value)
        self.assertNotIn("ReadWritePaths=", unit)
        self.assertNotIn("SupplementaryGroups=", unit)

    def test_identity_and_roots_are_guarded_and_code_remains_verified(self):
        body = function("install_kit_sub")
        for text in (
            "[[ ! -L /usr/local/lib/kit-sub && ! -L /etc/kit-sub ]]",
            "groupadd --system kit-sub",
            "useradd --system --gid kit-sub --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin kit-sub",
            "$ks_uid != 0", "$ks_gid != 0", '$ks_gid == "$ks_group_gid"',
            "$ks_home == /nonexistent", "$ks_shell == /usr/sbin/nologin",
            '$(id -G kit-sub) == "$ks_gid"', "-z $ks_members",
            "install -d -o root -g root -m 0755 /usr/local/lib/kit-sub",
            "install -d -o root -g kit-sub -m 0750 /etc/kit-sub",
            'sc verify "$KIT_BUNDLE_ROOT"',
            'install -o root -g root -m 0644 "$KIT_BUNDLE_ROOT/scripts/kit-sub.py" /usr/local/lib/kit-sub/kit_sub.py',
            "chown root:root /etc/systemd/system/kit-sub.service",
            "chmod 0644 /etc/systemd/system/kit-sub.service",
        ):
            with self.subTest(contract=text):
                self.assertTrue(text in body, "missing contract: " + text)
        self.assertLess(body.index('sc verify "$KIT_BUNDLE_ROOT"'), body.index('"$KIT_BUNDLE_ROOT/scripts/kit-sub.py"'))
        self.assertNotIn("curl", body)
        self.assertNotRegex(source(), r"KIT_SUB_(?:URL|SRC)")
        for gate in ("supply_chain_bootstrap || exit 1", 'sc prepare-xui "$KIT_BUNDLE_ROOT"', 'sc prepare-xray "$KIT_BUNDLE_ROOT"', 'sc persist "$KIT_BUNDLE_ROOT"'):
            self.assertIn(gate, source())


class TLSContractTests(unittest.TestCase):
    def test_tls_config_and_publication_are_root_managed_read_only(self):
        body = function("install_kit_sub")
        sync = function("install_kit_sub_tls_sync")
        for text in (
            'ks_config=$(mktemp /etc/kit-sub/.config.XXXXXXXX)',
            'chown root:kit-sub "$ks_config"; chmod 0640 "$ks_config"',
            'mv -Tf -- "$ks_config" /etc/kit-sub/config.json',
            'cert: "/etc/kit-sub/tls/current/fullchain.pem", key: "/etc/kit-sub/tls/current/privkey.pem"',
            "install_kit_sub_tls_sync",
            "systemctl enable --now kit-sub-tls-sync.timer",
        ):
            self.assertTrue(text in body, "missing contract: " + text)
        for text in (
            '[[ ! -L /etc/kit-sub/tls ]]',
            'install -d -o root -g kit-sub -m 0750 /etc/kit-sub/tls',
            'chown root:root "$sources"; chmod 0600 "$sources"',
            'install -o root -g root -m 0700 "$helper" /usr/local/sbin/kit-sub-sync-tls',
            'install -o root -g kit-sub -m 0640 -- "$cert" "$generation/fullchain.pem"',
            'install -o root -g kit-sub -m 0640 -- "$key" "$generation/privkey.pem"',
            'chown root:kit-sub "$generation"', 'chmod 0750 "$generation"',
            'chown root:root /etc/systemd/system/kit-sub-tls-sync.service /etc/systemd/system/kit-sub-tls-sync.timer',
            'chmod 0644 /etc/systemd/system/kit-sub-tls-sync.service /etc/systemd/system/kit-sub-tls-sync.timer',
        ):
            self.assertTrue(text in sync, "missing contract: " + text)
        unit = heredoc("/etc/systemd/system/kit-sub-tls-sync.service")
        for setting in ("User=root", "Group=root", "ProtectHome=read-only", "ProtectSystem=strict",
                        "ReadWritePaths=/etc/kit-sub/tls", "PrivateNetwork=true", "PrivateDevices=true",
                        "RestrictAddressFamilies=AF_UNIX", "CapabilityBoundingSet=CAP_CHOWN", "TimeoutStartSec=30"):
            self.assertTrue(setting in unit.splitlines(), "missing helper setting: " + setting)
        self.assertNotIn("CAP_DAC_OVERRIDE", unit)
        self.assertNotIn("CAP_DAC_READ_SEARCH", unit)
        timer = heredoc("/etc/systemd/system/kit-sub-tls-sync.timer")
        self.assertIn("OnUnitActiveSec=60s", timer)
        self.assertLess(body.index("systemctl daemon-reload"), body.index("systemctl enable --now kit-sub-tls-sync.timer"))


@unittest.skipUnless(BASH and shutil.which("openssl"), "Bash/OpenSSL required")
class TLSHelperTests(unittest.TestCase):
    def setUp(self):
        # Extract only the generated publisher, NEVER the installer function.
        self.helper = heredoc('"$helper"', "HELPER")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.tls = self.base / "tls"
        self.tls.mkdir()
        probe = self.base / "symlink-probe"
        try:
            probe.symlink_to("tls", target_is_directory=True)
            probe.unlink()
        except OSError:
            self.skipTest("native symlink creation required")
        self.cert = self.base / "source-cert.pem"
        self.key = self.base / "source-key.pem"
        self.pair("initial")

    def pair(self, name):
        openssl = shutil.which("openssl")
        assert openssl
        subprocess.run([openssl, "req", "-x509", "-nodes", "-newkey", "ec",
                        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-keyout", self.key.as_posix(),
                        "-out", self.cert.as_posix(), "-subj", "/CN=" + name, "-days", "1"],
                       check=True, capture_output=True,
                       env={**os.environ, "MSYS_NO_PATHCONV": "1"})

    def publish(self, mutate_after_stage=False, lock_busy=False):
        assert BASH
        import shlex
        quote = lambda p: shlex.quote(pathlib.Path(p).as_posix())
        # Windows does not have Linux EUID, jq, flock or root:kit-sub accounts.
        # Shim only those boundaries; real copy/cmp/SSL/ln/mv/rm code is exercised.
        shims = '''
flock() { return "$FIXTURE_LOCK_BUSY"; }
jq() {
  case "$2" in
    .cert*) printf '%s\\n' "$FIXTURE_CERT" ;;
    .key*) printf '%s\\n' "$FIXTURE_KEY" ;;
    *) return 1 ;;
  esac
}
chown() { printf 'chown %s\\n' "$*" >>"$FIXTURE_COMMANDS"; }
install() {
  printf 'install %s\\n' "$*" >>"$FIXTURE_COMMANDS"
  local -a args=()
  while (( $# )); do
    case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
  done
  command install "${args[@]}"
}
chmod() {
  printf 'chmod %s\\n' "$*" >>"$FIXTURE_COMMANDS"
  command chmod "$@"
}
'''
        # Simulate source renewal during staging, after genuine SSL validation.
        python = quote(sys.executable)
        if mutate_after_stage:
            validate = python + ' "$@"; printf changed >>"$FIXTURE_KEY"'
            shims += "fixture_python() { " + validate + "; }\n"
            python = "fixture_python"
        helper = self.helper.replace("base=/etc/kit-sub/tls", "base=" + quote(self.tls))
        helper = helper.replace('[[ $EUID == 0 && -d $base && ! -L $base ]]', '[[ -d $base && ! -L $base ]]')
        helper = helper.replace("/usr/bin/python3", python)
        path = self.base / "publisher.sh"
        path.write_text("#!/bin/bash\n" + shims + helper, encoding="utf-8", newline="\n")
        env = {**os.environ, "MSYS": "winsymlinks:nativestrict", "MSYS_NO_PATHCONV": "1",
               "FIXTURE_CERT": self.cert.as_posix(), "FIXTURE_KEY": self.key.as_posix(),
               "FIXTURE_COMMANDS": (self.base / "commands").as_posix(),
               "FIXTURE_LOCK_BUSY": str(int(lock_busy))}
        return subprocess.run([BASH, path.as_posix()], capture_output=True, text=True, env=env, timeout=30)

    def test_valid_pairs_publish_atomically_and_keep_only_two_generations(self):
        for name in ("initial", "renewed", "latest"):
            self.pair(name)
            result = self.publish()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout + result.stderr, "")
            current = self.tls / "current"
            self.assertTrue(current.is_symlink())
            self.assertEqual((current / "fullchain.pem").read_bytes(), self.cert.read_bytes())
            self.assertEqual((current / "privkey.pem").read_bytes(), self.key.read_bytes())
        self.assertEqual(len(list(self.tls.glob("gen.*"))), 2)
        before = os.readlink(self.tls / "current")
        self.assertEqual(self.publish().returncode, 0)
        self.assertEqual(os.readlink(self.tls / "current"), before)
        self.assertEqual(len(list(self.tls.glob("gen.*"))), 2)
        commands = (self.base / "commands").read_text()
        self.assertIn("-o root -g kit-sub -m 0640", commands)
        self.assertIn("chown root:kit-sub", commands)
        self.assertIn("chmod 0750", commands)
        self.assertFalse(list(self.tls.glob(".current.*")))

    def test_invalid_and_mismatched_pairs_preserve_current_without_secret_logs(self):
        self.assertEqual(self.publish().returncode, 0)
        before = os.readlink(self.tls / "current")
        old_cert = self.cert.read_bytes()
        self.pair("mismatch")
        self.cert.write_bytes(old_cert)
        for invalid in (False, True):
            if invalid:
                self.key.write_text("SYNTHETIC_SECRET_SENTINEL invalid PEM")
            result = self.publish()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "kit-sub: protected TLS sync failed\n")
            self.assertEqual(result.stderr, "")
            self.assertEqual(os.readlink(self.tls / "current"), before)
            self.assertEqual(len(list(self.tls.glob("gen.*"))), 1)
            self.assertFalse(list(self.tls.glob(".current.*")))

    def test_sources_changed_during_stage_and_busy_lock_do_not_publish(self):
        self.assertEqual(self.publish().returncode, 0)
        before = os.readlink(self.tls / "current")
        self.pair("race")
        result = self.publish(mutate_after_stage=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(os.readlink(self.tls / "current"), before)
        self.assertEqual(len(list(self.tls.glob("gen.*"))), 1)
        result = self.publish(lock_busy=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertEqual(os.readlink(self.tls / "current"), before)


class LifecycleTests(unittest.TestCase):
    def test_stale_cleanup_stops_publisher_before_removing_owned_files(self):
        body = function("main")
        cleanup = body[body.index("  if [[ -f $RESULT ]]; then"):body.index("  if [[ -d /usr/local/x-ui")]
        for text in ("systemctl disable --now kit-sub-tls-sync.timer", "systemctl stop kit-sub-tls-sync.service",
                     "/etc/systemd/system/kit-sub-tls-sync.service", "/etc/systemd/system/kit-sub-tls-sync.timer",
                     "/usr/local/sbin/kit-sub-sync-tls"):
            self.assertTrue(text in cleanup, "missing stale cleanup: " + text)
        self.assertLess(cleanup.index("systemctl stop kit-sub-tls-sync.service"), cleanup.index("rm -rf"))
        self.assertNotRegex(source(), r"\b(?:userdel|groupdel)\b")
        self.assertNotIn("/root/cert", cleanup)

    def test_plaintext_mode_revokes_copies_before_config_and_never_uses_privileged_port(self):
        body = function("install_kit_sub")
        single = body[body.index("    # Only loopback HTTP"):body.index("    install_kit_sub_tls_sync")]
        for text in ("systemctl disable --now kit-sub-tls-sync.timer", "systemctl stop kit-sub-tls-sync.service",
                     "systemctl stop kit-sub", "rm -rf -- /etc/kit-sub/tls", "rm -f -- /etc/kit-sub/tls-sources.json",
                     'listen: "127.0.0.1"'):
            self.assertTrue(text in single, "missing single-port contract: " + text)
        self.assertLess(single.index("systemctl stop kit-sub"), single.index("rm -rf"))
        self.assertLess(single.index("rm -rf"), single.index("jq -n"))
        self.assertNotIn("/root/cert", single)
        self.assertIn('((kp > 1023 && kp < 65536))', body)
        self.assertLess(body.index('((kp > 1023'), body.index('sc verify'))


@unittest.skipUnless(BASH, "Bash required for isolated helpers")
class SecretStateTests(unittest.TestCase):
    def bash(self, body, **values):
        assert BASH
        with tempfile.TemporaryDirectory() as tmp:
            fixture = pathlib.Path(tmp)
            result = fixture / "3x-ui.txt"
            result.write_text("old protected result")
            result.chmod(0o666)
            test_script = fixture / "test.sh"
            env = {**os.environ, "RESULT": result.as_posix(), "COMMANDS": (fixture / "commands").as_posix(),
                   "XUI_VERSION": "test", "XUI_USERNAME": "SYNTHETIC_USER", "XUI_PASSWORD": "SYNTHETIC_PASSWORD",
                   "panel_url": "https://example.invalid/SYNTHETIC_PANEL_PATH/",
                   "SUB_URL": "https://example.invalid/sub/SYNTHETIC_SUB_ID", "TRUSTED": "yes", "NAME": "test",
                   "links": "vless://SYNTHETIC_LINK_SECRET@example.invalid", "SINGLE": "no",
                   "TOKEN": "SYNTHETIC_API_TOKEN", "XUI_API_TOKEN": "SYNTHETIC_API_TOKEN",
                   "G": "", "B": "", "N": "", "D": "", "PIN": "", "CHOWN_FAIL": "0", **values}
            shims = '''
set -euo pipefail
chown() { printf 'chown %s\\n' "$*" >>"$COMMANDS"; return "$CHOWN_FAIL"; }
chmod() { printf 'chmod %s\\n' "$*" >>"$COMMANDS"; command chmod "$@"; }
die() { printf '%s\\n' "$*" >&2; exit 1; }
warn() { printf '%s\\n' "$*" >&2; }
CREATED=(REALITY)
'''
            test_script.write_text(shims + body, encoding="utf-8", newline="\n")
            completed = subprocess.run([BASH, test_script.as_posix()], capture_output=True, text=True, env=env, timeout=30)
            return completed, result.read_text(), (fixture / "commands").read_text() if (fixture / "commands").exists() else "", list(fixture.glob(".3x-ui-result.*"))

    def test_result_is_atomic_root_owned_0600_even_if_existing_file_was_public(self):
        helper = function("write_install_result")
        completed, result, commands, debris = self.bash(helper + "\nwrite_install_result\n")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("SYNTHETIC_PASSWORD", result)
        self.assertIn("SYNTHETIC_LINK_SECRET", result)
        self.assertEqual(completed.stdout + completed.stderr, "")
        self.assertIn("chown root:root", commands)
        self.assertIn("chmod 0600", commands)
        self.assertFalse(debris)
        failed, result, _, debris = self.bash(helper + "\nwrite_install_result\n", CHOWN_FAIL="1")
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(result, "old protected result")
        self.assertFalse(debris)

    def test_summary_never_prints_credentials_links_or_qr_to_logs(self):
        helper = function("print_install_summary")
        for trusted in ("yes", "no"):
            completed, _, _, _ = self.bash(helper + "\nprint_install_summary\n", TRUSTED=trusted)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn("SYNTHETIC_", completed.stdout + completed.stderr)
            self.assertIn("3x-ui.txt", completed.stdout)
        self.assertNotIn("qrencode", helper)
        main = function("main")
        self.assertIn("write_install_result", main)
        self.assertIn("print_install_summary", main)
        self.assertNotIn('echo "$SUB_URL"', main)
        self.assertNotIn('echo "$links"', main)
        self.assertNotIn('echo "Пароль:', main)

    def test_root_environment_is_protected_before_source_and_symlink_paths_refused(self):
        main = function("main")
        helper = function("secure_xui_environment")
        for text in ('! -L /etc/x-ui', '! -L $XUI_ENV', '-f $XUI_ENV',
                     "$(stat -c '%u' /etc/x-ui) == 0", "$(stat -c '%u' \"$XUI_ENV\") == 0",
                     'install -d -o root -g root -m 0700 /etc/x-ui',
                     'chown root:root "$XUI_ENV"', 'chmod 0600 "$XUI_ENV"'):
            self.assertTrue(text in helper, "missing environment protection: " + text)
        self.assertLess(main.index("secure_xui_environment"), main.index('. "$XUI_ENV"'))
        self.assertIn('[[ ! -L $RESULT && ! -L $XUI_ENV && ! -L /etc/x-ui ]]', main)
        self.assertIn('[[ ! -L $RESULT ]]', function("write_install_result"))

    def test_api_failure_does_not_echo_backend_message_or_payload(self):
        helper = function("api")
        fixture = '''
API=http://127.0.0.1:2097/SYNTHETIC_PANEL_PATH
curl() { printf '%s\\n' '{}'; }
jq() { if [[ $2 == .success ]]; then printf false; else printf SYNTHETIC_BACKEND_SECRET; fi; }
'''
        completed, _, _, _ = self.bash(helper + fixture + "\napi GET safe\n")
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("SYNTHETIC_", completed.stdout + completed.stderr)
        self.assertNotIn(".msg // .", source())
        self.assertNotIn("journalctl -u kit-sub -n", source())
        self.assertNotIn("cat /tmp/nginx-test.log", source())
        self.assertIn('install -o root -g root -m 0600 /dev/null /var/log/3x-ui-install.log', source())

    def test_api_transport_failure_does_not_log_sensitive_diagnostics(self):
        helper = function("api")
        fixture = '''
API=http://127.0.0.1:2097/SYNTHETIC_PANEL_PATH
curl() { printf SYNTHETIC_CURL_DIAGNOSTIC >&2; return 1; }
'''
        completed, _, _, _ = self.bash(helper + fixture + "\napi GET safe\n")
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("SYNTHETIC_", completed.stdout + completed.stderr)
        self.assertIn("Panel API transport failed", completed.stderr)

    def test_inbound_transport_also_suppresses_raw_curl_diagnostics(self):
        inbound = function("add_inbound")
        calls = [line for line in inbound.splitlines() if 'out=$(curl' in line]
        self.assertEqual(len(calls), 2)
        for line in calls:
            self.assertTrue('2>/dev/null) || die "Panel API transport failed"' in line,
                            "inbound curl diagnostics must be suppressed")

    def test_source_keys_are_root_owned_private_without_dac_bypass_requirement(self):
        tls = function("setup_tls_cert")
        for text in ('[[ ! -L /root/cert && ! -L ${CERT%/*} ]]',
                     'install -d -o root -g root -m 0700 /root/cert "${CERT%/*}"',
                     '[[ -f $CERT && ! -L $CERT && -f $KEY && ! -L $KEY ]]',
                     'chown root:root "$CERT" "$KEY"', 'chmod 0600 "$KEY"', 'chmod 0644 "$CERT"'):
            self.assertTrue(text in tls, "missing TLS source protection: " + text)
        self.assertNotIn('chown root:kit-sub "$KEY"', tls)


if __name__ == "__main__":
    unittest.main()
