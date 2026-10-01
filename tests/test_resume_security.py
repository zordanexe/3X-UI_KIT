"""SEC-1: isolated resume gate; no installer, binary, service or admin operation."""
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/3x-ui.sh"
BASH = shutil.which("bash")


def function(text, name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{[^\n]*\n.*?^}\n", text, re.M | re.S)
    if not match:
        raise AssertionError("missing function: " + name)
    return match.group()


@unittest.skipUnless(BASH, "Bash required")
class ResumeSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.state = self.base / "etc/x-ui"
        self.state.mkdir(parents=True)
        self.env = self.state / "install-result.env"
        # Root-owned state is not an attestation. NEVER source this fixture.
        self.env.write_text("printf ENV_WAS_EXECUTED\\n\n", encoding="utf-8")
        self.panel = self.base / "usr/local/x-ui"
        self.panel.mkdir(parents=True)
        (self.panel / "x-ui").write_bytes(b"unrecognized interrupted panel")
        (self.panel / "x-ui.sh").write_bytes(b"legacy unpinned menu")
        self.commands = self.base / "commands"

    def run_to_environment_source(self):
        text = SCRIPT.read_text(encoding="utf-8")
        # Execute only the real control flow before sourcing credentials.
        # Replace source with a marker, and mock every OS/network/admin boundary.
        body = function(text, "main").split('  . "$XUI_ENV"', 1)[0]
        body += "  printf '%s\\n' RESUME_ACCEPTED\n}\n"
        body = body.replace('  [[ $EUID -eq 0 ]] || die', '  true || die')
        helpers = ""
        if "resume_verified_xui() {" in text:
            helpers = function(text, "resume_verified_xui")
        replacements = {
            "/usr/local/x-ui": self.panel.as_posix(),
            "/etc/x-ui": self.state.as_posix(),
            "/usr/bin/x-ui": (self.base / "usr/bin/x-ui").as_posix(),
            "/etc/systemd/system/x-ui.service": (self.base / "etc/systemd/system/x-ui.service").as_posix(),
            "/root/.acme.sh": (self.base / "root/.acme.sh").as_posix(),
        }
        for old, new in replacements.items():
            body = body.replace(old, new)
            helpers = helpers.replace(old, new)
        shims = """
set -euo pipefail
say() { :; }
warn() { :; }
die() { printf '%s\\n' "$*" >&2; exit 1; }
record() { printf '%s\\n' "$*" >>"$COMMANDS"; }
systemctl() { record systemctl; }
apt-get() { record apt-get; }
curl() { record curl; }
install() { record install; }
chown() { record chown; }
chmod() { record chmod; }
secure_xui_environment() { record secure_xui_environment; }
port_busy() { return 1; }
public_ip() { printf 192.0.2.1; }
sni_ok() { return 0; }
free_port() { printf 2096; }
rand_str() { printf synthetic; }
xui_arch() { printf amd64; }
sc() { record "sc $1"; [[ $1 == verify ]]; }
SNI_CANDIDATES=(example.invalid mask.invalid third.invalid)
ALL_PROTOS=(reality)
DEFAULT_PROTOS=(reality)
PROTOS=(); SNI2=; SNI3=; B=; N=
"""
        runner = self.base / "runner.sh"
        runner.write_text(shims + helpers + body + '\nmain --panel-ssl none --sni example.invalid -y\n',
                          encoding="utf-8", newline="\n")
        env = {**os.environ, "XUI_ENV": self.env.as_posix(),
               "RESULT": (self.base / "missing-result").as_posix(),
               "KIT_BUNDLE_ROOT": ROOT.as_posix(), "COMMANDS": self.commands.as_posix(),
               "XUI_VERSION": "v3.8.5", "MSYS_NO_PATHCONV": "1"}
        assert BASH
        completed = subprocess.run([BASH, runner.as_posix()], env=env,
                                   capture_output=True, text=True, timeout=30)
        commands = self.commands.read_text() if self.commands.exists() else ""
        return completed, commands

    def test_legacy_interrupted_environment_does_not_authorize_resume(self):
        completed, commands = self.run_to_environment_source()
        self.assertNotIn("RESUME_ACCEPTED", completed.stdout,
                         "existing upstream install-result.env bypassed authenticated preparation")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Migration:", completed.stderr)
        self.assertNotIn("ENV_WAS_EXECUTED", completed.stdout + completed.stderr)
        for operation in ("apt-get", "install", "systemctl", "secure_xui_environment"):
            self.assertNotIn(operation, commands)
        self.assertEqual(self.env.read_text(), "printf ENV_WAS_EXECUTED\\n\n")


@unittest.skipUnless(BASH, "Bash required")
class RecognizedResumeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cache = pathlib.Path(os.environ.get("KIT_SC_AUDIT_CACHE", ""))
        if not (cache / "xui-install.sh").is_file():
            raise unittest.SkipTest("set KIT_SC_AUDIT_CACHE for real pinned resume integration")
        spec = importlib.util.spec_from_file_location("resume_supply_chain", ROOT / "scripts/supply-chain.py")
        assert spec and spec.loader
        sc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sc)
        lock = json.loads((ROOT / "scripts/supply-chain.lock.json").read_text())
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.prepared = pathlib.Path(cls.tmp.name) / "prepared"
        cls.prepared.mkdir()

        def cached_fetch(url, digest, target):
            name = next(n for n, asset in lock["assets"].items() if asset["url"] == url)
            if sc.sha256(cache / name) != digest:
                raise AssertionError("cached upstream pin mismatch: " + name)
            shutil.copyfile(cache / name, target)
            return pathlib.Path(target)

        with mock.patch.object(sc, "fetch", side_effect=cached_fetch):
            sc.prepare_xui(lock, cls.prepared, "amd64")
            sc.prepare_xray(lock, cls.prepared, "amd64")
        cls.cache = cache
        cls.sc = sc
        cls.lock = lock
        cls.cached_fetch = staticmethod(cached_fetch)

    def setUp(self):
        self.tmp_fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_fixture.cleanup)
        self.base = pathlib.Path(self.tmp_fixture.name)
        self.layout("amd64")

    def layout(self, arch):
        self.arch = arch
        self.panel = self.base / "usr/local/x-ui"
        self.panel.mkdir(parents=True)
        # Lay out the real upstream files, without executing installer/binaries.
        with tarfile.open(self.prepared / ("x-ui-linux-" + arch + ".tar.gz")) as archive:
            for member in archive:
                if member.isfile() and (member.mode & 0o111 or ".service" in member.name):
                    name = pathlib.PurePosixPath(member.name).relative_to("x-ui").as_posix()
                    if arch in ("armv5", "armv6", "armv7"):
                        name = name.replace("xray-linux-" + arch, "xray-linux-arm32").replace("mtg-linux-" + arch, "mtg-linux-arm")
                    target = self.panel / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    stream = archive.extractfile(member)
                    assert stream
                    with stream, target.open("wb") as output:
                        shutil.copyfileobj(stream, output)
        self.menu = self.base / "usr/bin/x-ui"
        self.menu.parent.mkdir(parents=True)
        shutil.copyfile(self.prepared / "x-ui.sh", self.menu)
        shutil.copyfile(self.menu, self.panel / "x-ui.sh")
        self.service = self.base / "etc/systemd/system/x-ui.service"
        self.service.parent.mkdir(parents=True)
        shutil.copyfile(self.panel / "x-ui.service.debian", self.service)
        self.acme = self.base / "root/.acme.sh"
        self.acme.mkdir(parents=True)
        for name in ("acme.sh", "acme.sh.completion"):
            shutil.copyfile(self.prepared / "acme-source" / name, self.acme / name)
        for name in ("dnsapi", "deploy", "notify"):
            shutil.copytree(self.prepared / "acme-source" / name, self.acme / name)
        self.state = self.base / "etc/x-ui"
        self.state.mkdir(parents=True)
        (self.state / "install-result.env").write_bytes(b"private synthetic state\n")

    def gate(self, fail_prepare=False):
        text = function(SCRIPT.read_text(encoding="utf-8"), "resume_verified_xui")
        replacements = {
            "/usr/local/x-ui": self.panel.as_posix(),
            "/usr/bin/x-ui": self.menu.as_posix(),
            "/etc/systemd/system/x-ui.service": self.service.as_posix(),
            "/root/.acme.sh": self.acme.as_posix(),
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        text = text.replace("python3 -I", "fixture_python -I")
        shims = """
set -euo pipefail
fixture_python() {
  local -a args=("$@")
  # Git Bash mktemp emits MSYS paths; native Windows Python needs native paths.
  if command -v cygpath >/dev/null; then args[2]=$(cygpath -m "${args[2]}"); fi
  "$FIXTURE_PYTHON" "${args[@]}"
}
die() { printf '%s\\n' "$*" >&2; exit 1; }
xui_arch() { printf '%s' "$FIXTURE_ARCH"; }
sc() {
  printf '%s\\n' "$1" >>"$COMMANDS"
  [[ $FAIL_PREPARE == 0 ]] || return 1
  case "$1" in
    prepare-xui) cp -R "$PREPARED/." "$3/" ;;
    prepare-xray) printf '%s\\n' "$3/xray" ;;
    *) return 1 ;;
  esac
}
"""
        runner = self.base / "gate.sh"
        runner.write_text(shims + text + "\nresume_verified_xui\nprintf '%s\\n' VERIFIED_RESUME\n",
                          encoding="utf-8", newline="\n")
        assert BASH
        return subprocess.run([BASH, runner.as_posix()], capture_output=True, text=True, timeout=60,
                              env={**os.environ, "PREPARED": self.prepared.as_posix(),
                                   "KIT_BUNDLE_ROOT": ROOT.as_posix(), "FAIL_PREPARE": str(int(fail_prepare)),
                                   "FIXTURE_PYTHON": pathlib.Path(sys.executable).as_posix(), "FIXTURE_ARCH": self.arch,
                                   "COMMANDS": (self.base / "commands").as_posix(),
                                   "TMPDIR": self.base.as_posix(), "MSYS_NO_PATHCONV": "1"})

    def test_recognized_pinned_hardened_release_resumes_idempotently(self):
        before = (self.state / "install-result.env").read_bytes()
        for _ in range(2):
            result = self.gate()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "VERIFIED_RESUME\n")
            self.assertEqual(result.stderr, "")
            self.assertEqual((self.state / "install-result.env").read_bytes(), before)
        self.assertEqual((self.base / "commands").read_text().splitlines(),
                         ["prepare-xui", "prepare-xray", "prepare-xui", "prepare-xray"])
        self.assertFalse(list(self.base.glob("tmp.*")))

    def test_pinned_replacement_xray_and_acme_bash_shebang_are_recognized(self):
        shutil.copyfile(self.prepared / "xray", self.panel / "bin/xray-linux-amd64")
        for path in (self.acme / "acme.sh", *self.acme.glob("dnsapi/*.sh"),
                     *self.acme.glob("deploy/*.sh"), *self.acme.glob("notify/*.sh")):
            content = path.read_bytes()
            path.write_bytes(b"#!/usr/bin/bash\n" + content.partition(b"\n")[2])
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "VERIFIED_RESUME\n")

    def test_plain_pinned_upstream_menu_or_acme_still_requires_migration(self):
        for target, source in ((self.menu, self.cache / "x-ui.sh"),
                               (self.panel / "x-ui.sh", self.cache / "x-ui.sh"),
                               (self.acme / "acme.sh", self.cache / "acme.sh")):
            with self.subTest(target=target.relative_to(self.base)):
                before = target.read_bytes()
                shutil.copyfile(source, target)
                result = self.gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("VERIFIED_RESUME", result.stdout)
                self.assertIn("Migration:", result.stderr)
                self.assertEqual(target.read_bytes(), source.read_bytes())
                target.write_bytes(before)
        self.assertFalse(list(self.base.glob("tmp.*")))

    def test_changed_installed_code_is_not_blessed_by_valid_other_components(self):
        targets = (self.panel / "x-ui", self.panel / "bin/xray-linux-amd64",
                   self.panel / "bin/mtg-linux-amd64", self.panel / "bin/tuic-server",
                   self.service, self.acme / "dnsapi/dns_cf.sh")
        for target in targets:
            with self.subTest(target=target.relative_to(self.base)):
                before = target.read_bytes()
                target.write_bytes(b"changed unrecognized code\n")
                result = self.gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("VERIFIED_RESUME", result.stdout)
                self.assertIn("Migration:", result.stderr)
                self.assertEqual(target.read_bytes(), b"changed unrecognized code\n")
                target.write_bytes(before)
        self.assertFalse(list(self.base.glob("tmp.*")))

    def test_missing_and_extra_acme_code_are_rejected(self):
        hook = self.acme / "dnsapi/dns_cf.sh"
        before = hook.read_bytes()
        hook.unlink()
        result = self.gate()
        self.assertNotEqual(result.returncode, 0)
        hook.write_bytes(before)
        (self.acme / "dnsapi/unknown.sh").write_bytes(b"unrecognized hook\n")
        result = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("VERIFIED_RESUME", result.stdout)
        self.assertFalse(list(self.base.glob("tmp.*")))

    def test_verification_failure_preserves_installed_code_and_cleans_stage(self):
        before = self.menu.read_bytes()
        result = self.gate(fail_prepare=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verification is unavailable", result.stderr)
        self.assertIn("Migration:", result.stderr)
        self.assertEqual(self.menu.read_bytes(), before)
        self.assertNotIn("VERIFIED_RESUME", result.stdout)
        self.assertFalse(list(self.base.glob("tmp.*")))

    def test_all_other_pinned_architectures_resume_after_upstream_renames(self):
        original_base = self.base
        for arch in self.sc.XRAY_ASSETS:
            if arch == "amd64":
                continue
            with self.subTest(architecture=arch), tempfile.TemporaryDirectory() as tmp:
                self.base = original_base / arch
                self.base.mkdir()
                self.prepared = pathlib.Path(tmp)
                with mock.patch.object(self.sc, "fetch", side_effect=self.cached_fetch):
                    self.sc.prepare_xui(self.lock, self.prepared, arch)
                    self.sc.prepare_xray(self.lock, self.prepared, arch)
                self.layout(arch)
                result = self.gate()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "VERIFIED_RESUME\n")
                name = "arm32" if arch in ("armv5", "armv6", "armv7") else arch
                shutil.copyfile(self.prepared / "xray", self.panel / ("bin/xray-linux-" + name))
                result = self.gate()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(list(self.base.glob("tmp.*")))

    def test_symlinked_code_is_rejected_even_when_target_bytes_match(self):
        actual = self.base / "pinned-menu"
        shutil.copyfile(self.menu, actual)
        self.menu.unlink()
        try:
            self.menu.symlink_to(actual)
        except OSError:
            self.skipTest("native symlinks required")
        result = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("VERIFIED_RESUME", result.stdout)
        self.assertTrue(self.menu.is_symlink())


if __name__ == "__main__":
    unittest.main()
