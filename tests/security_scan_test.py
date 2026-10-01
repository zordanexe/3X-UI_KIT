"""Offline scanner regressions; every credential here is constructed, never live."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts/security_scan.py"


class SecurityScanTests(unittest.TestCase):
    def run_scan(self, root, *args):
        result = subprocess.run([sys.executable, "-B", str(SCANNER), "--root", str(root), "--json", *args], capture_output=True, text=True)
        self.assertTrue(SCANNER.is_file(), "offline scanner is not implemented")
        self.assertIn(result.returncode, (0, 1, 2))
        return result, json.loads(result.stdout)

    def test_aws_secret_access_key_assignments_are_redacted_candidates(self):
        value = 'J9z' * 13 + 'R'
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            name = 'AWS_' + 'SECRET_ACCESS_KEY'
            Path(directory, 'credentials.env').write_text(name + '=' + value, encoding='utf-8')
            result, report = self.run_scan(directory)
            self.assertEqual(result.returncode, 1)
            self.assertTrue(any(hit['rule'] == 'literal-credential' for hit in report['findings']))
            self.assertNotIn(value, result.stdout + result.stderr)

    def test_provider_families_private_keys_and_utf16(self):
        samples = [
            'AK' + 'IA' + 'Q7' * 8,
            'AI' + 'za' + 'Z7q' * 11 + 'X8',
            'xo' + 'xb-' + 'A7z' * 12,
            'sk_' + 'live_' + 'Q8w' * 10,
            '123456789:' + 'K9v' * 11 + 'P4',
            '-----BEGIN ' + 'RSA PRIVATE KEY-----',
            'ey' + 'J' + 'N7q' * 6 + '.' + 'H8n' * 8 + '.' + 'D7v' * 10,
        ]
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            path = Path(directory, 'secret.txt')
            for value in samples:
                path.write_text(value, encoding='utf-16')
                result, report = self.run_scan(directory)
                self.assertEqual(result.returncode, 1)
                self.assertTrue(report['findings'])
                self.assertNotIn(value, result.stdout + result.stderr)

    def test_tar_gzip_limits_and_unsupported_stores_fail_closed(self):
        import gzip
        import io
        import tarfile
        value = ('ghp_' + 'Hv9Q' * 9).encode()
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            path = Path(directory, 'backup.tar.gz')
            with tarfile.open(path, 'w:gz') as archive:
                member = tarfile.TarInfo('credentials.txt')
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
            result, report = self.run_scan(directory)
            self.assertEqual(result.returncode, 1)
            self.assertTrue(any('credentials.txt' in h['path'] for h in report['findings']))
            path.unlink()
            with gzip.open(Path(directory, 'bomb.gz'), 'wb') as stream:
                stream.write(b'a' * (16 * 1024 * 1024 + 1))
            result, report = self.run_scan(directory)
            self.assertEqual(result.returncode, 2)
            self.assertTrue(report['errors'])
            Path(directory, 'bomb.gz').unlink()
            Path(directory, 'database.sqlite').write_bytes(b'SQLite format 3\x00')
            result, report = self.run_scan(directory)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(report['errors'][0]['reason'], 'manual-binary-review-required')

    def test_redacted_authorities_do_not_mask_adjacent_real_secret(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            path = Path(directory, 'report.md')
            path.write_text('hy2://[REDACTED]@example.invalid:443\nvless://[REDACTED]@example.invalid:443\n', encoding='utf-8')
            result, report = self.run_scan(directory)
            self.assertEqual(result.returncode, 0)
            with path.open('a', encoding='utf-8') as stream:
                stream.write('credential=' + 'ghp_' + 'Nr8Z' * 9)
            changed, report = self.run_scan(directory)
            self.assertEqual(changed.returncode, 1)
            self.assertEqual(len(report['findings']), 1)

    def test_security_check_is_an_offline_noninstaller_entrypoint(self):
        path = ROOT / 'scripts/security-check.sh'
        self.assertTrue(path.is_file(), 'security-check entrypoint is missing')
        text = path.read_text(encoding='utf-8')
        self.assertIn('security_scan.py', text)
        self.assertIn('security_scan_test.py', text)
        self.assertIn('tests/security*.test.js', text)
        self.assertNotRegex(text, r'curl|wget|apt-get|npm install|bash "?\$?ROOT/scripts/(?:3x-ui|hysteria2)')

    def test_common_credentials_and_fail_closed_errors(self):
        tokens = [
            'sk-proj-' + 'M7qR' * 15,
            'sk-ant-api03-' + 'V8rN' * 20,
            'Authorization: Bearer ' + 'B7vP' * 10,
            'https://example.invalid/sub?token=' + 'T9rK' * 8,
            'PASSWORD=' + 'UPPERCASESECRET',
        ]
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            path = Path(directory, 'config.env')
            for text in tokens:
                path.write_text(text, encoding='utf-8')
                result, report = self.run_scan(directory)
                self.assertEqual(result.returncode, 1)
                self.assertTrue(report['findings'])
                self.assertNotIn(text, result.stdout + result.stderr)
            path.unlink()
            Path(directory, 'invalid.zip').write_bytes(b'not an archive')
            result, report = self.run_scan(directory)
            self.assertEqual(result.returncode, 2)
            self.assertTrue(report['errors'])
            missing, report = self.run_scan(Path(directory, 'missing'))
            self.assertEqual(missing.returncode, 2)

    def test_only_exact_reviewed_fixture_is_exempt(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            path = Path(directory, 'tools/test/links.test.js')
            path.parent.mkdir(parents=True)
            path.write_bytes((ROOT / 'tools/test/links.test.js').read_bytes())
            result, report = self.run_scan(directory)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(report['reviewed_fixture_files'], 1)
            with path.open('a', encoding='utf-8') as stream:
                stream.write('\ncredential=' + 'ghp_' + 'Nw5X' * 9)
            changed, report = self.run_scan(directory)
            self.assertEqual(changed.returncode, 1)
            self.assertTrue(any(h['rule'] == 'github-token' for h in report['findings']))

    def test_compressed_and_encoded_secrets_are_detected(self):
        import base64
        import zipfile
        value = "ghp_" + "Qm4Y" * 9
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            with zipfile.ZipFile(Path(directory, "backup.zip"), "w") as archive:
                archive.writestr(".env", 'access=' + value)
            private = "C7n" + "mVs2Rq5Tu8Lx" * 3
            conf = '[Interface]\nPrivateKey = ' + private + '\n'
            Path(directory, "proxy.txt").write_text('vpn://' + base64.b64encode(conf.encode()).decode(), encoding='utf-8')
            result, report = self.run_scan(directory)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any('backup.zip!' in h['path'] for h in report['findings']))
        self.assertTrue(any(h['rule'] == 'encoded-proxy-credential' for h in report['findings']))
        self.assertNotIn(value, result.stdout + result.stderr)
        self.assertNotIn(private, result.stdout + result.stderr)

    def test_history_detects_deleted_secret(self):
        value = "ghp_" + "Zq7W" * 9
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            def git(*args):
                return subprocess.run(["git", "-C", directory, *args], check=True, capture_output=True)
            git("init", "-q")
            path = Path(directory, "old.txt")
            path.write_text(value, encoding="utf-8")
            git("add", "old.txt")
            git("-c", "user.name=Offline Test", "-c", "user.email=offline@example.invalid", "commit", "-qm", "synthetic fixture")
            path.unlink()
            git("add", "-u")
            git("-c", "user.name=Offline Test", "-c", "user.email=offline@example.invalid", "commit", "-qm", "remove fixture")
            result, report = self.run_scan(directory, "--history")
        self.assertEqual(result.returncode, 1)
        self.assertGreater(report['history_blobs_scanned'], 0)
        self.assertTrue(any('history:' in hit['path'] for hit in report['findings']))
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_literal_assignments_and_proxy_links_are_candidates_even_in_tests(self):
        value = "R8m" + "qJx2Kp4Vs7Ny" * 3
        samples = [
            'client_secret = "' + value + '"',
            'PrivateKey = ' + value,
            'password: "' + value + '"',
            'db = "postgresql://user:' + value + '@example.invalid/db"',
            'link = "vless://' + value + '@example.invalid:443"',
            'link = "trojan://' + value + '@example.invalid:443"',
            'link = "hy2://user:' + value + '@example.invalid:443"',
        ]
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            Path(directory, "tests").mkdir()
            for i, sample in enumerate(samples):
                Path(directory, "tests", str(i) + ".txt").write_text(sample, encoding="utf-8")
            result, report = self.run_scan(directory)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len({hit['path'] for hit in report['findings']}), len(samples))
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_provider_token_detected_without_disclosure(self):
        token = "ghp_" + "Ab9Z" * 9
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as directory:
            Path(directory, "config.txt").write_text("access=" + token, encoding="utf-8")
            result, report = self.run_scan(directory)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["findings"][0]["rule"], "github-token")
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertNotIn("Ab9Z", result.stdout + result.stderr)


class MatrixPermissionsTests(unittest.TestCase):
    def test_private_key_is_not_world_readable(self):
        source = (ROOT / "tests/matrix/mk-inbounds.sh").read_text(encoding="utf-8")
        self.assertNotIn("chmod 644 /root/cert/*", source)
        self.assertIn("chmod 600 /root/cert/key", source)
        self.assertIn("chmod 644 /root/cert/crt", source)

    def test_disposable_warning_exists(self):
        source = (ROOT / "tests/matrix/README.md").read_text(encoding="utf-8")
        self.assertIn("изолированном одноразовом", source)
        self.assertIn("pkill", source)
        self.assertIn("rmSync", source)


if __name__ == "__main__":
    unittest.main()
