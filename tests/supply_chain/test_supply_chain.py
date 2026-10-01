"""Safe unit/static tests: never execute installers, services or binaries."""
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/supply-chain.py'
sc = None
if HELPER.exists():
    spec = importlib.util.spec_from_file_location('supply_chain', HELPER)
    sc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sc)


class FetchTests(unittest.TestCase):
    def test_rejects_mismatch_without_replacing_target(self):
        self.assertIsNotNone(sc, 'verified download helper is missing')
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / 'asset'
            target.write_bytes(b'existing trusted asset')
            def download(args, **kwargs):
                pathlib.Path(args[args.index('--output') + 1]).write_bytes(b'tampered')
            with mock.patch.object(sc.subprocess, 'run', side_effect=download):
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    sc.fetch('https://github.com/test/asset', hashlib.sha256(b'expected').hexdigest(), target)
            self.assertEqual(target.read_bytes(), b'existing trusted asset')
            self.assertEqual(sorted(p.name for p in pathlib.Path(tmp).iterdir()), ['asset'])

    def test_success_ignores_curlrc_and_requires_https_redirects(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / 'asset'
            payload = b'verified payload'
            def download(args, **kwargs):
                self.assertEqual(args[:2], ['curl', '--disable'])
                self.assertEqual(args[args.index('--proto-redir') + 1], '=https')
                self.assertEqual(args[args.index('--proto') + 1], '=https')
                pathlib.Path(args[args.index('--output') + 1]).write_bytes(payload)
            with mock.patch.object(sc.subprocess, 'run', side_effect=download):
                sc.fetch('https://github.com/test/asset', hashlib.sha256(payload).hexdigest(), target)
            self.assertEqual(target.read_bytes(), payload)

    def test_rejects_non_github_and_credential_urls_before_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            for url in ('http://github.com/test', 'https://evil.example/asset', 'https://user@github.com/asset'):
                with self.subTest(url=url), mock.patch.object(sc.subprocess, 'run') as run:
                    with self.assertRaises(ValueError):
                        sc.fetch(url, '0' * 64, pathlib.Path(tmp) / 'asset')
                    run.assert_not_called()


class BundleTests(unittest.TestCase):
    def bundle(self, root):
        names = ('scripts/3x-ui.sh', 'scripts/hysteria2.sh', 'scripts/kit.sh',
                 'scripts/kit-sub.py', 'scripts/supply-chain.py', 'scripts/supply-chain.lock.json')
        (root / 'scripts').mkdir()
        for name in names:
            (root / name).write_bytes(name.encode())
        self.manifest(root, names)
        return names

    def manifest(self, root, names):
        (root / 'SHA256SUMS').write_text(''.join(hashlib.sha256((root / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in names), newline='\n')

    def test_verified_bundle_is_persisted_with_adjacent_helper_and_manifest(self):
        self.assertTrue(hasattr(sc, 'persist_bundle'), 'bundle persistence is missing')
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            source = base / 'source'; source.mkdir()
            names = self.bundle(source)
            destination = sc.persist_bundle(source, base / 'installed')
            for name in (*names, 'SHA256SUMS'):
                self.assertEqual((source / name).read_bytes(), (destination / name).read_bytes())
            self.assertEqual(sc.persist_bundle(source, base / 'installed'), destination)
            (source / 'scripts/kit.sh').write_text('tampered')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                sc.persist_bundle(source, base / 'installed')

    def test_manifest_rejects_traversal_duplicates_and_self_listing(self):
        self.assertTrue(hasattr(sc, 'verify_bundle'), 'bundle verification is missing')
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            names = self.bundle(root)
            valid = (root / 'SHA256SUMS').read_text()
            for entry in ('0' * 64 + '  ../outside\n', valid.splitlines()[0] + '\n', '0' * 64 + '  SHA256SUMS\n'):
                with self.subTest(entry=entry):
                    (root / 'SHA256SUMS').write_text(valid + entry)
                    with self.assertRaises(ValueError):
                        sc.verify_bundle(root)
            self.manifest(root, names[:-1])
            with self.assertRaisesRegex(ValueError, 'missing'):
                sc.verify_bundle(root)

    def test_manifest_must_cover_every_bundle_file_except_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.bundle(root)
            (root / 'unverified-extra.py').write_text('unexpected executable input')
            with self.assertRaisesRegex(ValueError, 'unlisted'):
                sc.verify_bundle(root)

    def test_existing_snapshot_manifest_must_match_its_content_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            source = base / 'source'; source.mkdir()
            names = self.bundle(source)
            snapshot = sc.persist_bundle(source, base / 'installed')
            (snapshot / 'scripts/kit.sh').write_text('changed with a recomputed manifest')
            self.manifest(snapshot, names)
            with self.assertRaisesRegex(ValueError, 'snapshot'):
                sc.persist_bundle(source, base / 'installed')


class PreparationTests(unittest.TestCase):
    def test_upstream_adapters_fail_closed_and_remove_remote_execution(self):
        self.assertTrue(hasattr(sc, 'adapt_installer'), 'offline upstream adapter is missing')
        cache = pathlib.Path(__import__('os').environ.get('KIT_SC_AUDIT_CACHE', ''))
        if not (cache / 'xui-install.sh').is_file():
            self.skipTest('set KIT_SC_AUDIT_CACHE for real upstream integration')
        installer = (cache / 'xui-install.sh').read_text()
        menu = (cache / 'x-ui.sh').read_text()
        acme = (cache / 'acme.sh').read_text()
        lock = __import__('json').loads((ROOT / 'scripts/supply-chain.lock.json').read_text())
        changed = sc.adapt_installer(installer, lock)
        sanitized_menu = sc.adapt_menu(menu, lock)
        sanitized_acme = sc.adapt_acme(acme)
        for text in (changed, sanitized_menu):
            executable = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
            self.assertFalse(__import__('re').search(r'curl[^\n]*(?:get\.acme\.sh|raw\.githubusercontent\.com|packagecloud)', executable), 'remote script fetch remains')
            self.assertFalse(__import__('re').search(r'--upgrade --auto-upgrade(?! 0)', executable), 'auto code upgrade remains')
            self.assertFalse(__import__('re').search(r'curl[^\n]*\|\s*(?:sh|bash)', executable), 'pipe-to-shell remains')
        self.assertIn('config_after_install', changed)
        self.assertIn('setup_fail2ban', changed)
        self.assertIn('reset_user()', sanitized_menu)
        self.assertNotIn('_get\n', sc.function_body(sanitized_acme, 'upgrade'))
        with self.assertRaisesRegex(ValueError, 'checksum'):
            sc.adapt_installer(installer + '# tampered', lock)

    def test_safe_extraction_rejects_links_traversal_and_unexpected_root(self):
        self.assertTrue(hasattr(sc, 'extract_tar'), 'safe extraction is missing')
        import io, tarfile
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            for name, kind in (('../escape', tarfile.REGTYPE), ('safe/link', tarfile.SYMTYPE), ('elsewhere/file', tarfile.REGTYPE)):
                archive = base / 'test.tar.gz'
                with tarfile.open(archive, 'w:gz') as tar:
                    member = tarfile.TarInfo(name); member.type = kind
                    member.size = 1 if kind == tarfile.REGTYPE else 0
                    member.linkname = '/etc/passwd'
                    tar.addfile(member, io.BytesIO(b'x') if member.size else None)
                with self.assertRaises(ValueError):
                    sc.extract_tar(archive, base / 'output', 'safe')
                self.assertFalse((base / 'escape').exists())

    def test_real_pinned_assets_prepare_without_executing_dependencies(self):
        self.assertTrue(hasattr(sc, 'prepare_xui'), 'asset preparation is missing')
        import os, json, shutil, subprocess
        cache = pathlib.Path(os.environ.get('KIT_SC_AUDIT_CACHE', ''))
        if not (cache / 'xui-install.sh').is_file():
            self.skipTest('set KIT_SC_AUDIT_CACHE for real asset integration')
        lock = json.loads((ROOT / 'scripts/supply-chain.lock.json').read_text())
        def cached_fetch(url, digest, target):
            name = next(n for n, a in lock['assets'].items() if a['url'] == url)
            self.assertEqual(sc.sha256(cache / name), digest)
            shutil.copyfile(cache / name, target)
            return pathlib.Path(target)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sc, 'fetch', side_effect=cached_fetch):
            for arch in sc.XRAY_ASSETS:
                with self.subTest(architecture=arch):
                    stage = pathlib.Path(tmp) / arch
                    stage.mkdir()
                    prepared = sc.prepare_xui(lock, stage, arch)
                    self.assertEqual(prepared, stage / 'install-verified.sh')
                    self.assertTrue((stage / 'acme-source/acme.sh').is_file())
                    with mock.patch.object(sc.subprocess, 'run') as run:
                        binary = sc.prepare_xray(lock, stage, arch)
                        run.assert_not_called()
                    self.assertGreater(binary.stat().st_size, 0)
                    bash = shutil.which('bash')
                    if bash:
                        for file in (prepared, stage / 'x-ui.sh', stage / 'acme-source/acme.sh'):
                            subprocess.run([bash, '-n', str(file)], check=True)
            with self.assertRaisesRegex(ValueError, 'architecture'):
                sc.prepare_xui(lock, pathlib.Path(tmp), 'bogus')

    def test_acme_cannot_install_online_and_upgrade_initializes_config(self):
        import os
        cache = pathlib.Path(os.environ.get('KIT_SC_AUDIT_CACHE', ''))
        if not (cache / 'acme.sh').is_file():
            self.skipTest('set KIT_SC_AUDIT_CACHE for upstream ACME integration')
        text = sc.adapt_acme((cache / 'acme.sh').read_text())
        self.assertFalse('_get ' in sc.function_body(text, 'installOnline'), 'ACME online code installer remains')
        self.assertIn('_initpath', sc.function_body(text, 'upgrade'))

    def test_cached_pin_fetcher_checks_real_assets_without_execution(self):
        import os, subprocess, sys
        fetcher = ROOT / 'tests/supply_chain/fetch_pinned.py'
        self.assertTrue(fetcher.is_file(), 'safe provenance fetch harness is missing')
        cache = pathlib.Path(os.environ.get('KIT_SC_AUDIT_CACHE', ''))
        if not (cache / 'xui-install.sh').is_file():
            self.skipTest('set KIT_SC_AUDIT_CACHE for cached provenance check')
        result = subprocess.run([sys.executable, '-B', str(fetcher), str(cache)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        lock = __import__('json').loads((ROOT / 'scripts/supply-chain.lock.json').read_text())
        self.assertEqual(len(result.stdout.splitlines()), len(lock['assets']))


class BootstrapTests(unittest.TestCase):
    bundle = BundleTests.bundle
    manifest = BundleTests.manifest
    def test_shell_bootstrap_accepts_complete_bundle_and_refuses_tampering(self):
        import shutil, subprocess
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('Bash required for isolated bootstrap test')
        text = (ROOT / 'scripts/3x-ui.sh').read_text(encoding='utf-8')
        body = sc.function_body(text, 'supply_chain_bootstrap')
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            names = self.bundle(root)
            script = root / 'scripts/3x-ui.sh'
            script.write_text('#!/bin/bash\n' + body + '\nsupply_chain_bootstrap || exit 1\nprintf VERIFIED\\\\n\n', encoding='utf-8', newline='\n')
            self.manifest(root, names)
            result = subprocess.run([bash, script.as_posix()], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('VERIFIED', result.stdout)
            (root / 'scripts/kit.sh').write_text('tampered')
            result = subprocess.run([bash, script.as_posix()], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('VERIFIED', result.stdout)


class ScriptIntegrationTests(unittest.TestCase):
    def test_entrypoints_require_bundle_and_do_not_execute_mutable_downloads(self):
        for name in ('3x-ui.sh', 'hysteria2.sh', 'kit.sh'):
            text = (ROOT / 'scripts' / name).read_text(encoding='utf-8')
            with self.subTest(script=name):
                self.assertIn('supply_chain_bootstrap', text)
                self.assertIn('SHA256SUMS', text)
                self.assertNotIn('/main/', text)
                self.assertNotIn('Bearer ***', text)
        xui = (ROOT / 'scripts/3x-ui.sh').read_text(encoding='utf-8')
        hy = (ROOT / 'scripts/hysteria2.sh').read_text(encoding='utf-8')
        self.assertNotIn('KIT_SUB_SRC', xui)
        self.assertIn('prepare-xui', xui)
        self.assertIn('prepare-xray', xui)
        self.assertNotIn('server/installXray', xui)
        self.assertIn('persist', hy)
        self.assertIn('hysteria "$KIT_BUNDLE_ROOT"', hy)
        self.assertNotIn('hashes.txt', hy)

    def test_hysteria_update_never_executes_unverified_old_binary(self):
        body = sc.function_body((ROOT / 'scripts/hysteria2.sh').read_text(encoding='utf-8'), 'cmd_update_binary')
        self.assertNotIn('"$BIN" version', body)
        self.assertIn('install_binary', body)
        self.assertIn('reload_service', body)

    def test_release_shell_files_use_lf_and_update_executes_snapshot(self):
        for name in ('3x-ui.sh', 'hysteria2.sh', 'kit.sh'):
            self.assertFalse(b'\r' in (ROOT / 'scripts' / name).read_bytes(), 'CRLF breaks Linux Bash: ' + name)
        update = sc.function_body((ROOT / 'scripts/hysteria2.sh').read_text(encoding='utf-8'), 'cmd_update')
        self.assertIn('bash "$installed/scripts/hysteria2.sh"', update)
        self.assertLess(update.index('sc persist'), update.index('bash "$installed'))


if __name__ == '__main__':
    unittest.main()
