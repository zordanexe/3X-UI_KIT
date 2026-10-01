import hashlib
import importlib.util
import pathlib
import subprocess
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class ReleaseBundleTests(unittest.TestCase):
    def test_deterministic_git_bytes_and_real_manifest(self):
        path = ROOT / 'scripts/build-release.py'
        self.assertTrue(path.is_file(), 'release builder not implemented')
        spec = importlib.util.spec_from_file_location('release_builder', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / 'repo'
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)
            git('init', '-b', 'main')
            (repo / 'scripts').mkdir()
            (repo / 'scripts/example.sh').write_bytes(b'#!/bin/bash\necho safe\n')
            git('add', '.')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture')
            commit = git('rev-parse', 'HEAD').decode().strip()
            # An untracked local secret must never enter release assets.
            (repo / '.env').write_text('not-real-secret')
            first = module.build(repo, commit, 'secure-v1.0.0', pathlib.Path(tmp) / 'one')
            second = module.build(repo, commit, 'secure-v1.0.0', pathlib.Path(tmp) / 'two')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                names = archive.getnames()
                self.assertFalse(any(n.endswith('.env') for n in names))
                prefix = '3X-UI_KIT-secure-v1.0.0/'
                data = archive.extractfile(prefix + 'scripts/example.sh').read()
                self.assertEqual(data, b'#!/bin/bash\necho safe\n')
                manifest = archive.extractfile(prefix + 'SHA256SUMS').read().decode()
                self.assertEqual(manifest, hashlib.sha256(data).hexdigest() + '  scripts/example.sh\n')
            (repo / 'secret.env').write_text('dummy')
            git('add', 'secret.env')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'unsafe fixture')
            with self.assertRaises(ValueError):
                module.build(repo, 'HEAD', 'secure-v1.0.0', pathlib.Path(tmp) / 'refused')

if __name__ == '__main__':
    unittest.main()
