#!/usr/bin/env python3
"""Build deterministic source-only release from exact Git objects, never local configs."""
import argparse
import gzip
import hashlib
import io
import pathlib
import re
import subprocess
import tarfile


def build(repo, revision, tag, output):
    repo, output = pathlib.Path(repo), pathlib.Path(output)
    if not re.fullmatch(r'secure-v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('invalid release tag')
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)
    commit = git('rev-parse', '--verify', revision + '^{commit}').decode().strip()
    records = git('ls-tree', '-rz', '--full-tree', commit).split(b'\0')
    files = {}
    modes = {}
    for record in filter(None, records):
        metadata, raw_name = record.split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        name = raw_name.decode('utf-8')
        parts = name.split('/')
        if (kind != 'blob' or mode not in ('100644', '100755') or
                not re.fullmatch(r'[A-Za-z0-9_./-]+', name) or
                any(p in ('', '.', '..') for p in parts) or
                any(p == '.git' or p == '.env' or p.endswith(('.env', '.pem', '.key', '.p12', '.pfx')) for p in parts)):
            raise ValueError('unsafe release member: ' + name)
        if name == 'SHA256SUMS':
            continue  # generated from exact release files, never self-hashed
        data = git('cat-file', 'blob', oid)
        if name.endswith(('.sh', '.py', '.js', '.json')) and b'\r\n' in data:
            raise ValueError('release source must use LF: ' + name)
        files[name] = data
        modes[name] = 0o755 if name.endswith('.sh') else 0o644
    manifest = ''.join(hashlib.sha256(files[name]).hexdigest() + '  ' + name + '\n' for name in sorted(files))
    files['SHA256SUMS'] = manifest.encode('utf-8')
    modes['SHA256SUMS'] = 0o644
    if output.exists() and any(output.iterdir()):
        raise ValueError('release output directory must be empty')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / ('3X-UI_KIT-' + tag + '.tar.gz')
    if archive.exists():
        raise ValueError('refusing to overwrite release archive')
    prefix = '3X-UI_KIT-' + tag + '/'
    with archive.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                for name, data in sorted(files.items()):
                    info = tarfile.TarInfo(prefix + name)
                    info.size, info.mode, info.mtime = len(data), modes[name], 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    tar.addfile(info, io.BytesIO(data))
    for name in ('3x-ui.sh', 'kit-sub.py', 'kit.sh', 'hysteria2.sh'):
        source = 'scripts/' + name
        if source in files:
            (output / name).write_bytes(files[source])
    assets = sorted(p for p in output.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
    (output / 'SHA256SUMS').write_bytes(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in assets).encode())
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='.')
    parser.add_argument('--revision', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    print(build(args.repo, args.revision, args.tag, args.output))
