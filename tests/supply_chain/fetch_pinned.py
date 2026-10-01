#!/usr/bin/env python3
"""Fetch reviewed upstream inputs for safe tests; never execute dependencies.
Usage: python -B tests/supply_chain/fetch_pinned.py CACHE_DIRECTORY
"""
import importlib.util
import json
import pathlib
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('supply_chain', ROOT / 'scripts/supply-chain.py')
assert spec and spec.loader
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    cache = pathlib.Path(sys.argv[1]).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / 'scripts/supply-chain.lock.json').read_text(encoding='utf-8'))
    for name, pin in lock['assets'].items():
        artifact = cache / name
        if not artifact.is_file() or sc.sha256(artifact) != pin['sha256']:
            sc.download_asset(lock, name, cache)
        print(name, pin['sha256'])
    with tarfile.open(cache / 'acme.tar.gz') as archive:
        member = archive.getmember('acme.sh-' + lock['acme_commit'] + '/acme.sh')
        if not member.isfile():
            raise ValueError('ACME source is not a regular file')
        source = archive.extractfile(member)
        assert source is not None
        with source:
            (cache / 'acme.sh').write_bytes(source.read())


if __name__ == '__main__':
    main()
