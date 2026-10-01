#!/usr/bin/env python3
"""Pinned downloads and verified local release bundles. Never runs installers."""
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import urllib.parse


def sha256(path):
    with pathlib.Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _hash_stream(stream)


def _hash_stream(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
    return digest.hexdigest()


def fetch(url, expected, target):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in
            ('github.com', 'raw.githubusercontent.com', 'codeload.github.com') or
            parsed.username or parsed.password or parsed.port not in (None, 443) or
            not re.fullmatch(r'[0-9a-f]{64}', expected)):
        raise ValueError('HTTPS URL and pinned SHA256 required')
    target = pathlib.Path(target)
    fd, part = tempfile.mkstemp(prefix='.download-', dir=target.parent)
    os.close(fd)
    try:
        subprocess.run(['curl', '--disable', '--fail', '--silent', '--show-error', '--location',
                        '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
                        '--retry', '3', '--connect-timeout', '20', '--max-time', '600',
                        '--output', part, url], check=True)
        if sha256(part) != expected:
            raise ValueError('download checksum mismatch')
        os.replace(part, target)
    finally:
        if os.path.exists(part):
            os.unlink(part)
    return target


REQUIRED = {'scripts/3x-ui.sh', 'scripts/hysteria2.sh', 'scripts/kit.sh',
            'scripts/kit-sub.py', 'scripts/supply-chain.py', 'scripts/supply-chain.lock.json'}


def verify_bundle(root):
    root = pathlib.Path(root).resolve()
    manifest = root / 'SHA256SUMS'
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError('missing regular SHA256SUMS')
    entries = {}
    for line in manifest.read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./-]+)', line)
        if not match:
            raise ValueError('malformed bundle manifest')
        digest, name = match.groups()
        parts = pathlib.PurePosixPath(name).parts
        if (name in entries or name == 'SHA256SUMS' or name.startswith('/') or
                any(p in ('.', '..') for p in name.split('/'))):
            raise ValueError('unsafe or duplicate bundle path')
        file = root.joinpath(*parts)
        if any(root.joinpath(*parts[:i]).is_symlink() for i in range(1, len(parts) + 1)):
            raise ValueError('symlink in bundle')
        if not file.is_file() or sha256(file) != digest:
            raise ValueError('bundle checksum mismatch: ' + name)
        entries[name] = digest
    if not REQUIRED.issubset(entries):
        raise ValueError('missing required bundle files')
    for file in root.rglob('*'):
        if file.is_symlink():
            raise ValueError('symlink in bundle')
        if file.is_file() and file != manifest and file.relative_to(root).as_posix() not in entries:
            raise ValueError('unlisted bundle file: ' + file.relative_to(root).as_posix())
    return entries


def persist_bundle(root, base):
    root = pathlib.Path(root).resolve()
    entries = verify_bundle(root)
    base = pathlib.Path(base)
    base.mkdir(parents=True, exist_ok=True, mode=0o755)
    destination = base / sha256(root / 'SHA256SUMS')
    if destination.exists():
        if destination.is_symlink() or sha256(destination / 'SHA256SUMS') != destination.name:
            raise ValueError('existing snapshot content address mismatch')
        verify_bundle(destination)
        return destination
    stage = pathlib.Path(tempfile.mkdtemp(prefix='.bundle-', dir=base))
    try:
        for name in (*entries, 'SHA256SUMS'):
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            shutil.copyfile(root / name, target)
            target.chmod(0o755 if name.endswith('.sh') else 0o644)
        verify_bundle(stage)
        stage.rename(destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return destination


def function_body(text, name):
    match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', text, re.M | re.S)
    if not match:
        raise ValueError('upstream function missing: ' + name)
    return match.group()


def replace_function(text, name, body):
    return text.replace(function_body(text, name), name + '() {\n' + body + '\n}', 1)


def replace_exact(text, old, new, count=1):
    if text.count(old) != count:
        raise ValueError('upstream adapter context changed')
    return text.replace(old, new)


def check_source(text, lock, name):
    if hashlib.sha256(text.encode('utf-8')).hexdigest() != lock['assets'][name]['sha256']:
        raise ValueError('upstream source checksum mismatch: ' + name)


def adapt_installer(text, lock):
    check_source(text, lock, 'xui-install.sh')
    text = replace_function(text, 'install_acme', '''    (cd "$SC_ASSETS/acme-source" && AUTO_UPGRADE=0 sh ./acme.sh --install --home /root/.acme.sh --no-profile) || return 1
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade 0''')
    text = replace_exact(text, 'curl -s https://get.acme.sh | sh', 'install_acme')
    text = replace_exact(text, '~/.acme.sh/acme.sh --upgrade --auto-upgrade', '~/.acme.sh/acme.sh --upgrade --auto-upgrade 0', count=3)
    text = replace_function(text, 'install_tuic_server', '''    # TUIC is authenticated inside the pinned release archive.
    # Architectures without bundled TUIC remain unsupported upstream.
    return 0''')
    text = replace_function(text, 'resolve_latest_tag', '    printf "%s\\n" "' + lock['xui_version'] + '"')
    text = replace_function(text, 'verify_release_checksum', '    return 0 # resources were verified before this offline installer was prepared')
    text = replace_function(text, 'require_repo_files', '''    shift
    local name
    for name in "$@"; do [[ -s "$SC_ASSETS/$name" ]] || exit 1; done''')
    start = text.index('    # Download resources\n', text.index('install_x-ui()'))
    end = text.index('    local xui_script_temp=', start)
    text = text[:start] + '''    # All executable resources were verified up front.
    tag_version="''' + lock['xui_version'] + '''"
    local script_ref="''' + lock['xui_commit'] + '''"
    cp "$SC_ASSETS/x-ui-linux-$(arch).tar.gz" "${xui_folder}-linux-$(arch).tar.gz" || exit 1
''' + text[end:]
    text = replace_exact(text, 'curl -fLRo "${xui_script_temp}" "https://raw.githubusercontent.com/MHSanaei/3x-ui/${script_ref}/x-ui.sh"', 'cp "$SC_ASSETS/x-ui.sh" "${xui_script_temp}"')
    text = replace_exact(text, 'curl -fLRo "${xui_rc_temp}" "https://raw.githubusercontent.com/MHSanaei/3x-ui/${script_ref}/x-ui.rc"', 'cp "$SC_ASSETS/x-ui.rc" "${xui_rc_temp}"')
    text = replace_exact(text, 'curl -fLRo "$temp_file" "$source" > /dev/null 2>&1', 'cp "$SC_ASSETS/${source##*/}" "$temp_file" > /dev/null 2>&1')
    text = replace_exact(text, '    chmod +x x-ui.sh', '    cp "$SC_ASSETS/x-ui.sh" x-ui.sh || exit 1\n    chmod +x x-ui.sh')
    text = replace_exact(text, 'install_base\ninstall_x-ui $1', '''# Replace existing ACME code too, retaining account/certificate state.
install_acme || exit 1
install_base
install_x-ui "$1"''')
    return text


def adapt_menu(text, lock):
    check_source(text, lock, 'x-ui.sh')
    refusal = '    echo "Use a new verified 3X-UI KIT release bundle; unpinned downloads are disabled." >&2\n    return 1'
    for name in ('install', 'update', 'update_dev', 'replace_xui_script',
                 'installed_script_url', 'update_menu', 'legacy_version'):
        text = replace_function(text, name, refusal)
    text = replace_function(text, 'install_acme', '    [[ -x /root/.acme.sh/acme.sh ]] || { echo "Pinned ACME missing; reinstall verified bundle." >&2; return 1; }')
    text = replace_function(text, 'run_speedtest', '    command -v speedtest >/dev/null || { echo "Install speedtest via a trusted OS repository first." >&2; return 1; }\n    speedtest')
    text = replace_exact(text, '~/.acme.sh/acme.sh --upgrade --auto-upgrade', '~/.acme.sh/acme.sh --upgrade --auto-upgrade 0', count=3)
    text = replace_exact(text, 'bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)', 'bash ./scripts/3x-ui.sh (from a verified 3X-UI KIT release bundle)')
    return text


def adapt_acme(text):
    # Cron renews certificates but never fetches new code.
    text = replace_function(text, 'installOnline', '  _err "Online code installation disabled; use a verified KIT bundle."\n  return 1')
    return replace_function(text, 'upgrade', '''  _initpath || return 1
  AUTO_UPGRADE=0
  _saveaccountconf "AUTO_UPGRADE" "0"
  return 0 # Code upgrades require a newly verified KIT bundle.''')


def extract_tar(archive, destination, prefix):
    import tarfile
    destination = pathlib.Path(destination)
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        seen = set()
        for member in members:
            name = member.name.rstrip('/')
            parts = name.split('/')
            if (not name or name in seen or parts[0] != prefix or
                    any(p in ('', '.', '..') for p in parts) or
                    not (member.isfile() or member.isdir())):
                raise ValueError('unsafe archive member: ' + member.name)
            seen.add(name)
        for member in members:
            target = destination.joinpath(*member.name.rstrip('/').split('/'))
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, target.open('xb') as out:
                    shutil.copyfileobj(source, out)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return destination / prefix


XRAY_ASSETS = {'amd64': 'Xray-linux-64.zip', '386': 'Xray-linux-32.zip',
               'arm64': 'Xray-linux-arm64-v8a.zip', 'armv5': 'Xray-linux-arm32-v5.zip',
               'armv6': 'Xray-linux-arm32-v6.zip', 'armv7': 'Xray-linux-arm32-v7a.zip',
               's390x': 'Xray-linux-s390x.zip'}


def download_asset(lock, name, destination):
    asset = lock['assets'][name]
    path = pathlib.Path(destination) / name
    fetch(asset['url'], asset['sha256'], path)
    # Recheck even injected/test download transports; nothing executes here.
    if sha256(path) != asset['sha256']:
        raise ValueError('asset checksum mismatch: ' + name)
    return path


def prepare_xui(lock, destination, arch):
    import tarfile
    if arch not in XRAY_ASSETS:
        raise ValueError('unsupported architecture')
    destination = pathlib.Path(destination)
    names = ('xui-install.sh', 'x-ui.sh', 'x-ui.rc', 'x-ui.service.debian',
             'x-ui.service.arch', 'x-ui.service.rhel', 'acme.tar.gz',
             'x-ui-linux-' + arch + '.tar.gz')
    for name in names:
        download_asset(lock, name, destination)
    # Validate the authenticated archive's member types and paths before upstream tar.
    with tarfile.open(destination / names[-1]) as archive:
        members = archive.getmembers()
        if not any(m.name == 'x-ui/x-ui' and m.isfile() for m in members):
            raise ValueError('panel archive missing binary')
        seen = set()
        for member in members:
            name = member.name.rstrip('/')
            if (name in seen or name.split('/')[0] != 'x-ui' or
                    any(p in ('', '.', '..') for p in name.split('/')) or
                    not (member.isfile() or member.isdir())):
                raise ValueError('unsafe panel archive member')
            seen.add(name)
    acme = extract_tar(destination / 'acme.tar.gz', destination / 'acme-extract',
                       'acme.sh-' + lock['acme_commit'])
    acme.rename(destination / 'acme-source')
    script = destination / 'acme-source/acme.sh'
    script.write_text(adapt_acme(script.read_text(encoding='utf-8')), encoding='utf-8', newline='\n')
    menu = destination / 'x-ui.sh'
    menu.write_text(adapt_menu(menu.read_text(encoding='utf-8'), lock), encoding='utf-8', newline='\n')
    installer = destination / 'install-verified.sh'
    installer.write_text(adapt_installer((destination / 'xui-install.sh').read_text(encoding='utf-8'), lock), encoding='utf-8', newline='\n')
    return installer


def prepare_xray(lock, destination, arch):
    import zipfile
    if arch not in XRAY_ASSETS:
        raise ValueError('unsupported architecture')
    archive = download_asset(lock, XRAY_ASSETS[arch], destination)
    output = pathlib.Path(destination) / 'xray'
    with zipfile.ZipFile(archive) as z:
        entries = [entry for entry in z.infolist() if entry.filename == 'xray']
        if (len(entries) != 1 or entries[0].is_dir() or
                entries[0].file_size > 100 * 1024 * 1024 or
                (entries[0].external_attr >> 16) & 0o170000 == 0o120000):
            raise ValueError('invalid Xray binary archive')
        with z.open(entries[0]) as source, output.open('xb') as out:
            shutil.copyfileobj(source, out)
    output.chmod(0o755)
    return output


def main():
    import argparse, json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('verify', 'persist', 'prepare-xui', 'prepare-xray', 'hysteria'))
    parser.add_argument('root', type=pathlib.Path)
    parser.add_argument('destination', nargs='?', type=pathlib.Path)
    parser.add_argument('arch', nargs='?')
    args = parser.parse_args()
    verify_bundle(args.root)
    if args.command == 'verify':
        return
    if args.destination is None:
        parser.error('destination required')
    if args.command == 'persist':
        print(persist_bundle(args.root, args.destination))
        return
    lock = json.loads((args.root / 'scripts/supply-chain.lock.json').read_text(encoding='utf-8'))
    if args.command == 'prepare-xui':
        print(prepare_xui(lock, args.destination, args.arch))
    elif args.command == 'prepare-xray':
        print(prepare_xray(lock, args.destination, args.arch))
    elif args.command == 'hysteria':
        if args.arch not in ('amd64', 'arm64'):
            raise ValueError('unsupported Hysteria architecture')
        print(download_asset(lock, 'hysteria-linux-' + args.arch, args.destination))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit('Supply-chain verification failed: ' + str(error)) from None
