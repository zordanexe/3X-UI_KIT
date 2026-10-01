#!/usr/bin/env python3
"""Offline, redacted secret scanner. No network, dependencies, or execution of source.

Exit 0: no unsuppressed candidates; 1: candidates; 2: incomplete/error.
Rules identify candidates, not credential validity. --history scans local reachable
Git blobs as well as the current tracked/untracked, non-ignored working tree.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

MAX_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 512
MAX_DEPTH = 4

# Immutable upstream examples reviewed for RFC 5737/example.com endpoints.
# Changing even one byte (other than CRLF) invalidates the exemption; no test
# directory is globally ignored. Provenance: docs/EXTERNAL_CONNECTIONS.md.
REVIEWED_FIXTURES = {
    # Added regression harness: SYNTHETIC_* sentinels, example.invalid only;
    # locally generated test, never copied from credentials or a live server.
    'tests/test_kit_sub_integration.py': {'98b7d90f8cecb443b6dc73fa19e3885557827f981cd0771b41e6051ae4ab1a26'},
    'tools/test/links.test.js': {
        # Same reviewed RFC5737/example.com fixtures; only dummy SHA256 pins
        # expanded to the required 32-byte format for parser compatibility.
        'a2c4665d63e45a9df2ef7b7c6d2a9a65ac15a6ba322689286a195ece78ea198e',
        '503016d991991662f396868c8538b57e2351897188516a2ce48f194d3e7f0de9',
        'd23b97bb882c5c0eae8ebdade73460ca2ff5d9edfc6725ce4a03c8d2c217b6d9',
        'ed2a85357b9aeb8d63685c36bee7469a7189f8ea7d3f2e17dc550f294688c75d',
    },
    'manuals/assets/script-hy2-add.svg': {'bb734196ae6339afdeaf8d93aba2db22e6fc56ae9af199d96120f127634ac3da'},
    'manuals/assets/script-hysteria2.svg': {
        '0917093aac37b18fd3cb04d9716360b0377d69527d57c7d7f8eb84d6043c154d',
        'e3f12166ffdb65718d2f21bce06e3f763c799200681589aaa24ce5299af99bb9',
    },
    'manuals/assets/script-3x-ui.svg': {
        '2613237f31b1c3bc62a066203ad2d7207d575f597c39773ac23957639624e64b',
        '29fda2389babfbbf42f2f91c4328599a3ba87125e05850c3eb89af4afc5b7fab',
        '506f1137ae9fa5d0129e5dec50e26b214d9780113fff6ff203a038eaf9e4029d',
        '5c85aa51a51dfb4fc27f8eaa454070a7271c5a9e5cc6c2543157599a11579a3c',
        'cfafa90033526fe7d439d4a6b82ef6a8eb1ac552ad271fa17079cf843c268c61',
    },
}


def reviewed_fixture(path, data):
    relative = path.split(':', 2)[-1] if path.startswith('history:') else path
    digest = hashlib.sha256(data.replace(b'\r\n', b'\n')).hexdigest()
    return digest in REVIEWED_FIXTURES.get(relative, set())


RULES = {
    "openai-key": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b"),
    "anthropic-key": re.compile(r"\bsk-ant-api\d+-[A-Za-z0-9_-]{40,}\b"),
    "bearer-token": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    "credential-query": re.compile(r'''(?i)[?&](?:token|secret|password|api_key|apikey|access_token)=[A-Za-z0-9_%+./=-]{8,}'''),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "google-api-key": re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "stripe-secret": re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    "telegram-bot-token": re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
}


ASSIGNMENT = re.compile(
    r'''(?i)(?<![\w.-])["']?(?:[a-z_][a-z0-9_]*[_-])?'''
    r'''(?:password|passwd|pwd|token|secret|api[_-]?key|client[_-]?secret|private[_-]?key|preshared[_-]?key|secret[_-]?access[_-]?key|secretkey|headerprotectionkey)["']?'''
    r'''\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([A-Za-z0-9+/=_-]{4,})(?=\s*(?:$|[,#;\r\n])))''', re.M)
CREDENTIAL_URI = re.compile(r'''(?i)\b(https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|vless|trojan|hy2|hysteria2|tuic|ss|wg|wireguard)://([^\s"'<>/@]+)@[^\s"'<>]+''')


def literal(value):
    if value.lower() in {'[redacted]', '***'}:
        return False
    if len(value) < 4 or any(c in value for c in "$<>\\\n"):
        return False
    if value.lower() in {"none", "null", "true", "false", "changeme", "redacted", "example", "placeholder", "synthetic", "your_password", "your_token"}:
        return False
    # Source references are not literal credentials.
    if re.fullmatch(r"(?:[A-Za-z_$][\w$]*\.)+[\w$]+(?:\([^)]*\))?", value):
        return False
    if value.endswith("()"):
        return False
    return True


def scan_text(text, path):
    """Return metadata only: never matched text, a prefix, or surrounding source."""
    findings = []
    for rule, pattern in RULES.items():
        for match in pattern.finditer(text):
            if rule == 'credential-query' and match.group().split('=', 1)[-1] == 'synthetic':
                continue  # explicitly non-live test marker, not a test-path exemption
            findings.append({"path": path, "line": text.count("\n", 0, match.start()) + 1, "rule": rule})
    for match in ASSIGNMENT.finditer(text):
        value = next(v for v in match.groups() if v is not None)
        source_file = Path(path.split("!", 1)[-1]).suffix in {".js", ".py"}
        source_expression = match.group(3) is not None and source_file
        mapped_name = re.sub(r"[-_]", "", value.lower()) in {"password", "secret", "privatekey", "headerprotectionkey", "presharedkey"}
        if literal(value) and not source_expression and not mapped_name and not value.startswith(("/", "./")) and "' +" not in value and value not in {"ghp_", "github_pat_"}:
            findings.append({"path": path, "line": text.count("\n", 0, match.start()) + 1, "rule": "literal-credential"})
    for match in CREDENTIAL_URI.finditer(text):
        scheme, value = match.groups()
        if scheme.lower() in {'http', 'https', 'postgres', 'postgresql', 'mysql', 'mongodb', 'mongodb+srv', 'redis'} and ':' not in value:
            continue  # username alone, or a CDN revision path, is not a password
        relative = path.split(':', 2)[-1] if path.startswith('history:') else path
        digest = hashlib.sha256(value.encode()).hexdigest()
        reviewed_value = relative == 'tests/test_kit_sub.py' and digest == 'c91b1d6acd383c44c4ec20c9723e758c31182a1f4f0231d63d91259a2ea14b9d'
        if literal(value) and not reviewed_value:
            findings.append({"path": path, "line": text.count("\n", 0, match.start()) + 1, "rule": "credential-uri"})
    for match in re.finditer(r'\b(vpn|vmess|ss)://([A-Za-z0-9_+/=-]{16,})', text):
        try:
            raw = match.group(2)
            decoded = base64.b64decode(raw + '=' * (-len(raw) % 4), altchars=b'-_', validate=True).decode('utf-8')
            sensitive = bool(scan_text(decoded, path))
            if match.group(1) == 'vmess':
                payload = json.loads(decoded)
                sensitive = isinstance(payload, dict) and bool(payload.get('id'))
            elif match.group(1) == 'ss':
                sensitive = ':' in decoded
            if sensitive:
                findings.append({"path": path, "line": text.count("\n", 0, match.start()) + 1, "rule": "encoded-proxy-credential"})
        except (ValueError, UnicodeError, RecursionError):
            pass
    return findings


def scan_blob(data, path, depth=0):
    """Inspect supported archives in memory, never unpack paths or execute payloads."""
    findings, errors = [], []
    if len(data) > MAX_BYTES or depth > MAX_DEPTH:
        return [], [{"path": path, "reason": "scan-limit"}]
    try:
        if data.startswith(b'PK\x03\x04') or path.lower().endswith('.zip'):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if len(members) > MAX_MEMBERS or sum(m.file_size for m in members) > MAX_BYTES:
                    raise ValueError('archive limit')
                for member in members:
                    if member.is_dir():
                        continue
                    child = path + '!' + member.filename
                    if member.file_size > MAX_BYTES or member.flag_bits & 1:
                        errors.append({"path": child, "reason": "encrypted-or-oversized-archive"})
                        continue
                    with archive.open(member) as stream:
                        blob = stream.read(MAX_BYTES + 1)
                    hits, failures = scan_blob(blob, child, depth + 1)
                    findings.extend(hits); errors.extend(failures)
        elif data.startswith(b'\x1f\x8b') or path.lower().endswith(('.gz', '.tgz')):
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                blob = stream.read(MAX_BYTES + 1)
            hits, failures = scan_blob(blob, path + '!.tar' if path.lower().endswith(('.tar.gz', '.tgz')) else path + '!gzip', depth + 1)
            findings.extend(hits); errors.extend(failures)
        elif path.lower().endswith('.tar') or data[257:262] == b'ustar':
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                total = 0
                for number, member in enumerate(archive):
                    total += member.size
                    if number >= MAX_MEMBERS or total > MAX_BYTES:
                        raise ValueError('archive limit')
                    if not member.isfile():
                        if not member.isdir():
                            errors.append({"path": path, "reason": "archive-link-or-special-file"})
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError('unreadable member')
                    with stream:
                        blob = stream.read(MAX_BYTES + 1)
                    hits, failures = scan_blob(blob, path + '!' + member.name, depth + 1)
                    findings.extend(hits); errors.extend(failures)
        else:
            encoding = 'utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8'
            findings.extend(scan_text(data.decode(encoding, 'replace'), path))
            if path.lower().endswith(('.7z', '.rar', '.p12', '.pfx', '.db', '.sqlite', '.sqlite3')):
                errors.append({"path": path, "reason": "manual-binary-review-required"})
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, tarfile.TarError, EOFError):
        errors.append({"path": path, "reason": "archive-invalid-or-scan-limit"})
    return findings, errors


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)


def files(root):
    def generated(name):
        return '__pycache__' in Path(name).parts
    if (root / ".git").exists():
        tracked = set(git(root, 'ls-files', '-z', '--cached').decode('utf-8').split('\0')) - {''}
        others = set(git(root, 'ls-files', '-z', '--others', '--exclude-standard').decode('utf-8').split('\0')) - {''}
        return sorted(tracked | {name for name in others if not generated(name)})
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts and not generated(p.relative_to(root).as_posix()))


def run(root, history=False):
    if not root.is_dir():
        raise ValueError('invalid root')
    findings, errors = [], []
    count = 0
    reviewed = 0
    for name in files(root):
        path = root / name
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise ValueError("outside scope")
            if path.stat().st_size > MAX_BYTES:
                errors.append({"path": name, "reason": "scan-limit"})
                continue
            data = path.read_bytes()
            if reviewed_fixture(name, data):
                reviewed += 1
            else:
                hits, failures = scan_blob(data, name)
                findings.extend(hits); errors.extend(failures)
            count += 1
        except (OSError, ValueError):
            errors.append({"path": name, "reason": "unreadable-or-outside-scope"})
    blobs = 0
    if history:
        objects = git(root, "rev-list", "--objects", "--all").decode("utf-8", "replace").splitlines()
        for item in objects:
            oid, _, name = item.partition(" ")
            if git(root, "cat-file", "-t", oid).strip() != b"blob":
                continue
            if int(git(root, "cat-file", "-s", oid)) > MAX_BYTES:
                errors.append({"path": "history:" + oid[:12] + ":" + name, "reason": "scan-limit"})
                continue
            data = git(root, "cat-file", "blob", oid)
            label = "history:" + oid[:12] + ":" + name
            if reviewed_fixture(label, data):
                reviewed += 1
            else:
                hits, failures = scan_blob(data, label)
                findings.extend(hits); errors.extend(failures)
            blobs += 1
    findings = sorted({(h['path'], h['line'], h['rule']) for h in findings})
    return {"files_scanned": count, "history_blobs_scanned": blobs, "reviewed_fixture_files": reviewed,
            "findings": [dict(zip(('path', 'line', 'rule'), h)) for h in findings], "errors": errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = run(args.root.resolve(), args.history)
    except (OSError, ValueError, subprocess.SubprocessError):
        report = {"files_scanned": 0, "history_blobs_scanned": 0, "reviewed_fixture_files": 0, "findings": [], "errors": [{"reason": "scan-failed"}]}
    if args.json:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    else:
        for hit in report["findings"]:
            print(f'{hit["path"]}:{hit["line"]}: {hit["rule"]} [REDACTED]')
        print(f'Scanned {report["files_scanned"]} files, {report["history_blobs_scanned"]} history blobs; {len(report["findings"])} candidates, {len(report["errors"])} errors.')
    return 2 if report["errors"] else 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
