#!/usr/bin/env bash
# Offline verification only. Never runs production entrypoints or matrix clients.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
case "${1:-}" in
  "") SCAN_ARGS=() ;;
  --history) SCAN_ARGS=(--history) ;;
  *) printf '%s\n' 'Usage: bash scripts/security-check.sh [--history]' >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { printf '%s\n' 'Too many arguments' >&2; exit 2; }
if [[ -n ${PYTHON:-} ]]; then PY=$PYTHON
elif command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else printf '%s\n' 'Python 3.9+ is required' >&2; exit 2; fi
if [[ -n ${NODE:-} ]]; then JS=$NODE
elif command -v node >/dev/null 2>&1; then JS=node
elif command -v node.exe >/dev/null 2>&1; then JS=node.exe
else printf '%s\n' 'Node.js 18+ is required' >&2; exit 2; fi
export PYTHONDONTWRITEBYTECODE=1
printf '%s\n' 'Bash syntax (no execution)'
for file in scripts/*.sh tests/matrix/*.sh; do bash -n "$file"; done
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck scripts/*.sh tests/matrix/*.sh
else
  printf '%s\n' 'NOT_TESTED: ShellCheck is not installed (no automatic installation).'
fi
printf '%s\n' 'Python syntax (compile in memory; no imports, no bytecode files)'
"$PY" -B -c 'from pathlib import Path; files = sorted(Path("scripts").glob("*.py")) + sorted(Path("tests").rglob("*.py")); [compile(p.read_text(encoding="utf-8-sig"), str(p), "exec") for p in files]; print("Parsed", len(files), "Python files")'
printf '%s\n' 'JavaScript syntax and inspected offline tests'
for file in tools/lib/*.js tools/test/*.js tests/matrix/*.js tests/security*.test.js; do "$JS" --check "$file"; done
"$JS" --test tools/test/links.test.js tests/security*.test.js
"$PY" -B -m unittest discover -s tests -p 'security_scan_test.py' -v
"$PY" -B -W error::ResourceWarning -m unittest discover -s tests -p 'test_*.py' -v
"$PY" -B -m unittest discover -s tests/supply_chain -p 'test_*.py' -v
printf '%s\n' 'Offline secret candidates (values always redacted)'
"$PY" -B scripts/security_scan.py "${SCAN_ARGS[@]}"
printf '%s\n' 'PASS: offline checks completed; live installation/protocol matrix was not run.'
