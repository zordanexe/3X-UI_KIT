#!/usr/bin/env bash
# 3X-UI со всеми протоколами одной командой — https://github.com/itsnotkubrick/3X-UI_KIT
#
# Установка: bash ./scripts/3x-ui.sh из проверенного release bundle secure-v1.0.0 (см. README).
#
# Ставит официальную панель 3X-UI (версия закреплена ниже) её собственным
# установщиком, получает сертификат Let's Encrypt на IP, создаёт подключения
# REALITY, XHTTP, VLESS/VMess WS, Trojan gRPC, Shadowsocks 2022, Hysteria2, TUIC,
# AmneziaWG (классика и 3.1) и MTProto (и WireGuard по запросу), включает единую подписку
# с форматом под каждый клиент и настраивает ufw. Домены не нужны.
# Каждый протокол проверен настоящими клиентами — см. tests/matrix.

set -Eeuo pipefail

# Only run scripts from an operator-authenticated release bundle (see README).
# This shell gate checks the helper before Python can execute it.
supply_chain_bootstrap() {
  local src file expected
  src=$(readlink -f -- "${BASH_SOURCE[0]}") || { printf '%s\n' 'Cannot resolve bundle script.' >&2; return 1; }
  [[ -f $src && $src != /dev/* && $src != /proc/* ]] || { printf '%s\n' 'Use an extracted verified release bundle, not curl | bash.' >&2; return 1; }
  KIT_BUNDLE_ROOT=$(cd -- "$(dirname -- "$src")/.." && pwd -P)
  [[ -f $KIT_BUNDLE_ROOT/SHA256SUMS && ! -L $KIT_BUNDLE_ROOT/SHA256SUMS && ! -L $KIT_BUNDLE_ROOT/scripts ]] || { printf '%s\n' 'Missing regular bundle SHA256SUMS.' >&2; return 1; }
  for file in 3x-ui.sh hysteria2.sh kit.sh kit-sub.py supply-chain.py supply-chain.lock.json; do
    [[ -f $KIT_BUNDLE_ROOT/scripts/$file && ! -L $KIT_BUNDLE_ROOT/scripts/$file ]] || return 1
    expected=$(awk -v f="scripts/$file" '$2 == f {n++; h=$1} END {if(n != 1 || length(h) != 64 || h ~ /[^0-9a-f]/) exit 1; print h}' "$KIT_BUNDLE_ROOT/SHA256SUMS") || return 1
    [[ $(sha256sum "$KIT_BUNDLE_ROOT/scripts/$file" | cut -d ' ' -f1) == "$expected" ]] || { printf '%s\n' 'Bundle checksum mismatch.' >&2; return 1; }
  done
  (cd -- "$KIT_BUNDLE_ROOT" && sha256sum --check --strict --quiet SHA256SUMS) || return 1
}
supply_chain_bootstrap || exit 1
sc() { python3 -I "$KIT_BUNDLE_ROOT/scripts/supply-chain.py" "$@"; }

XUI_VERSION="v3.8.5"
# Ядро Xray для панели. С 26.7.x клиенты на Mihomo и sing-box (Hiddify, FlClash,
# Clash Verge, Mihomo в XKeen) не проходят REALITY — проверено 2026-09-25.
# 26.6.27 — последняя версия, с которой работают все клиенты и которую принимает 3X-UI.
XRAY_CORE="v26.6.27"
XUI_REPO="MHSanaei/3x-ui"
RESULT=/root/3x-ui.txt
XUI_ENV=/etc/x-ui/install-result.env
# Сайты для маскировки REALITY: нужны TLS 1.3 и HTTP/2. Берём первый доступный.
# Apple, iCloud, Microsoft и домены .ru сам Xray не советует — их тут нет.
SNI_CANDIDATES=(dl.google.com www.amazon.com www.samsung.com www.yahoo.com)

ALL_PROTOS=(reality hy2 xhttp ws trojan vmess ss tuic wg awg awg3 mtproto)
# Обычный WireGuard в России режет DPI (проверено 2026-09-27: рукопожатие доходит до сервера,
# ответ — нет), а его попытки могут привлечь блокировку IP. По умолчанию не ставим.
DEFAULT_PROTOS=(reality hy2 xhttp ws trojan vmess ss tuic awg awg3 mtproto)
declare -A PORTS=([xhttp]=8443 [ws]=2053 [trojan]=2083 [vmess]=2087 [ss]=8388 [tuic]=8444 [wg]=51820 [awg]=51821 [awg3]=51822 [mtproto]=8445)
PROTOS=(); CREATED=(); OPEN=()
# Режим «всё TCP на 443»: nginx разводит по SNI и путям, подключения слушают только localhost.
SINGLE=no
declare -A INNER=([reality]=10443 [xhttp]=10444 [mtproto]=10445 [web]=10446 [ws]=10451 [vmess]=10452 [trojan]=10453 [sub]=10460)
SNI2=""; SNI3=""

if [[ -t 1 ]]; then
  G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
else
  G=; Y=; R=; B=; D=; N=
fi
say()  { printf '%s\n' "${G}==>${N} $*"; }
warn() { printf '%s\n' "${Y}!${N}  $*" >&2; }
die()  { printf '%s\n' "${R}✗${N}  $*" >&2; exit 1; }
trap 'die "Ошибка в строке $LINENO. Исправьте причину и запустите скрипт ещё раз."' ERR

rand_str() { openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c "$1"; }
port_busy() { ss -H -ln"${2:0:1}" "sport = :$1" 2>/dev/null | grep -q .; }

xui_arch() {
  case "$(uname -m)" in
    x86_64|x64|amd64) echo amd64 ;;
    i*86|x86) echo 386 ;;
    armv8*|arm64|aarch64) echo arm64 ;;
    armv7*|arm) echo armv7 ;;
    armv6*) echo armv6 ;;
    armv5*) echo armv5 ;;
    s390x) echo s390x ;;
    *) die "Неподдерживаемая архитектура." ;;
  esac
}

public_ip() {
  local ip
  for u in https://api.ipify.org https://ifconfig.me/ip https://ipv4.icanhazip.com; do
    ip=$(curl -4 -fsS -m 6 "$u" 2>/dev/null | tr -d '[:space:]') || true
    [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { echo "$ip"; return; }
  done
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'
}

free_port() {
  local p
  for _ in $(seq 1 50); do
    p=$(shuf -i 20000-60000 -n 1)
    port_busy "$p" tcp || { echo "$p"; return; }
  done
  die "Не нашёл свободный порт для панели."
}

# REALITY маскируется под чужой сайт: он должен отвечать по TLS 1.3 и HTTP/2.
sni_ok() {
  echo | timeout 8 openssl s_client -connect "$1:443" -servername "$1" -tls1_3 -alpn h2 2>/dev/null \
    | grep -q 'ALPN protocol: h2'
}

# ---------- API панели ----------

api() { # METHOD path [json]
  local url="$API/$2" out
  if [[ $1 == GET ]]; then
    out=$(curl -fsSk -m 20 -H "Authorization: Bearer $TOKEN" "$url" 2>/dev/null) || die "Panel API transport failed"
  else
    out=$(curl -fsSk -m 20 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X "$1" -d "$3" "$url" 2>/dev/null) || die "Panel API transport failed"
  fi
  [[ $(jq -r '.success' <<<"$out" 2>/dev/null) == true ]] || die "Panel API request failed"
  jq -c '.obj' <<<"$out"
}

wait_panel() {
  local i
  for i in $(seq 1 60); do
    curl -fsk -m 5 -o /dev/null -H "Authorization: Bearer $TOKEN" "$API/server/getNewUUID" 2>/dev/null && return 0
    sleep 2
  done
  die "Панель не отвечает. Лог: journalctl -u x-ui -n 50"
}

# ---------- установка ----------

# Пасхалка — только в конце установки.
kit_banner() {
  echo
  printf '%s' "$G"
  cat <<'ART'
  _ _                   _   _          _          _      _
 (_) |_ ___ _ __   ___ | |_| | ___   _| |__  _ __(_) ___| | __
 | | __/ __| '_ \ / _ \| __| |/ / | | | '_ \| '__| |/ __| |/ /
 | | |_\__ \ | | | (_) | |_|   <| |_| | |_) | |  | | (__|   <
 |_|\__|___/_| |_|\___/ \__|_|\_\\__,_|_.__/|_|  |_|\___|_|\_\
ART
  printf '%s' "$N"
  echo
  echo "${B}3X-UI KIT${N} на основе панели 3X-UI (MHSanaei/3x-ui), ядра Xray и mihomo"
  echo
  echo "  https://github.com/itsnotkubrick/3X-UI_KIT"
  echo "  ${D}it's not Kubrick. it's just a VPN.${N}"
  echo
  echo "Данные для входа и подключения хранятся только в root-only файле."
}

# An upstream install-result.env is configuration, never code provenance.
resume_verified_xui() {
  # Reconstruct the authenticated adapters; never execute installed code to ask
  # for its version. Recognition is read-only and precedes administrative work.
  if ! (
    umask 077
    local tmp arch
    tmp=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$tmp"' EXIT
    arch=$(xui_arch) || exit 1
    sc prepare-xui "$KIT_BUNDLE_ROOT" "$tmp" "$arch" >/dev/null || exit 1
    sc prepare-xray "$KIT_BUNDLE_ROOT" "$tmp" "$arch" >/dev/null || exit 1
    python3 -I - "$tmp" "$arch" /usr/local/x-ui /usr/bin/x-ui /etc/systemd/system/x-ui.service /root/.acme.sh 2>/dev/null <<'PY'
import hashlib
import pathlib
import sys
import tarfile

stage, arch, panel, menu, service, acme = sys.argv[1:]
stage, panel, menu, service, acme = map(pathlib.Path, (stage, panel, menu, service, acme))


def regular(path):
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError('unsafe or missing installed code')
    return path


def digest(stream):
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        result.update(block)
    return result.digest()


def file_digest(path):
    with regular(path).open('rb') as stream:
        return digest(stream)


hardened_menu = file_digest(stage / 'x-ui.sh')
if any(file_digest(p) != hardened_menu for p in (menu, panel / 'x-ui.sh')):
    raise ValueError('unrecognized or unhardened menu')
units = {file_digest(stage / ('x-ui.service.' + distro)) for distro in ('debian', 'arch', 'rhel')}
pinned_xray = file_digest(stage / 'xray')
with tarfile.open(stage / ('x-ui-linux-' + arch + '.tar.gz')) as archive:
    for member in archive:
        if not member.isfile():
            continue
        name = pathlib.PurePosixPath(member.name).relative_to('x-ui').as_posix()
        if '.service' in name:
            with archive.extractfile(member) as stream:
                units.add(digest(stream))
        if not member.mode & 0o111 or name == 'x-ui.sh':
            continue
        installed_name = name
        if arch in ('armv5', 'armv6', 'armv7'):
            installed_name = name.replace('xray-linux-' + arch, 'xray-linux-arm32').replace('mtg-linux-' + arch, 'mtg-linux-arm')
        with archive.extractfile(member) as stream:
            allowed = {digest(stream)}
        # Resume both before and after this KIT's authenticated core replacement.
        if name.startswith('bin/xray-linux-'):
            allowed.add(pinned_xray)
        if file_digest(panel / installed_name) not in allowed:
            raise ValueError('unrecognized panel or sidecar binary')
if file_digest(service) not in units:
    raise ValueError('unrecognized service code')

# ACME installs these source files verbatim except for its documented Bash
# shebang rewrite. Executable root-managed configuration/renewal hooks retain
# their existing trust boundary; they are never used as provenance evidence.
def acme_equal(installed, expected):
    actual = regular(installed).read_bytes()
    wanted = expected.read_bytes()
    if actual == wanted:
        return True
    first, separator, body = actual.partition(b'\n')
    return (separator and first in (b'#!/bin/bash', b'#!/usr/bin/bash') and
            wanted.startswith(b'#!') and body == wanted.partition(b'\n')[2])

source = stage / 'acme-source'
for name in ('acme.sh', 'acme.sh.completion'):
    if not acme_equal(acme / name, source / name):
        raise ValueError('unrecognized or unhardened ACME')
for folder in ('dnsapi', 'deploy', 'notify'):
    installed = acme / folder
    expected = source / folder
    if installed.is_symlink() or not installed.is_dir():
        raise ValueError('unsafe or missing ACME hooks')
    if {p.name for p in installed.iterdir()} != {p.name for p in expected.iterdir()}:
        raise ValueError('unrecognized ACME hooks')
    for path in expected.iterdir():
        if not acme_equal(installed / path.name, path):
            raise ValueError('unrecognized ACME hook code')
PY
  ); then
    die "Resume refused: installed code is not a recognized pinned, hardened release, or verification is unavailable. If verification is unavailable, restore Python/network access and retry without removing state. Migration: for unrecognized code, stop x-ui and ACME renewal jobs; privately back up /etc/x-ui, /root/.acme.sh and /root/cert; manually remove the old /usr/local/x-ui, /usr/bin/x-ui and ACME code plus stale install-result.env (do not execute the legacy menu/uninstaller); install a newly authenticated KIT bundle and restore reviewed data only. Deleting only install-result.env is not a migration."
  fi
}

secure_xui_environment() {
  [[ -d /etc/x-ui && ! -L /etc/x-ui && -f $XUI_ENV && ! -L $XUI_ENV ]] || die "Unsafe installer state path"
  # Never bless a foreign-owned executable state file before sourcing it.
  [[ $(stat -c '%u' /etc/x-ui) == 0 && $(stat -c '%u' "$XUI_ENV") == 0 ]] || die "Installer state is not root-owned"
  install -d -o root -g root -m 0700 /etc/x-ui
  chown root:root "$XUI_ENV"
  chmod 0600 "$XUI_ENV"
}

write_install_result() {
  (
    set -e
    umask 077
    [[ ! -L $RESULT ]] || die "Unsafe result path"
    local result_tmp
    result_tmp=$(mktemp "${RESULT%/*}/.3x-ui-result.XXXXXXXX")
    trap 'rm -f -- "$result_tmp"' EXIT
    {
      echo "3X-UI KIT (3X-UI $XUI_VERSION) — данные для входа (файл виден только root)"
      echo
      echo "Панель:  $panel_url"
      echo "Логин:   $XUI_USERNAME"
      echo "Пароль:  $XUI_PASSWORD"
      echo
      [[ $TRUSTED == yes ]] && { echo "Подписка ($NAME) — все протоколы одной ссылкой:"; echo "$SUB_URL"; echo; }
      echo "Отдельные подключения ($NAME):"
      echo "$links"
    } >"$result_tmp"
    chown root:root "$result_tmp"
    chmod 0600 "$result_tmp"
    mv -Tf -- "$result_tmp" "$RESULT"
  )
}

print_install_summary() {
  echo
  echo "${G}${B}Готово! 3X-UI работает: ${#CREATED[@]} протоколов.${N}"
  echo "${D}${CREATED[*]}${N}"
  echo
  # Passwords, bearer URLs, panel paths and QR codes never enter installer logs.
  echo "Данные для входа и подключения сохранены только в ${B}$RESULT${N} (root:root, 0600)."
  echo "Посмотреть их в приватном root-терминале: cat $RESULT"
  if [[ -n $PIN && " ${CREATED[*]} " == *" TUIC "* ]]; then
    warn "TUIC со своим сертификатом: в клиенте включите «Разрешить небезопасный» (allow insecure) — отпечаток TUIC-ссылки не передают."
  fi
  echo
  echo "Дополнительные пользователи — одной командой, сразу во все протоколы, со своей подпиской:"
  echo "  ${B}kit user add sasha --gb 50 --days 30${N}"
  echo "  ${B}kit user list${N}     — кто сколько израсходовал и до какого числа"
}

main() {
  [[ $EUID -eq 0 ]] || die "Запустите от root: sudo -i, затем команду ещё раз."
  command -v systemctl >/dev/null || die "Нужен systemd."
  [[ ! -L $RESULT && ! -L $XUI_ENV && ! -L /etc/x-ui ]] || die "Unsafe installer state path"
  if [[ -f $RESULT && -x /usr/local/x-ui/x-ui ]]; then
    die "3X-UI уже установлена этим скриптом. Управление: команда x-ui, данные для входа: cat $RESULT"
  fi
  # Refuse legacy/interrupted code before package, TLS, service or state writes.
  [[ ! -f $XUI_ENV ]] || resume_verified_xui
  # Панель удалили через меню x-ui, а наши файлы остались — убираем их и ставим заново.
  if [[ -f $RESULT ]]; then
    warn "Панель 3X-UI удалена, но остались файлы прошлой установки — убираю их."
    systemctl disable --now kit-sub >/dev/null 2>&1 || true
    systemctl disable --now kit-sub-tls-sync.timer >/dev/null 2>&1 || true
    systemctl stop kit-sub-tls-sync.service >/dev/null 2>&1 || true
    rm -rf -- /etc/systemd/system/kit-sub.service /usr/local/lib/kit-sub /etc/kit-sub /etc/kit /usr/local/bin/kit \
      /etc/systemd/system/kit-sub-tls-sync.service /etc/systemd/system/kit-sub-tls-sync.timer \
      /usr/local/sbin/kit-sub-sync-tls \
      /etc/cron.d/kit-nginx-reload /etc/cron.d/kit-xui-menu "$RESULT"
    systemctl daemon-reload
    # Наш nginx держит 443 — без этого проверка порта ниже не пустит REALITY.
    if [[ -f /etc/nginx/kit-stream.conf ]]; then
      systemctl stop nginx >/dev/null 2>&1 || true
      rm -f /etc/nginx/kit-stream.conf /etc/nginx/conf.d/kit.conf
      sed -i '/kit-stream\.conf/d' /etc/nginx/nginx.conf
    fi
  fi
  if [[ -d /usr/local/x-ui && ! -f $XUI_ENV ]]; then
    die "3X-UI уже установлена другим способом — не трогаю её. Удалите её (x-ui uninstall) или добавьте REALITY в панели вручную."
  fi

  local PORT=443 SNI="" PANEL_SSL=auto HOST="" UFW=yes NAME="admin" yes=no protos=all ucert="" ukey="" multi=no
  while [[ $# -gt 0 ]]; do
    case $1 in
      --port) PORT=$2; shift 2 ;;
      --sni) SNI=$2; shift 2 ;;
      --panel-ssl) PANEL_SSL=$2; shift 2 ;;
      --host) HOST=$2; shift 2 ;;
      --user) NAME=$2; shift 2 ;;
      --protocols) protos=$2; shift 2 ;;
      --cert) ucert=$2; shift 2 ;;
      --multi-port) multi=yes; shift ;;
      --key) ukey=$2; shift 2 ;;
      --no-ufw) UFW=no; shift ;;
      -y|--yes) yes=yes; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Неизвестный параметр: $1 (см. --help)" ;;
    esac
  done
  [[ $PORT =~ ^[0-9]+$ ]] && ((PORT > 0 && PORT < 65536)) || die "Неверный порт: $PORT"
  [[ $NAME =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || die "Имя: латиница, цифры, _ . - (до 32 символов)."
  [[ $PANEL_SSL =~ ^(auto|ip|none)$ ]] || die "--panel-ssl: auto, ip или none"
  if [[ -n $ucert || -n $ukey ]]; then
    [[ -s $ucert && -s $ukey ]] || die "Нужны оба файла: --cert fullchain.pem --key privkey.pem"
    openssl x509 -in "$ucert" -noout 2>/dev/null || die "$ucert — не сертификат в формате PEM"
    PANEL_SSL=custom
  fi
  case $protos in
    all) PROTOS=("${DEFAULT_PROTOS[@]}") ;;
    minimal) PROTOS=(reality) ;;
    *) IFS=, read -ra PROTOS <<<"$protos"
       local x
       for x in "${PROTOS[@]}"; do [[ " ${ALL_PROTOS[*]} " == *" $x "* ]] || die "Неизвестный протокол: $x. Доступны: ${ALL_PROTOS[*]}"; done ;;
  esac
  if port_busy "$PORT" tcp && ! { [[ -f $XUI_ENV ]] && ss -H -ltnp "sport = :$PORT" | grep -q -E 'xray|nginx'; }; then
    die "Порт $PORT/tcp уже занят. REALITY нужен свободный порт — укажите другой: --port 8443"
  fi

  if [[ $PANEL_SSL == auto ]]; then
    if port_busy 80 tcp; then
      PANEL_SSL=none
      warn "Порт 80 занят — сертификат для панели не получить. Панель будет доступна только через SSH-туннель."
    else
      PANEL_SSL=ip
    fi
  fi
  [[ $PANEL_SSL == ip ]] && port_busy 80 tcp && die "Для сертификата панели нужен свободный порт 80/tcp."
  # Доверенный сертификат (Let's Encrypt или свой) — панель и подписка доступны снаружи по HTTPS.
  TRUSTED=no
  [[ $PANEL_SSL == ip || $PANEL_SSL == custom ]] && TRUSTED=yes
  if [[ $PANEL_SSL == custom ]]; then
    [[ ! -L /root/cert && ! -L /root/cert/custom ]] || die "Unsafe TLS source directory"
    install -d -o root -g root -m 0700 /root/cert /root/cert/custom
    install -o root -g root -m 0644 "$ucert" /root/cert/custom/fullchain.pem
    install -o root -g root -m 0600 "$ukey" /root/cert/custom/privkey.pem
  fi

  say "Ставлю пакеты: curl, jq, openssl, qrencode, ufw"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl jq openssl qrencode ca-certificates iproute2 ufw socat cron python3 >/dev/null

  sc verify "$KIT_BUNDLE_ROOT"
  HOST=${HOST:-$(public_ip)}
  [[ -n $HOST ]] || die "Не удалось узнать внешний IP. Укажите его: --host 1.2.3.4"

  if [[ -z $SNI ]]; then
    say "Выбираю сайт для маскировки REALITY"
    for s in "${SNI_CANDIDATES[@]}"; do
      if sni_ok "$s"; then SNI=$s; break; fi
    done
    [[ -n $SNI ]] || die "Ни один сайт из списка не ответил по TLS 1.3 + HTTP/2. Укажите свой: --sni example.com"
  elif ! sni_ok "$SNI"; then
    die "$SNI не отвечает по TLS 1.3 + HTTP/2 — REALITY с ним работать не будет. Выберите другой сайт."
  fi
  say "Маскировка: ${B}$SNI${N}"
  # Для режима «всё на 443» XHTTP и MTProto нужны свои сайты: nginx различает их по SNI.
  for s in "${SNI_CANDIDATES[@]}"; do
    [[ $s == "$SNI" ]] && continue
    if [[ -z $SNI2 ]] && sni_ok "$s"; then SNI2=$s; continue; fi
    [[ -z $SNI3 && -n $SNI2 ]] && { SNI3=$s; break; }
  done
  SNI2=${SNI2:-$SNI}; SNI3=${SNI3:-www.cloudflare.com}

  # --- официальный установщик 3X-UI с закреплённой версией ---
  local panel_port panel_path panel_user panel_pass tmp
  panel_port=$(free_port)
  panel_path=$(rand_str 18)
  panel_user=$(rand_str 10)
  panel_pass=$(rand_str 20)
  if [[ -f $XUI_ENV ]]; then
    say "Проверенная 3X-UI уже стоит после прошлого запуска — продолжаю с создания подключений"
  else
  tmp=$(mktemp -d)
  say "Ставлю 3X-UI $XUI_VERSION: upstream installer и архив с закреплёнными SHA256"
  ( trap 'rm -rf -- "$tmp"' EXIT
    sc prepare-xui "$KIT_BUNDLE_ROOT" "$tmp" "$(xui_arch)" >/dev/null || exit 1
    umask 077
    [[ ! -L /var/log/3x-ui-install.log ]] || exit 1
    install -o root -g root -m 0600 /dev/null /var/log/3x-ui-install.log || exit 1
    XUI_NONINTERACTIVE=1 XUI_SSL_MODE="${PANEL_SSL/custom/none}" XUI_SERVER_IP="$HOST" \
      XUI_PANEL_PORT="$panel_port" XUI_WEB_BASE_PATH="$panel_path" \
      XUI_USERNAME="$panel_user" XUI_PASSWORD="$panel_pass" XUI_DB_TYPE=sqlite \
      XUI_MAIN_FOLDER=/usr/local/x-ui XUI_SERVICE=/etc/systemd/system HOME=/root SC_ASSETS="$tmp" \
      env -u BASH_ENV -u ENV bash "$tmp/install-verified.sh" "$XUI_VERSION" </dev/null >/var/log/3x-ui-install.log 2>&1
  ) || die "Проверка или установка 3X-UI не удалась. Лог root-only: /var/log/3x-ui-install.log"
  fi
  [[ -f $XUI_ENV ]] || die "Установщик не сохранил данные входа. Лог: /var/log/3x-ui-install.log"

  # Данные для входа — из файла, который пишет сам установщик.
  secure_xui_environment
  # shellcheck disable=SC1090
  . "$XUI_ENV"
  TOKEN=${XUI_API_TOKEN:?Missing panel API token}
  # Панель может уже работать по HTTPS (сертификат ставится после установщика) — пробуем оба.
  local scheme
  for scheme in https http; do
    API="$scheme://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/panel/api"
    curl -fsk -m 5 -o /dev/null -H "Authorization: Bearer $XUI_API_TOKEN" "$API/server/getNewUUID" 2>/dev/null && break
  done
  wait_panel

  if [[ $PANEL_SSL == custom ]]; then
    say "Подключаю ваш сертификат к панели"
    /usr/local/x-ui/x-ui cert -webCert /root/cert/custom/fullchain.pem -webCertKey /root/cert/custom/privkey.pem >/dev/null 2>&1
    systemctl restart x-ui
    API="https://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/panel/api"
    wait_panel
  fi

  # Без сертификата панель и подписки не должны торчать наружу по HTTP.
  if [[ $PANEL_SSL == none ]]; then
    say "Панель без сертификата — открываю её только для SSH-туннеля (127.0.0.1)"
    local all
    all=$(api POST setting/all '{}')
    api POST setting/update "$(jq -c '.webListen = "127.0.0.1" | .subListen = "127.0.0.1"' <<<"$all")" >/dev/null
    systemctl restart x-ui
    wait_panel
  fi

  # --- ядро Xray, совместимое со всеми клиентами ---
  local core_tmp core_binary core_arch core_name
  core_arch=$(xui_arch); core_name=$core_arch
  [[ $core_arch == armv* ]] && core_name=arm32
  core_tmp=$(mktemp -d)
  say "Ставлю проверенное ядро Xray $XRAY_CORE"
  ( trap 'rm -rf -- "$core_tmp"' EXIT
    core_binary=$(sc prepare-xray "$KIT_BUNDLE_ROOT" "$core_tmp" "$core_arch") || exit 1
    systemctl stop x-ui
    # If installation fails, bring the previously installed service back.
    trap 'systemctl start x-ui >/dev/null 2>&1 || true; rm -rf -- "$core_tmp"' EXIT
    install -m 755 "$core_binary" "/usr/local/x-ui/bin/xray-linux-$core_name.new" || exit 1
    mv -f -- "/usr/local/x-ui/bin/xray-linux-$core_name.new" "/usr/local/x-ui/bin/xray-linux-$core_name" || exit 1
    systemctl restart x-ui
  ) || die "Не удалось установить проверенный Xray."
  wait_panel
  # --- сертификат для протоколов с TLS ---
  setup_tls_cert

  # --- подключения: все выбранные протоколы, один subId на пользователя ---
  EXISTING=$(api GET inbounds/list)
  SUBID=""
  # «Всё на 443» — для новых установок с доверенным сертификатом. Старую многопортовую
  # установку не переделываем: перенос работающих подключений — осознанное решение.
  if [[ $TRUSTED == yes && $multi == no ]]; then
    if jq -e 'any(.[]; .remark == "REALITY" and (.listen // "") != "127.0.0.1")' <<<"$EXISTING" >/dev/null; then
      warn "Установка уже работает в режиме с отдельными портами — оставляю его."
    else
      SINGLE=yes
    fi
  fi
  local p
  for p in "${PROTOS[@]}"; do "proto_$p"; done
  # Первый пользователь — сразу на всех протоколах (как «kit user add»).
  ensure_user

  # --- подписка: ссылки, Clash/Mihomo и JSON с автоопределением клиента ---
  setup_subscription
  [[ $SINGLE == yes ]] && setup_nginx
  install_kit_cli
  brand_xui_menu

  # --- файрвол ---
  if [[ $UFW == yes ]]; then
    local ssh_port
    ssh_port=$(ss -H -ltnp 2>/dev/null | awk '/sshd/ {sub(/.*:/,"",$4); print $4; exit}')
    ssh_port=${ssh_port:-22}
    OPEN+=("$ssh_port/tcp")
    [[ $TRUSTED == yes && $SINGLE == no ]] && OPEN+=("$XUI_PANEL_PORT/tcp" "$SUB_PORT/tcp")
    [[ $PANEL_SSL == ip ]] && OPEN+=("80/tcp")
    say "Настраиваю ufw: ${OPEN[*]}"
    local o
    for o in "${OPEN[@]}"; do ufw allow "$o" >/dev/null; done
    ufw --force enable >/dev/null || warn "ufw не включился (так бывает в контейнерах) — откройте порты у хостера вручную."
  fi

  # --- итог ---
  local panel_url links
  if [[ $SINGLE == yes ]]; then
    panel_url="https://$HOST/${XUI_WEB_BASE_PATH#/}"
    panel_url="${panel_url%/}/"
  elif [[ $TRUSTED == yes ]]; then
    panel_url="https://$HOST:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH"
  else
    panel_url="http://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH  (через SSH-туннель: ssh -L $XUI_PANEL_PORT:127.0.0.1:$XUI_PANEL_PORT root@$HOST)"
  fi
  links=$(sub_links "$SUBID")
  # У установок до kit 1.1 AmneziaWG и MTProto лежат в подписках «-awg» и «-tg».
  local extra
  extra=$(sub_links "$SUBID-awg" 1; sub_links "$SUBID-tg" 1)
  [[ -n $extra ]] && links+=$'\n'"$extra"
  AWG_LINKS=$(grep '^vpn://' <<<"$links" || true)
  # MTProto слушает localhost, а клиенты приходят через nginx на 443.
  [[ $SINGLE == yes ]] && links=$(sed "s/^\(tg:\/\/proxy?\)\(.*\)port=${INNER[mtproto]}/\1\2port=443/" <<<"$links")
  write_install_result
  kit_banner
  print_install_summary
}

# ---------- сертификат ----------

setup_tls_cert() {
  PIN=""
  if [[ $PANEL_SSL == custom ]]; then
    CERT=/root/cert/custom/fullchain.pem; KEY=/root/cert/custom/privkey.pem
  elif [[ $PANEL_SSL == ip && -s /root/cert/ip/fullchain.pem ]]; then
    CERT=/root/cert/ip/fullchain.pem; KEY=/root/cert/ip/privkey.pem
  else
    # Без Let's Encrypt — свой сертификат, а его отпечаток уходит в ссылки (pcs),
    # чтобы клиенты доверяли именно ему.
    CERT=/root/cert/self/fullchain.pem; KEY=/root/cert/self/privkey.pem
    if [[ ! -s $CERT ]]; then
      [[ ! -L /root/cert && ! -L /root/cert/self && ! -L $CERT && ! -L $KEY ]] || die "Unsafe TLS source path"
      install -d -o root -g root -m 0700 /root/cert /root/cert/self
      local san="DNS:$HOST"
      [[ $HOST =~ ^[0-9.]+$ ]] && san="IP:$HOST"
      openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$KEY" -out "$CERT" \
        -subj "/CN=$HOST" -addext "subjectAltName=$san" -days 3650 2>/dev/null
      chmod 600 "$KEY"
    fi
    PIN=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
  fi
  # The publisher is root and uses owner DAC access, not a broad DAC capability.
  [[ ! -L /root/cert && ! -L ${CERT%/*} ]] || die "Unsafe TLS source directory"
  install -d -o root -g root -m 0700 /root/cert "${CERT%/*}"
  [[ -f $CERT && ! -L $CERT && -f $KEY && ! -L $KEY ]] || die "Unsafe TLS source files"
  chown root:root "$CERT" "$KEY"
  chmod 0600 "$KEY"
  chmod 0644 "$CERT"
}

tls_json() { # alpn(JSON-массив)
  jq -nc --arg sni "$HOST" --arg c "$CERT" --arg k "$KEY" --arg pin "$PIN" --argjson alpn "$1" '{
    serverName: $sni, alpn: $alpn, certificates: [{certificateFile: $c, keyFile: $k}],
    settings: ({fingerprint: "chrome"} + (if $pin != "" then {pinnedPeerCertSha256: [$pin]} else {} end))}'
}

# ---------- протоколы ----------

# AmneziaWG — в отдельной подписке: приложения на Xray и sing-box (Happ, v2rayN, Karing,
# Hiddify) его не умеют и видят как обычный WireGuard, который не подключается.
client_base() { # суффикс
  local sid=$SUBID
  [[ $1 == awg* ]] && sid="$SUBID-awg"
  [[ $1 == mtproto ]] && sid="$SUBID-tg"   # ссылка для Telegram, VPN-приложениям не нужна
  jq -nc --arg e "$NAME-$1" --arg s "$sid" '{email: $e, limitIp: 0, totalGB: 0, expiryTime: 0, enable: true, tgId: 0, subId: $s, comment: "", reset: 0}'
}
uuid() { cat /proc/sys/kernel/random/uuid; }
rnd() { shuf -i "$1-$2" -n 1; }

# add_inbound remark port proto(tcp|udp|both|inner) protocol settings stream
# inner — подключение за nginx: слушает 127.0.0.1, наружу порт не открываем.
add_inbound() {
  local remark=$1 port=$2 net=$3 protocol=$4 settings=$5 stream=$6 body listen=""
  [[ $net == inner ]] && listen=127.0.0.1
  if jq -e --arg r "$remark" 'any(.[]; .remark == $r)' <<<"$EXISTING" >/dev/null; then
    CREATED+=("$remark"); open_port "$port" "$net"; return
  fi
  # Клиентов в подключение не кладём: пользователь добавляется потом сразу во все подключения.
  settings=$(jq -c 'if has("clients") then .clients = [] else . end' <<<"$settings")
  local n
  local nets=$net
  [[ $net == both ]] && nets="tcp udp"
  [[ $net == inner ]] && nets=tcp
  for n in $nets; do
    if port_busy "$port" "$n"; then warn "$remark пропущен: порт $port/$n занят"; return; fi
  done
  body=$(jq -nc --arg rm "$remark" --argjson port "$port" --arg p "$protocol" --arg s "$settings" --arg st "$stream" --arg l "$listen" '{
    remark: $rm, enable: true, listen: $l, port: $port, protocol: $p, settings: $s, streamSettings: $st,
    sniffing: "{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"],\"metadataOnly\":false,\"routeOnly\":false}",
    expiryTime: 0, total: 0}')
  local out
  out=$(curl -sSk -m 20 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST -d "$body" "$API/inbounds/add" 2>/dev/null) || die "Panel API transport failed"
  if [[ $(jq -r '.success' <<<"$out") != true ]] && grep -q 'Duplicate email' <<<"$out"; then
    # Клиент с таким именем остался от удалённого подключения — берём уникальное имя.
    body=$(jq -c --arg sfx "-$(openssl rand -hex 2)" '.settings |= (fromjson | .clients[0].email += $sfx | tojson)' <<<"$body")
    out=$(curl -sSk -m 20 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X POST -d "$body" "$API/inbounds/add" 2>/dev/null) || die "Panel API transport failed"
  fi
  [[ $(jq -r '.success' <<<"$out" 2>/dev/null) == true ]] || die "Panel inbound creation failed"
  CREATED+=("$remark"); open_port "$port" "$net"
}

open_port() { # port net
  case $2 in
    inner) ;;
    tcp|udp) OPEN+=("$1/$2") ;;
    both) OPEN+=("$1/tcp" "$1/udp") ;;
  esac
}

# External Proxy 3X-UI: ссылки ведут на HOST:443, хотя подключение слушает localhost.
# SNI — только для TLS через nginx: у REALITY своё имя сайта маскировки, его не трогаем.
ext_proxy() { # forceTls(same|tls) alpn(JSON)
  local sni=""
  [[ $HOST =~ ^[0-9.]+$ ]] || sni=$HOST
  jq -nc --arg f "$1" --arg h "$HOST" --arg sni "$sni" --argjson alpn "${2:-null}" '[{forceTls: $f, dest: $h, port: 443, remark: ""}
    + (if $f == "tls" then {fingerprint: "chrome", alpn: $alpn} + (if $sni != "" then {sni: $sni} else {} end) else {} end)]'
}

proto_reality() {
  local keys stream settings
  keys=$(api GET server/getNewX25519Cert)
  settings=$(jq -nc --arg id "$(uuid)" --argjson c "$(client_base reality)" '{clients: [$c + {id: $id, flow: "xtls-rprx-vision"}], decryption: "none", fallbacks: []}')
  stream=$(jq -nc --arg sni "$SNI" --argjson k "$keys" --arg sid "$(openssl rand -hex 8)" '{
    network: "tcp", security: "reality", externalProxy: [],
    realitySettings: {show: false, xver: 0, target: ($sni + ":443"), serverNames: [$sni], privateKey: $k.privateKey,
      minClientVer: "", maxClientVer: "", maxTimediff: 0, shortIds: [$sid],
      settings: {publicKey: $k.publicKey, fingerprint: "chrome", serverName: "", spiderX: "/"}},
    tcpSettings: {acceptProxyProtocol: false, header: {type: "none"}}}')
  if [[ $SINGLE == yes ]]; then
    stream=$(jq -c --argjson e "$(ext_proxy same)" '.externalProxy = $e | .tcpSettings.acceptProxyProtocol = true' <<<"$stream")
    add_inbound "REALITY" "${INNER[reality]}" inner vless "$settings" "$stream"
  else
    add_inbound "REALITY" "$PORT" tcp vless "$settings" "$stream"
  fi
}

proto_xhttp() {
  local keys stream settings
  keys=$(api GET server/getNewX25519Cert)
  settings=$(jq -nc --arg id "$(uuid)" --argjson c "$(client_base xhttp)" '{clients: [$c + {id: $id, flow: ""}], decryption: "none"}')
  stream=$(jq -nc --arg sni "$SNI" --argjson k "$keys" --arg sid "$(openssl rand -hex 8)" --arg path "/$(rand_str 10 | tr 'A-Z' 'a-z')" '{
    network: "xhttp", security: "reality", xhttpSettings: {path: $path, mode: "auto"},
    realitySettings: {target: ($sni + ":443"), serverNames: [$sni], privateKey: $k.privateKey, shortIds: [$sid],
      settings: {publicKey: $k.publicKey, fingerprint: "chrome", spiderX: "/"}}}')
  if [[ $SINGLE == yes ]]; then
    stream=$(jq -c --arg sni "$SNI2" --argjson e "$(ext_proxy same)" '.realitySettings.target = ($sni + ":443") | .realitySettings.serverNames = [$sni]
      | .externalProxy = $e | .sockopt = {acceptProxyProtocol: true}' <<<"$stream")
    add_inbound "XHTTP" "${INNER[xhttp]}" inner vless "$settings" "$stream"
  else
    add_inbound "XHTTP" "${PORTS[xhttp]}" tcp vless "$settings" "$stream"
  fi
}

proto_ws() {
  local settings stream
  settings=$(jq -nc --arg id "$(uuid)" --argjson c "$(client_base ws)" '{clients: [$c + {id: $id, flow: ""}], decryption: "none"}')
  stream=$(jq -nc --argjson t "$(tls_json '["http/1.1"]')" --arg path "/$(rand_str 10 | tr 'A-Z' 'a-z')" '{network: "ws", security: "tls", wsSettings: {path: $path}, tlsSettings: $t}')
  if [[ $SINGLE == yes ]]; then
    stream=$(jq -c --argjson e "$(ext_proxy tls '["http/1.1"]')" '{network, wsSettings, security: "none", externalProxy: $e}' <<<"$stream")
    add_inbound "VLESS-WS" "${INNER[ws]}" inner vless "$settings" "$stream"
  else
    add_inbound "VLESS-WS" "${PORTS[ws]}" tcp vless "$settings" "$stream"
  fi
}

proto_trojan() {
  local settings stream
  settings=$(jq -nc --arg pw "$(rand_str 16)" --argjson c "$(client_base trojan)" '{clients: [$c + {password: $pw}]}')
  stream=$(jq -nc --argjson t "$(tls_json '["h2"]')" --arg sn "$(rand_str 8 | tr 'A-Z' 'a-z')" '{network: "grpc", security: "tls", grpcSettings: {serviceName: $sn}, tlsSettings: $t}')
  if [[ $SINGLE == yes ]]; then
    stream=$(jq -c --argjson e "$(ext_proxy tls '["h2"]')" '{network, grpcSettings, security: "none", externalProxy: $e}' <<<"$stream")
    add_inbound "Trojan-gRPC" "${INNER[trojan]}" inner trojan "$settings" "$stream"
  else
    add_inbound "Trojan-gRPC" "${PORTS[trojan]}" tcp trojan "$settings" "$stream"
  fi
}

proto_vmess() {
  local settings stream
  settings=$(jq -nc --arg id "$(uuid)" --argjson c "$(client_base vmess)" '{clients: [$c + {id: $id, security: "auto", alterId: 0}]}')
  stream=$(jq -nc --argjson t "$(tls_json '["http/1.1"]')" --arg path "/$(rand_str 10 | tr 'A-Z' 'a-z')" '{network: "ws", security: "tls", wsSettings: {path: $path}, tlsSettings: $t}')
  if [[ $SINGLE == yes ]]; then
    stream=$(jq -c --argjson e "$(ext_proxy tls '["http/1.1"]')" '{network, wsSettings, security: "none", externalProxy: $e}' <<<"$stream")
    add_inbound "VMess-WS" "${INNER[vmess]}" inner vmess "$settings" "$stream"
  else
    add_inbound "VMess-WS" "${PORTS[vmess]}" tcp vmess "$settings" "$stream"
  fi
}

proto_ss() {
  local settings
  settings=$(jq -nc --arg pw "$(openssl rand -base64 16)" --arg upw "$(openssl rand -base64 16)" --argjson c "$(client_base ss)" '{
    method: "2022-blake3-aes-128-gcm", password: $pw, network: "tcp,udp", clients: [$c + {method: "", password: $upw}]}')
  add_inbound "Shadowsocks" "${PORTS[ss]}" both shadowsocks "$settings" '{"network":"tcp","security":"none"}'
}

proto_hy2() {
  local settings stream
  settings=$(jq -nc --arg a "$(rand_str 16)" --argjson c "$(client_base hy2)" '{version: 2, clients: [$c + {auth: $a}]}')
  stream=$(jq -nc --argjson t "$(tls_json '["h3"]')" '{network: "hysteria", hysteriaSettings: {version: 2}, security: "tls", tlsSettings: $t}')
  add_inbound "Hysteria2" "$PORT" udp hysteria "$settings" "$stream"
}

proto_tuic() {
  local settings id
  id=$(uuid)
  settings=$(jq -nc --arg id "$id" --arg pw "$(rand_str 16)" --arg c "$CERT" --arg k "$KEY" --argjson cb "$(client_base tuic)" '{
    server: {certificate: $c, private_key: $k, congestion_control: "bbr", alpn: ["h3"], udp_relay_mode: "native",
      zero_rtt_handshake: false, log_level: "warn", sni: ""},
    clients: [$cb + {uuid: $id, id: $id, password: $pw}]}')
  add_inbound "TUIC" "${PORTS[tuic]}" udp tuic "$settings" '{}'
}

wg_pair() { /usr/local/x-ui/bin/xray-linux-* wg; }

proto_wg() {
  local srv cli settings
  srv=$(wg_pair); cli=$(wg_pair)
  settings=$(jq -nc --arg sk "$(awk '/Private/ {print $NF}' <<<"$srv")" \
    --arg pr "$(awk '/Private/ {print $NF}' <<<"$cli")" --arg pu "$(awk '/Public|Password/ {print $NF}' <<<"$cli" | head -1)" \
    --argjson c "$(client_base wg)" '{mtu: 1420, secretKey: $sk, peers: [], subnetIp: "10.0.0.0", subnetCidr: 24,
    clients: [$c + {privateKey: $pr, publicKey: $pu, allowedIPs: ["10.0.0.2/32"]}]}')
  add_inbound "WireGuard" "${PORTS[wg]}" udp wireguard "$settings" '{"network":"tcp","security":"none"}'
}

# AmneziaWG: классические параметры понимают Mihomo и роутеры Keenetic,
# полный набор 3.1 — только приложения AmneziaVPN/AmneziaWG. Поэтому два подключения.
awg_obfuscation() { # classic|full
  local jmin s1 s2
  jmin=$(rnd 40 89); s1=$(rnd 15 150); s2=$(rnd 15 150)
  while ((s1 + 56 == s2)); do s2=$(rnd 15 150); done
  local o
  o=$(jq -nc --argjson jc "$(rnd 3 6)" --argjson jmin "$jmin" --argjson jmax "$((jmin + $(rnd 50 250)))" --argjson s1 "$s1" --argjson s2 "$s2" \
    --arg h1 "$(rnd 5 536870911)" --arg h2 "$(rnd 536870912 1073741823)" --arg h3 "$(rnd 1073741824 1610612735)" --arg h4 "$(rnd 1610612736 2147483647)" \
    '{jc: $jc, jmin: $jmin, jmax: $jmax, s1: $s1, s2: $s2, h1: $h1, h2: $h2, h3: $h3, h4: $h4}')
  if [[ $1 == full ]]; then
    # С защитой заголовков (3.1) документация AmneziaWG советует H1–H4 = 1, 2, 3, 4:
    # тип сообщения тогда скрывает сама защита, а свои заголовки отключаются.
    local cp rk rj rt ka ha
    cp=$(rnd 8 24); rk=$(rnd 100 120); rj=$((rk + $(rnd 10 40) + $(rnd 30 60))); rt=$(rnd 3 6); ka=$(rnd 8 12); ha=$(rnd 15 25)
    o=$(jq -c --argjson s3 "$(rnd 12 55)" --argjson s4 "$(rnd 12 27)" --arg i1 "<r $(rnd 32 256)>" --arg hp "$(openssl rand -base64 32)" \
      --arg cp "$cp-$((cp + $(rnd 8 40)))" --arg rk "$rk-$((rk + $(rnd 10 40)))" --arg rj "$rj-$((rj + $(rnd 30 90)))" \
      --arg rt "$rt-$((rt + $(rnd 1 4)))" --arg ka "$ka-$((ka + $(rnd 2 8)))" --arg ha "$ha-$((ha + $(rnd 5 25)))" \
      '. + {h1: "1", h2: "2", h3: "3", h4: "4",
            s3: $s3, s4: $s4, i1: $i1, headerProtectionKey: $hp, contentPaddingAddition: $cp, rekeyAfterTime: $rk,
            rejectAfterTime: $rj, rekeyTimeout: $rt, keepaliveTimeout: $ka, maxHandshakeAttempts: $ha}' <<<"$o")
  fi
  echo "$o"
}

awg_inbound() { # remark port subnet client-ip suffix mode
  local srv cli settings
  srv=$(wg_pair); cli=$(wg_pair)
  settings=$(jq -nc --arg pk "$(awk '/Private/ {print $NF}' <<<"$srv")" --arg pub "$(awk '/Public|Password/ {print $NF}' <<<"$srv" | head -1)" \
    --arg pr "$(awk '/Private/ {print $NF}' <<<"$cli")" --arg pu "$(awk '/Public|Password/ {print $NF}' <<<"$cli" | head -1)" \
    --arg net "$3" --arg ip "$4" --argjson o "$(awg_obfuscation "$6")" --argjson c "$(client_base "$5")" '{
    server: ({privateKey: $pk, publicKey: $pub, subnetIp: $net, subnetCidr: 24, primaryDns: "1.1.1.1", secondaryDns: "8.8.8.8"} + $o),
    clients: [$c + {privateKey: $pr, publicKey: $pu, allowedIPs: [$ip]}]}')
  add_inbound "$1" "$2" udp amneziawg "$settings" '{}'
}

proto_awg() { awg_inbound "AmneziaWG" "${PORTS[awg]}" 10.8.1.0 10.8.1.2/32 awg classic; }
proto_awg3() { awg_inbound "AmneziaWG-3.1" "${PORTS[awg3]}" 10.8.2.0 10.8.2.2/32 awg3 full; }

telegram_reachable() {
  local ip
  for ip in 149.154.167.51 149.154.175.50 91.108.56.130; do
    timeout 5 bash -c "</dev/tcp/$ip/443" 2>/dev/null && return 0
  done
  return 1
}

proto_mtproto() {
  # MTProto бесполезен, если сам сервер не достаёт до Telegram (некоторые хостеры его блокируют).
  if ! telegram_reachable; then
    warn "MTProto пропущен: с этого сервера недоступны серверы Telegram — прокси для Telegram здесь работать не будет."
    return
  fi
  local settings
  if [[ $SINGLE == yes ]]; then
    # FakeTLS-домен — свой сайт: nginx узнаёт MTProto по нему и передаёт mtg с реальным IP клиента.
    settings=$(jq -nc --arg d "$SNI3" --argjson c "$(client_base mtproto)" '{fakeTlsDomain: $d, proxyProtocolListener: true, clients: [$c + {secret: ""}]}')
    add_inbound "MTProto" "${INNER[mtproto]}" inner mtproto "$settings" '{}'
  else
    settings=$(jq -nc --argjson c "$(client_base mtproto)" '{fakeTlsDomain: "www.cloudflare.com", clients: [$c + {secret: ""}]}')
    add_inbound "MTProto" "${PORTS[mtproto]}" tcp mtproto "$settings" '{}'
  fi
}

# ---------- пользователи ----------

# Один клиент 3X-UI на все подключения: общие трафик, лимиты и срок, одна подписка.
ensure_user() {
  local list me ids missing legacy
  list=$(api GET clients/list | jq -c 'if type == "array" then . else .clients end')
  ids=$(non_awg_ids)
  me=$(jq -c --arg e "$NAME" 'map(select(.email == $e))[0] // empty' <<<"$list")
  legacy=$(jq -r --arg p "$NAME-" 'map(select((.email | startswith($p)) and (.email | test("-awg[0-9]*$") | not))) | .[0].subId // empty' <<<"$list")
  if [[ -n $me ]]; then
    SUBID=$(jq -r '.subId' <<<"$me")
    missing=$(jq -c --argjson all "$ids" '$all - (.inboundIds // [])' <<<"$me")
    [[ $missing == "[]" ]] || api POST "clients/$NAME/attach" "$(jq -nc --argjson i "$missing" '{inboundIds: $i}')" >/dev/null
    awg_attach "$NAME" "$SUBID"
  elif [[ -n $legacy ]]; then
    # Установка до kit 1.1: у каждого протокола свой клиент — оставляем как есть.
    SUBID=$legacy
  else
    SUBID=$(rand_str 16 | tr 'A-Z' 'a-z')
    api POST clients/add "$(jq -nc --arg e "$NAME" --arg s "$SUBID" --argjson ids "$ids" \
      '{client: {email: $e, subId: $s, totalGB: 0, expiryTime: 0, limitIp: 0, enable: true, comment: "kit"}, inboundIds: $ids}')" >/dev/null
    awg_attach "$NAME" "$SUBID"
  fi
}

# В 3X-UI 3.x у клиента одна запись и в ней одна пара ключей WireGuard и один адрес. Если
# клиент подключён к двум AmneziaWG, в подписку для обоих уходят ключ и адрес одного из них,
# и второй сервер клиента не узнаёт (проверено 2026-09-27). Поэтому к первому AmneziaWG
# подключаем основную запись, а ко второму — запись-«двойник» «имя-awg» с подпиской «<id>-awg»
# (subId в 3X-UI обязан быть уникальным) и теми же лимитами; kit-sub подмешивает её в Clash.
awg_ids() { api GET inbounds/list | jq -r '[.[] | select(.protocol == "amneziawg") | .id] | sort | .[]'; }
non_awg_ids() { api GET inbounds/list | jq -c '[.[] | select(.protocol != "amneziawg") | .id]'; }

awg_attach() { # имя subId [лимит-байт] [срок-мс] [устройств]
  local name=$1 sid=$2 total=${3:-0} exp=${4:-0} lim=${5:-0} n=1 id email have
  have=$(api GET clients/list | jq -c 'if type == "array" then . else .clients end')
  for id in $(awg_ids); do
    local esid=$sid
    if ((n == 1)); then email=$name
    elif ((n == 2)); then email="$name-awg"; esid="$sid-awg"
    else email="$name-awg$n"; esid="$sid-awg$n"; fi
    n=$((n + 1))
    if jq -e --arg e "$email" --argjson i "$id" 'any(.[]; .email == $e and ((.inboundIds // []) | index($i)))' <<<"$have" >/dev/null; then
      continue
    elif jq -e --arg e "$email" 'any(.[]; .email == $e)' <<<"$have" >/dev/null; then
      api POST "clients/$email/attach" "$(jq -nc --argjson i "$id" '{inboundIds: [$i]}')" >/dev/null
    else
      api POST clients/add "$(jq -nc --arg e "$email" --arg s "$esid" --argjson t "$total" --argjson x "$exp" --argjson l "$lim" --argjson i "$id" \
        '{client: {email: $e, subId: $s, totalGB: $t, expiryTime: $x, limitIp: $l, enable: true, comment: "kit"}, inboundIds: [$i]}')" >/dev/null
    fi
  done
}


install_kit_cli() {
  install -d -m 700 /etc/kit
  {
    printf 'HOST=%q\n' "$HOST"
    printf 'SUB_BASE=%q\n' "${SUB_URL%$SUBID}"
    printf 'SUB_PATH=%q\n' "$SUB_PATH"
    printf 'SUB_INTERNAL=%q\n' "${SUB_INTERNAL:-$SUB_PORT}"
    printf 'SINGLE=%q\n' "$SINGLE"
    printf 'MTPROTO_INNER=%q\n' "${INNER[mtproto]}"
  } >/etc/kit/kit.env
  chmod 600 /etc/kit/kit.env
  local bundle
  bundle=$(sc persist "$KIT_BUNDLE_ROOT" /usr/local/lib/3x-ui-kit) || die "Не удалось сохранить проверенный bundle."
  ln -sfn -- "$bundle/scripts/kit.sh" /usr/local/bin/kit
}

KIT_INSTALL_CMD="bash ./scripts/3x-ui.sh (из проверенного release bundle secure-v1.0.0; см. README)"

# Удаляем старую cron-подмену подсказки. Само меню теперь готовит verified adapter;
# обновление компонентов через mutable upstream скрипты в нём отключено.
brand_xui_menu() {
  # The supply-chain adapter installs a matched, hardened upstream menu.
  # Never restore a mutable-main command through cron or self-update.
  rm -f /etc/cron.d/kit-xui-menu /etc/kit/xui-menu.sed
}

# ---------- всё на 443: nginx ----------

setup_nginx() {
  say "Настраиваю nginx: всё TCP через порт 443"
  apt-get install -y -qq nginx libnginx-mod-stream >/dev/null
  # Порт 80 нужен Let's Encrypt для продления сертификата — сайт nginx по умолчанию убираем.
  rm -f /etc/nginx/sites-enabled/default

  # Панель — только через nginx.
  local all
  all=$(api POST setting/all '{}')
  if [[ $(jq -r '.webListen' <<<"$all") != 127.0.0.1 ]]; then
    api POST setting/update "$(jq -c '.webListen = "127.0.0.1"' <<<"$all")" >/dev/null
    systemctl restart x-ui
    wait_panel
  fi

  install -d -m 755 /var/www/kit
  [[ -f /var/www/kit/index.html ]] || cat >/var/www/kit/index.html <<'HTML'
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title><style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f7f9;color:#1f2328}main{text-align:center;padding:24px}h1{font-weight:600;font-size:28px}p{color:#57606a}</style></head><body><main><h1>Site is under construction</h1><p>Please check back soon.</p></main></body></html>
HTML

  # Маршруты — из текущих подключений панели: сайты REALITY, пути WebSocket, сервисы gRPC.
  local list reality_sni xhttp_sni mt_sni locs="" kind path port
  list=$(api GET inbounds/list)
  reality_sni=$(jq -r '.[] | select(.remark == "REALITY" and .listen == "127.0.0.1") | (.streamSettings | if type == "string" then fromjson else . end).realitySettings.serverNames[0]' <<<"$list")
  xhttp_sni=$(jq -r '.[] | select(.remark == "XHTTP" and .listen == "127.0.0.1") | (.streamSettings | if type == "string" then fromjson else . end).realitySettings.serverNames[0]' <<<"$list")
  mt_sni=$(jq -r '.[] | select(.protocol == "mtproto" and .listen == "127.0.0.1") | (.settings | if type == "string" then fromjson else . end).fakeTlsDomain' <<<"$list")
  while IFS=$'\t' read -r kind path port; do
    [[ -n $path ]] || continue
    if [[ $kind == ws ]]; then
      locs+="
    location = $path {
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_protocol_addr;
        proxy_read_timeout 1h;
    }"
    else
      locs+="
    location /$path/ {
        grpc_pass grpc://127.0.0.1:$port;
        grpc_set_header X-Real-IP \$proxy_protocol_addr;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        client_max_body_size 0;
    }"
    fi
  done < <(jq -r '.[] | select(.listen == "127.0.0.1") | (.streamSettings | if type == "string" then fromjson else . end) as $st
    | if $st.network == "ws" then ["ws", $st.wsSettings.path, .port]
      elif $st.network == "grpc" then ["grpc", $st.grpcSettings.serviceName, .port]
      else empty end | @tsv' <<<"$list")

  local panel_path=/${XUI_WEB_BASE_PATH#/}
  panel_path=${panel_path%/}/
  {
    echo "# Сгенерировано 3x-ui.sh (3X-UI KIT) — перезаписывается при повторном запуске."
    echo "stream {"
    echo "    map \$ssl_preread_server_name \$kit_upstream {"
    [[ -n $reality_sni ]] && echo "        $reality_sni 127.0.0.1:${INNER[reality]};"
    [[ -n $xhttp_sni && $xhttp_sni != "$reality_sni" ]] && echo "        $xhttp_sni 127.0.0.1:${INNER[xhttp]};"
    [[ -n $mt_sni ]] && echo "        $mt_sni 127.0.0.1:${INNER[mtproto]};"
    echo "        default 127.0.0.1:${INNER[web]};"
    echo "    }"
    echo "    server {"
    echo "        listen 443;"
    echo "        listen [::]:443;"
    echo "        ssl_preread on;"
    echo "        proxy_pass \$kit_upstream;"
    echo "        proxy_protocol on;"
    echo "        proxy_connect_timeout 10s;"
    echo "        proxy_timeout 1h;"
    echo "    }"
    echo "}"
  } >/etc/nginx/kit-stream.conf
  cat >/etc/nginx/conf.d/kit.conf <<NGX
# Сгенерировано 3x-ui.sh (3X-UI KIT) — перезаписывается при повторном запуске.
server {
    listen 127.0.0.1:${INNER[web]} ssl http2 proxy_protocol;
    server_name _;
    ssl_certificate $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
    server_tokens off;
    # Иначе редирект «добавить слеш» уйдёт на внутренний порт nginx.
    absolute_redirect off;
    access_log off;
$locs
    location $SUB_PATH {
        proxy_pass http://127.0.0.1:${INNER[sub]};
        proxy_set_header Host \$host;
    }
    location $panel_path {
        proxy_pass https://127.0.0.1:$XUI_PANEL_PORT;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-For \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
    location / {
        root /var/www/kit;
        index index.html;
    }
}
NGX
  grep -q 'kit-stream.conf' /etc/nginx/nginx.conf || echo 'include /etc/nginx/kit-stream.conf;' >>/etc/nginx/nginx.conf
  [[ ! -L /var/log/kit-nginx-test.log ]] || die "Unsafe nginx diagnostic log"
  install -o root -g root -m 0600 /dev/null /var/log/kit-nginx-test.log
  nginx -t >/var/log/kit-nginx-test.log 2>&1 || die "nginx не принял конфиг. Лог root-only: /var/log/kit-nginx-test.log"
  systemctl enable nginx >/dev/null 2>&1
  systemctl restart nginx
  # Let's Encrypt на IP продлевается каждые несколько дней — nginx раз в сутки перечитывает сертификат.
  echo '17 4 * * * root systemctl reload nginx >/dev/null 2>&1' >/etc/cron.d/kit-nginx-reload
  OPEN+=("443/tcp")
  local i
  for i in $(seq 1 10); do port_busy 443 tcp && return 0; sleep 1; done
  die "nginx не открыл порт 443."
}

# ---------- подписка ----------

setup_subscription() {
  local all upd
  all=$(api POST setting/all '{}')
  SUB_PATH=$(jq -r '.subPath // "/sub/"' <<<"$all")
  if [[ $SUB_PATH == /sub/ || -z $SUB_PATH ]]; then SUB_PATH="/$(rand_str 12 | tr 'A-Z' 'a-z')/"; fi
  if [[ $TRUSTED == yes ]]; then
    # Наружу смотрит kit-sub (подписка с учётом приложения), 3X-UI — только на 127.0.0.1.
    SUB_PORT=2096; SUB_INTERNAL=2097
    # Без subURI панель показывает ссылку на внутренний порт 2097, до которого снаружи не достучаться.
    local uri="https://$HOST:$SUB_PORT$SUB_PATH"
    [[ $SINGLE == yes ]] && uri="https://$HOST$SUB_PATH"
    upd=$(jq -c --arg path "$SUB_PATH" --argjson ip "$SUB_INTERNAL" --arg title "3X-UI KIT" --arg uri "$uri" '
      .subEnable = true | .subPath = $path | .subTitle = $title | .subListen = "127.0.0.1" | .subPort = $ip
      | .subURI = $uri
      | .subCertFile = "" | .subKeyFile = ""
      | .subClashEnable = true | .subClashAutoDetect = true | .subJsonEnable = true | .subJsonAutoDetect = true' <<<"$all")
  else
    SUB_PORT=$(jq -r '.subPort // 2096' <<<"$all")
    upd=$(jq -c --arg path "$SUB_PATH" --arg title "3X-UI KIT" '
      .subEnable = true | .subPath = $path | .subTitle = $title
      | .subClashEnable = true | .subClashAutoDetect = true | .subJsonEnable = true | .subJsonAutoDetect = true' <<<"$all")
  fi
  if [[ $upd != "$all" ]]; then
    api POST setting/update "$upd" >/dev/null
    systemctl restart x-ui
    wait_panel
  fi
  [[ $TRUSTED == yes ]] && install_kit_sub
  if [[ $SINGLE == yes ]]; then SUB_URL="https://$HOST$SUB_PATH$SUBID"
  elif [[ $TRUSTED == yes ]]; then SUB_URL="https://$HOST:$SUB_PORT$SUB_PATH$SUBID"; else SUB_URL="http://127.0.0.1:$SUB_PORT$SUB_PATH$SUBID"; fi
  SUB_FETCH="$(if [[ $TRUSTED == yes ]]; then echo https; else echo http; fi)://$HOST:$SUB_PORT$SUB_PATH$SUBID"
}


install_kit_sub_tls_sync() {
  [[ ! -L /etc/kit-sub/tls ]] || die "Unsafe kit-sub TLS directory"
  install -d -o root -g kit-sub -m 0750 /etc/kit-sub/tls
  local sources helper
  sources=$(mktemp /etc/kit-sub/.tls-sources.XXXXXXXX)
  jq -n --arg cert "$CERT" --arg key "$KEY" '{cert: $cert, key: $key}' >"$sources"
  chown root:root "$sources"; chmod 0600 "$sources"
  mv -Tf -- "$sources" /etc/kit-sub/tls-sources.json
  helper=$(mktemp)
  cat >"$helper" <<'HELPER'
#!/bin/bash
set -euo pipefail
umask 077
exec 2>/dev/null
base=/etc/kit-sub/tls
generation=
link=
published=no
cleanup() {
  local result=$?
  [[ -z $link ]] || rm -f -- "$link"
  if [[ $published != yes && -n $generation ]]; then rm -rf -- "$generation"; fi
  if (( result != 0 )); then printf '%s\n' 'kit-sub: protected TLS sync failed'; fi
  return "$result"
}
trap cleanup EXIT
[[ $EUID == 0 && -d $base && ! -L $base ]]
exec 9>"$base/.sync.lock"
flock -n 9 || exit 0
cert=$(jq -er '.cert | select(type == "string" and startswith("/") and (test("[\\r\\n]") | not))' /etc/kit-sub/tls-sources.json)
key=$(jq -er '.key | select(type == "string" and startswith("/") and (test("[\\r\\n]") | not))' /etc/kit-sub/tls-sources.json)
[[ -s $cert && -s $key ]]
if [[ -L $base/current ]] && cmp -s -- "$cert" "$base/current/fullchain.pem" && cmp -s -- "$key" "$base/current/privkey.pem"; then
  exit 0
fi
generation=$(mktemp -d "$base/gen.XXXXXXXXXX")
install -o root -g kit-sub -m 0640 -- "$cert" "$generation/fullchain.pem"
install -o root -g kit-sub -m 0640 -- "$key" "$generation/privkey.pem"
# CPython validates the complete PEM chain and matching unencrypted key.
# Staging paths are root-controlled, never the source subscription config.
/usr/bin/python3 - "$generation/fullchain.pem" "$generation/privkey.pem" <<'PY'
import ssl
import sys
ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(sys.argv[1], sys.argv[2])
PY
# If sources changed while staging, retry at the next timer tick.
cmp -s -- "$cert" "$generation/fullchain.pem"
cmp -s -- "$key" "$generation/privkey.pem"
previous=$(readlink -- "$base/current" || true)
chown root:kit-sub "$generation"
chmod 0750 "$generation"
link="$base/.current.${generation##*/}"
ln -s -- "${generation##*/}" "$link"
mv -Tf -- "$link" "$base/current"
published=yes
# Retain the current and previous complete pairs; bound on-disk generations.
for old in "$base"/gen.*; do
  [[ -d $old && ! -L $old && $old != "$generation" && ${old##*/} != "$previous" ]] || continue
  rm -rf -- "$old"
done
HELPER
  install -o root -g root -m 0700 "$helper" /usr/local/sbin/kit-sub-sync-tls
  rm -f -- "$helper"
  /usr/local/sbin/kit-sub-sync-tls || die "kit-sub TLS publication failed"
  cat >/etc/systemd/system/kit-sub-tls-sync.service <<'UNIT'
[Unit]
Description=Publish protected kit-sub TLS copies

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/kit-sub-sync-tls
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/etc/kit-sub/tls
PrivateTmp=true
PrivateDevices=true
PrivateNetwork=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_CHOWN
TimeoutStartSec=30
UNIT
  cat >/etc/systemd/system/kit-sub-tls-sync.timer <<'UNIT'
[Unit]
Description=Detect renewed kit-sub TLS source files

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s
Unit=kit-sub-tls-sync.service

[Install]
WantedBy=timers.target
UNIT
  chown root:root /etc/systemd/system/kit-sub-tls-sync.service /etc/systemd/system/kit-sub-tls-sync.timer
  chmod 0644 /etc/systemd/system/kit-sub-tls-sync.service /etc/systemd/system/kit-sub-tls-sync.timer
}

install_kit_sub() {
  local kp=$SUB_PORT
  [[ $SINGLE == yes ]] && kp=${INNER[sub]}
  [[ $kp =~ ^[0-9]{1,5}$ ]] && ((kp > 1023 && kp < 65536)) || die "Invalid unprivileged kit-sub port"
  say "Ставлю подписку с учётом приложения (kit-sub)"
  apt-get install -y -qq python3 python3-yaml >/dev/null
  # Refuse symlinked application roots before changing their ownership.
  [[ ! -L /usr/local/lib/kit-sub && ! -L /etc/kit-sub ]] || die "Unsafe kit-sub directory"
  getent group kit-sub >/dev/null || groupadd --system kit-sub
  if ! getent passwd kit-sub >/dev/null; then
    useradd --system --gid kit-sub --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin kit-sub
  fi
  local ks_name ks_pass ks_uid ks_gid ks_gecos ks_home ks_shell ks_group ks_gpass ks_group_gid ks_members
  IFS=: read -r ks_name ks_pass ks_uid ks_gid ks_gecos ks_home ks_shell < <(getent passwd kit-sub)
  IFS=: read -r ks_group ks_gpass ks_group_gid ks_members < <(getent group kit-sub)
  [[ $ks_uid =~ ^[0-9]+$ && $ks_uid != 0 && $ks_gid =~ ^[0-9]+$ && $ks_gid != 0 && $ks_gid == "$ks_group_gid" \
     && $ks_home == /nonexistent && $ks_shell == /usr/sbin/nologin \
     && $(id -G kit-sub) == "$ks_gid" && -z $ks_members ]] || die "Unsafe existing kit-sub identity"
  install -d -o root -g root -m 0755 /usr/local/lib/kit-sub
  install -d -o root -g kit-sub -m 0750 /etc/kit-sub
  sc verify "$KIT_BUNDLE_ROOT"
  install -o root -g root -m 0644 "$KIT_BUNDLE_ROOT/scripts/kit-sub.py" /usr/local/lib/kit-sub/kit_sub.py
  python3 -I -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" /usr/local/lib/kit-sub/kit_sub.py || die "Некорректный kit-sub в bundle."
  local ks_config
  ks_config=$(mktemp /etc/kit-sub/.config.XXXXXXXX)
  if [[ $SINGLE == yes ]]; then
    # Only loopback HTTP behind nginx; nginx keeps its own root-only TLS key.
    systemctl disable --now kit-sub-tls-sync.timer >/dev/null 2>&1 || true
    systemctl stop kit-sub-tls-sync.service >/dev/null 2>&1 || true
    systemctl stop kit-sub >/dev/null 2>&1 || true
    # A plaintext-only daemon must not retain access to previous TLS key copies.
    rm -rf -- /etc/kit-sub/tls
    rm -f -- /etc/kit-sub/tls-sources.json
    jq -n --arg path "$SUB_PATH" --argjson port "${INNER[sub]}" --arg up "http://127.0.0.1:$SUB_INTERNAL" --arg host "$HOST" \
      '{listen: "127.0.0.1", port: $port, path: $path, upstream: $up, host: $host}' >"$ks_config"
  else
    install_kit_sub_tls_sync
    jq -n --arg path "$SUB_PATH" --argjson port "$SUB_PORT" --arg up "http://127.0.0.1:$SUB_INTERNAL" --arg host "$HOST" \
      '{listen: "0.0.0.0", port: $port, path: $path, upstream: $up, host: $host,
        cert: "/etc/kit-sub/tls/current/fullchain.pem", key: "/etc/kit-sub/tls/current/privkey.pem"}' >"$ks_config"
  fi
  chown root:kit-sub "$ks_config"; chmod 0640 "$ks_config"
  mv -Tf -- "$ks_config" /etc/kit-sub/config.json
  cat >/etc/systemd/system/kit-sub.service <<'UNIT'
[Unit]
Description=kit-sub: app-aware 3X-UI subscription
After=network-online.target x-ui.service
Wants=network-online.target

[Service]
Type=simple
User=kit-sub
Group=kit-sub
ExecStart=/usr/bin/python3 -B /usr/local/lib/kit-sub/kit_sub.py
Environment=KIT_SUB_CONFIG=/etc/kit-sub/config.json
WorkingDirectory=/usr/local/lib/kit-sub
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
MemoryMax=256M
TasksMax=32
LimitNOFILE=128

[Install]
WantedBy=multi-user.target
UNIT
  chown root:root /etc/systemd/system/kit-sub.service
  chmod 0644 /etc/systemd/system/kit-sub.service
  systemctl daemon-reload
  if [[ $SINGLE != yes ]]; then
    systemctl enable --now kit-sub-tls-sync.timer >/dev/null 2>&1
  fi
  systemctl enable kit-sub >/dev/null 2>&1
  systemctl restart kit-sub
  local i
  for i in $(seq 1 20); do port_busy "$kp" tcp && return 0; sleep 1; done
  die "kit-sub не запустился. Проверьте журнал в приватном root-терминале."
}

# Ссылки пользователя — из его же подписки (её собирает сама 3X-UI).
# Ссылки пользователя — прямо из подписки 3X-UI внутри сервера (мимо kit-sub, который
# прячет от VPN-приложений vpn:// и tg://). sub_links subId [попыток]
sub_links() {
  local id=$1 tries=${2:-20} raw="" i port=${SUB_INTERNAL:-$SUB_PORT} scheme=http
  [[ -z ${SUB_INTERNAL:-} && $TRUSTED == yes ]] && scheme=https
  for i in $(seq 1 "$tries"); do
    # Настоящий адрес в Host — 3X-UI подставит его в ссылки.
    raw=$(curl -fsSk -m 10 -A "v2rayN/7.0" -H "Host: $HOST:$SUB_PORT" "$scheme://127.0.0.1:$port$SUB_PATH$id" 2>/dev/null) && [[ -n $raw ]] && break
    raw=""; sleep 2
  done
  if grep -q '://' <<<"$raw"; then echo "$raw"; else base64 -d <<<"$raw" 2>/dev/null || true; fi
}

usage() {
  cat <<EOF
3X-UI со всеми протоколами одной командой

  --protocols all     all (по умолчанию — всё, кроме WireGuard), minimal (только REALITY)
                      или список через запятую: reality,hy2,xhttp,ws,trojan,vmess,ss,tuic,wg,awg,awg3,mtproto
                      (обычный WireGuard в России блокируется — включайте его, только если сервер и
                      пользователи за границей)
  --port 443          порт REALITY (TCP) и Hysteria2 (UDP), по умолчанию 443
  --sni сайт          сайт для маскировки (по умолчанию подбирается сам)
  --panel-ssl ip|none сертификат панели: ip — Let's Encrypt на IP (нужен порт 80),
                      none — панель только через SSH-туннель (по умолчанию выбирается сам)
  --cert файл --key файл  свой сертификат (например, для домена) вместо Let's Encrypt на IP;
                      тогда --host — это домен из сертификата
  --user admin        имя первого клиента
  --host 1.2.3.4      адрес в ссылке, если IP определился неверно
  --no-ufw            не трогать файрвол
  -y                  не задавать вопросов
EOF
}

main "$@"
