# kit-sub integration hand-off

**Integration applied by parent and regression-tested in `scripts/3x-ui.sh`.** This file preserves the original hand-off and Linux acceptance checklist; read the current source rather than reapplying snippets. This child did not edit that file. Anchors below refer to BASE `4f1e5d98ccd0e34083e844ed7f4c0849658be7dd`, not to potentially shifted working-tree line numbers. Preserve the other child's verified-download/install logic. Do not restore `KIT_SUB_URL`, an unverified `curl`, or the old upstream repository. Official fork: `zordanexe/3X-UI_KIT`.

## Findings and acceptance boundary

| Class | Evidence in BASE | Outcome |
|---|---|---|
| Confirmed vulnerability: HIGH, excessive privilege | `3x-ui.sh:937-955`: no `User`/`Group`, reads TLS key from `/root`; service defaults to root | Proposed service/user/copy snippets below; Python now refuses root. **Deploy the new unit together with the Python change**, otherwise the old root unit cannot start. |
| Confirmed vulnerability: MEDIUM, credential logging | `kit-sub.py:58,177,189,216,235,240`: exception text, arbitrary UA, and secret subscription prefix reach journal | Static event messages only; errors and startup failures do not print data or tracebacks. Tested with synthetic sentinels. |
| Confirmed vulnerability: MEDIUM, outbound trust boundary | `kit-sub.py:50-56,168`: urllib follows redirects and environment proxies; attacker Host is forwarded | Literal loopback HTTP origin only, no proxies or redirects, configured Host only; local redirect reproduction verifies no second request. Internet exploitability depends on backend/proxy environment. |
| Confirmed vulnerability: MEDIUM, resource exhaustion | `kit-sub.py:54,56,85,100,101,203`: unbounded body reads, YAML graph, request threads | 2 MiB response/serialization cap, 20,000 YAML nodes/logical visits, depth 32, recursive alias rejection before merge-key construction, 8 simultaneous request workers. Oversized/invalid replies fail closed. |
| Confirmed functional defects | malformed proxy/group shapes, invalid base64, whitespace-hidden unsupported links, and cert-only mtime reload | Shape checks, strict whitespace-tolerant base64 decoding, normalized scheme checks, atomic fresh TLS contexts tracking both files/inodes/nanoseconds. |
| Intentional or standard design | bearer subscription IDs are authorized by 3X-UI, not a new kit-sub account database | Preserved: backend refusal does not fetch AWG; only a successful main subscription can fetch its derived `-awg` subscription. IDs/URLs remain bearer credentials; existing weak IDs must be rotated administratively, not silently changed here. |
| Unverified hypothesis / NOT_TESTED | Linux deployment controls, ACME renewal, nginx/access/error logs, firewall, large real subscriptions, reboot behavior | Windows-only safe local tests do not prove Linux ownership/systemd or a live ACME deployment. Apply and validate on an explicitly authorized Linux test host before deployment. |

Clash merge/strip, Mihomo versus Karing/Hiddify/Stash behavior, plain/base64 links, metadata (`expire=0`), browser passthrough and HEAD remain covered. Real loopback HTTPS tests generate temporary synthetic EC certificates locally, confirm a changed certificate is served after reload, and verify a bad replacement retains the working context. They also exposed and fixed the original detached TLS socket leak. Benign aliases and YAML merge keys are supported within limits. Rejecting malformed, recursive, excessive subscriptions, public plaintext listeners, arbitrary upstream origins and root execution is intentional security behavior. Socket timeouts are inactivity timeouts, not a total wall-clock deadline; bounded worker capacity limits but does not eliminate slow-client denial of service. Keep a reverse proxy/rate limiting for an Internet-facing installation. No installer/admin command, production service or external network call was executed by this child.

## 1. Dedicated identity and directories

Inside `install_kit_sub()`, replace the old `install -d -m 755 /usr/local/lib/kit-sub /etc/kit-sub` with this block. Keep the other child's package and verified-source setup. No credentials are passed in arguments or logged.

```bash
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
```

After the other child's authenticated Python source has been installed, explicitly set its ownership/mode; do not add back any download:

```bash
  chown root:root /usr/local/lib/kit-sub/kit_sub.py
  chmod 0644 /usr/local/lib/kit-sub/kit_sub.py
```

## 2. Protected TLS publication and renewal helper

Add the following function immediately before `install_kit_sub()`. It only installs a root-only local helper and its local root timer; it neither modifies ACME code nor changes ACME's existing x-ui/nginx reload hooks. Source keys remain root-only. The dedicated service receives **read-only copies of this one certificate/key**, not access to `/root`, ACME account credentials, or the x-ui database. Publication is a symlink swap of a validated, complete generation; failed/mismatched renewals retain the previous generation. The helper emits fixed errors only.

```bash
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
}
```

The root helper is narrowly administrative, never the network-facing daemon. `CAP_CHOWN` is needed to publish `root:kit-sub` files; the main daemon has **zero capabilities**. Helper directories and config are not writable by kit-sub. Its private network forbids external traffic. Timer interval is independent of the ACME implementation; unchanged copies are not rewritten. The Python listener adopts a changed valid pair at its next 600-second reload check, without mutating active handshake contexts. Nginx still owns its own source cert/key and reload schedule in single-port mode.

## 3. Exact config block replacement

Replace the `if [[ $SINGLE == yes ]]; then ... chmod 600 /etc/kit-sub/config.json` block inside `install_kit_sub()` with:

```bash
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
```

Do not use `chown kit-sub` on config, certificate, key, unit or source code. `root:kit-sub 0640`, directories `0750`, means read-only access for the daemon and no access for unrelated users. The single-port branch stops the old listener and publisher before deleting only protected copies; it never deletes the source certificate/key needed by nginx. Keep root-only rollback backups before any upgrade; do not grant the single-port process extra permissions to do cleanup itself. Generated listener ports must be >1023; do not reintroduce `CAP_NET_BIND_SERVICE` just to support an arbitrary privileged port (443 belongs to nginx in single-port mode).

## 4. Exact kit-sub unit replacement

Replace the entire `cat >/etc/systemd/system/kit-sub.service <<'UNIT' ... UNIT` block with:

```bash
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
```

Keep the existing `systemctl daemon-reload`, kit-sub enable/restart and port wait. Between daemon-reload and kit-sub enable/restart add:

```bash
  if [[ $SINGLE != yes ]]; then
    systemctl enable --now kit-sub-tls-sync.timer >/dev/null 2>&1
  fi
```

No `ReadWritePaths` for the network daemon, no home traversal, no root UID, no supplementary privileged groups, no bind capability. The 256 MiB limit leaves room for bounded concurrent PyYAML work; the old 64 MiB limit can kill otherwise-valid transforms. Check compatibility of hardening directives with the deployment's systemd version rather than silently weakening the unit.

## 5. Cleanup integration

In the existing stale-install cleanup branch near BASE `3x-ui.sh:129`, before removing `/etc/kit-sub`, add:

```bash
    systemctl disable --now kit-sub-tls-sync.timer >/dev/null 2>&1 || true
    systemctl stop kit-sub-tls-sync.service >/dev/null 2>&1 || true
```

Extend its existing `rm -rf` list with exactly these root-managed installed files:

```bash
      /etc/systemd/system/kit-sub-tls-sync.service /etc/systemd/system/kit-sub-tls-sync.timer \
      /usr/local/sbin/kit-sub-sync-tls
```

Do not delete the system user/group automatically: UID reuse or another process still running under the identity is a worse failure mode. If another uninstall path exists after the supply-chain child's edits, apply the same timer stop/file cleanup there. Preserve x-ui/nginx certificate source files; only the protected copies live under `/etc/kit-sub`.

## 6. Parent verification checklist (Linux actions NOT executed here)

1. First apply snippets onto the finished supply-chain edit; inspect the diff and run `bash -n scripts/3x-ui.sh`. Do not replace authenticated code acquisition with the original `curl` block. Check `python -W error::ResourceWarning -m unittest discover -s tests -p test_kit_sub.py -v` locally (PyYAML required).
2. On an authorized disposable Linux host, validate units with `systemd-analyze verify` before startup; verify `systemctl show kit-sub -p User -p Group -p CapabilityBoundingSet -p AmbientCapabilities -p MainPID` and the actual `/proc/<pid>/status` UID/capabilities. Verify dedicated identity has no login/supplementary groups. Merely seeing `User=` in a file is not proof.
3. With `stat`/`namei` and read/write probes as kit-sub, verify config and copied key are readable but not writable, `/root` and `tls-sources.json` are unreadable, and unrelated users cannot read config/key. Do not output key bytes or config contents. Code/unit/helper must be root-owned and non-writable by kit-sub.
4. Verify both direct TLS and loopback-behind-nginx modes using synthetic subscriptions only; main denial stays denial, no ID/UA/path/payload/error text in app journal. Confirm nginx's error logs and x-ui logs are separately scrubbed or access-controlled: changing kit-sub's logging cannot sanitize other services' logs. TLS-required subscriptions must not appear in shell histories or URL-bearing `curl -v` output.
5. Renew/replace a synthetic source pair, invoke the local sync helper, check only permissions and public certificate fingerprints, and wait for/check the next reload. Confirm old connections work, new handshakes use the new certificate, unchanged sources do not create generations, invalid/mismatched pair leaves previous `current` untouched, and only current/previous generations remain. Do not run a real ACME renewal merely for this test.
6. Verify timer is enabled, listener survives restart and authorized reboot, key copies still update afterward, and `systemd-analyze security kit-sub` reflects the intended controls. Preserve rollback backups of code, config, unit and TLS copies root-only. A rollback to the old root unit also requires rolling back the Python root-refusal change; never claim this live acceptance was performed on the Windows workstation.
