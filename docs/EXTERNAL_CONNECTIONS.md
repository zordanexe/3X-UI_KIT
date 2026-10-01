# External connections and offline security audit

## Final hardening addendum (supersedes the snapshot findings below)

The literal inventory/Appendix B below deliberately records its original pre-integration snapshot, not a false claim that those source hashes describe the final release. Final source identity is the release Git commit plus the bundle SHA256SUMS.

- `scripts/3x-ui.sh` now integrates the dedicated non-root kit-sub service, protected read-only config/key copies, validated atomic TLS generations and root-only publisher timer. Public daemon has no capabilities; root helper only CAP_CHOWN. Source keys remain root:root 0600. Windows fixtures do not verify actual Linux DAC/systemd.
- Installer result is atomically root:root 0600 and credentials/QR are no longer printed. Raw API errors/journal dumps are removed. `kit user link` is still an intentional private operator display.
- `tools/lib/singbox.js` now refuses unsupported certificate pins; generic TLS pins that cannot be represented also fail explicitly. No silent pin→insecure downgrade remains. Explicitly insecure caller inputs remain an operator risk.
- Mihomo controller is now `127.0.0.1:9090`; forwarding `allow-lan` remains unchanged. `external-ui-url` is explicitly empty, removing automatic latest dashboard JS execution. Optional dashboard must be manually reviewed/preinstalled locally. Use SSH tunnel; no LAN HTTP controller instruction remains.
- Router commands now use subshell `umask 077`, 0600 staging before writing, atomic per-file replacement and no restart on write failure. Multi-file publish is not transactional across an abrupt host crash; backups are still required.
- Kit internal executable downloads use verified local release bundle only. 3x-ui/Xray/Hysteria/ACME source/artifacts have reviewed pins; dynamic APT and GeoIP/GeoSite/Mihomo rules are data/package trust as documented in SUPPLY_CHAIN_NOTES.md. Entware/XKeen root-bootstrap commands were withdrawn pending separate router supply-chain audit; links/attribution remain.
- No Linux installer, privileged service, real VPN connectivity, ACME issuance/renewal or reboot acceptance was executed. Browser checks are offline Node/VM tests, not a live browser/router session.

## Scope and evidence boundary

- Audited baseline: `zordanexe/3X-UI_KIT`, branch `security/hardening-v1`, commit `4f1e5d98ccd0e34083e844ed7f4c0849658be7dd` (33 tracked files).
- Literal working-tree snapshot: `2026-10-01T08:39:02+00:00`; **45 source/document files**, **38 files with network literals**, **372 distinct file/kind/redacted-literal records**, **66 distinct literal hosts/IPv4 addresses**. Appendix A includes docs, SVG drawings, tools, tests, and the concurrently added supply-chain/security helpers. Appendix B pins the exact normalized-LF source digests of this snapshot. This report itself and generated untracked `__pycache__` are excluded to avoid recursive self-inventory; `.git` internals are not application source. A literal does not prove a connection occurred.
- Findings citing `BASE` line numbers refer to that immutable baseline, not lines shifted by other hardening edits. New locked-resource rows describe the working-tree lockfile, not a deployed service. Other agents own installer/backend hardening; this audit did not edit production entrypoints.
- No installer, downloaded program, matrix client, root API mutation, service, firewall command, or third-party source upload was executed for this audit. Node tests were inspected first: their imports are pure parsers/config builders; no network or shell children. The added browser checks use a Node VM DOM stub and static source inspection, **not a live browser or live router**.
- Scans and syntax/unit checks are local/offline. Network calls described below are project behavior, **not observed outbound traffic**. No public-domain ownership, DNS responses, TLS endpoints, live token validity, remote firewall, or remote deployment was verified.

## Connection classes (applies to every appendix record)

| Class | Purpose / method | Credentials or private data | Execution / integrity |
|---|---|---|---|
| `CODE` | Download installation/update code; HTTPS GET | No project credentials intentionally sent; peer sees source IP, TLS/HTTP metadata; ambient proxy configuration may apply | Shell/native/Python code eventually runs, often as root. Pin + locally trusted SHA256 required. See locked assets table; baseline mutable paths are not authenticated by a tag alone. |
| `RULE` | Runtime rule/geo data; HTTPS GET, periodic | No standing credential; peer sees source IP/timing | Data, **not shell execution**. Mutable routing content can reroute/bypass/block traffic and parsers remain attack surfaces. No content hashes in generated browser configs. |
| `DASH` | Runtime dashboard ZIP; HTTPS GET | Download itself needs no token; loaded dashboard code interacts with controller and its secret | **Executable browser JS**, not harmless rule data. `latest` URL has no version/hash pin. |
| `PROBE` | HTTP GET health check or TLS/TCP handshake | No user password deliberately placed in request; sees source/proxy exit IP and timing | No downloaded code; result influences routing/selection. |
| `API` | Loopback 3X-UI GET/POST admin API | Bearer API token; POST bodies include private keys, passwords, user/account metadata | Mutates local panel/configuration; not an external analytics service. TLS verification disabled on baseline loopback calls (`-k`). |
| `SUB` | Subscription HTTP(S) GET/HEAD | Subscription path is a **bearer credential**; response contains proxy passwords/private keys; Host/UA metadata forwarded | Configuration parsed by clients, not installer code; provider origin can change client proxies/rules. HTTP transports expose bearer data on a non-loopback network. |
| `DOC` | User-clicked documentation/repo/donation page or displayed badge; GET | No connection input is appended; normal browser IP/referrer/cookies apply, payment data only if user voluntarily enters it on donation site | Not automatically executed by project. README badge images are remote assets, not tool-page telemetry. Manual install commands can explicitly elevate to `CODE`. |
| `NS` | SVG namespace identifier | None | `http://www.w3.org/2000/svg` is **not a fetch**. |
| `FIXTURE` | Parser/test/drawn-example placeholder | Synthetic credentials only; never report their literal values as a rotation incident without provenance | Node fixtures do not connect. Matrix fixtures may connect/mutate **only if explicitly executed** in a disposable lab. |
| `LOCAL` | Loopback/LAN listener, router UI/SSH, subnet or bind address | Controller secret, subscription or SSH credentials where applicable | Exposure depends on actual bind/firewall; a `0.0.0.0` listener is not proof of Internet reachability. |

## Runtime / installer network map

| Source (BASE evidence unless noted) | Destination / purpose | Method and credentials | Executed? Version / hash / risk |
|---|---|---|---|
| `scripts/3x-ui.sh:51-57`, `scripts/hysteria2.sh:70-76` | `api.ipify.org`, `ifconfig.me/ip`, `ipv4.icanhazip.com`: public IPv4 discovery | GET; no application secret; reveals server IP to three third parties | Text response only; no hash/version, IPv4-shaped validation |
| `scripts/3x-ui.sh:25,69-72,207-223` | `dl.google.com`, `www.amazon.com`, `www.samsung.com`, `www.yahoo.com`, user `--sni`; fallback `www.cloudflare.com` | TLS 1.3 handshake on TCP 443, ALPN h2; no proxy password | REALITY camouflage target/probe, not code download or telemetry beacon |
| `scripts/3x-ui.sh:637-640` | Telegram IPs `149.154.167.51`, `149.154.175.50`, `91.108.56.130`, TCP 443 | TCP reachability probe | Not HTTP POST/GET; no downloaded code. Installed MTProto subsequently carries user traffic to Telegram DCs |
| `scripts/3x-ui.sh:629`; `tests/matrix/mk-inbounds.sh:62` | `1.1.1.1`, `8.8.8.8`, `8.8.4.4` | Generated AmneziaWG DNS settings; DNS query, not HTTP | Runtime third-party DNS receives resolver-visible domain metadata; `ip route get 1.1.1.1` is a local route lookup, not necessarily a packet |
| `scripts/3x-ui.sh:236-244` | Baseline `raw.githubusercontent.com/MHSanaei/3x-ui/v3.8.5/install.sh` | GET; panel password/token generated locally and passed to child installer environment | **Root shell**; baseline no independently pinned content hash; replaced path owned by supply-chain hardening |
| `scripts/3x-ui.sh:715-733,913-926`; `scripts/hysteria2.sh:15,106-113,424-431` | Baseline kit CLI, kit-sub, hy2 self-update at upstream `main` | GET, no project credentials intended | Root shell / Python service; baseline mutable and unpinned. Syntax checks do not authenticate content. Prefer verified local fork bundle |
| `scripts/hysteria2.sh:13,90-103` | `github.com/HyNetworks/hysteria/releases/download/app/v2.12.3/hysteria-linux-{amd64,arm64}`, `hashes.txt` | HTTPS GET | Native server binary executes as `hysteria`; baseline checksum fetched from same mutable release authority, not an independent trust anchor. Current lockfile pins expected hashes locally |
| `scripts/3x-ui.sh:278-289` | Local API requests Xray core `v26.6.27`; upstream panel performs fetch | POST with bearer token | Native code supply chain delegated in BASE; explicit locked Xray assets now present in working-tree helper. Actual install not run here |
| `scripts/3x-ui.sh:77-95,255,459-470`; `scripts/kit.sh:27-42,49-72,121,175,211`; `tests/matrix/{mk-inbounds,awg-set}.sh` | `http(s)://127.0.0.1:<panel>/<base>/panel/api` | GET `server/getNewUUID`, `getNewX25519Cert`, `inbounds/list`, `clients/list`; POST settings, `inbounds/add/update`, client add/attach/update/delete, Xray installation | Admin bearer token in curl arguments, private credentials in some `jq --arg` / `curl -d` argv. Loopback requests are not third-party exfiltration, but multi-user hosts/process inspection and diagnostic logs need protection |
| `scripts/3x-ui.sh:845-858,880-982`; `scripts/kit.sh:134-138`; `scripts/kit-sub.py:48-60` | Public HTTPS subscription → nginx/kit-sub → fixed loopback 3X-UI subscription | GET/HEAD; bearer subscription ID in path; response contains connection secrets | Dynamic credentials/configuration, no code eval. BASE urllib follows redirects and honors environment proxies; child hardening owns that boundary |
| `tools/lib/mihomo.js:5-26,233-237` | MetaCubeX `meta-rules-dat/meta/geo/`: `geosite/{youtube,telegram,meta,twitter,discord,category-ai-!cn,tiktok,spotify,netflix,github,twitch,category-ads-all}.mrs`; `geoip/{telegram,facebook,twitter,netflix}.mrs` | Runtime GET once/day, router/client, **not the generator browser** | `RULE`: mutable meta branch, no content pin; filenames concatenated in JS, hence expanded here |
| `tools/lib/mihomo.js:6,10-11,233-236` | `github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/{domain-rule,ip-rule}.mrs` | Runtime GET once/day | `RULE`: mutable main branch, no content pin |
| `tools/lib/mihomo.js:197` | `github.com/Zephyruso/zashboard/releases/latest/download/dist.zip` | Runtime GET to install external UI | `DASH`: mutable **executable JS dashboard**, no version/hash pin |
| `tools/lib/mihomo.js:207-213`; `tools/mihomo/index.html:80` | User-supplied `opts.subscription` HTTP or HTTPS URL | Router/client GET hourly; URL can contain bearer ID/userinfo; no browser fetch | `SUB`: third-party origin selected by user; HTTP accepted and not upgraded; server supplied config trusted by the client |
| `tools/lib/xray.js:175`; `tools/lib/mihomo.js:211,219`; `tools/lib/singbox.js:83` | `www.gstatic.com/generate_204` | Runtime GET, Xray multi-proxy every minute; Mihomo/sing-box every 5 minutes | `PROBE`, not browser analytics. Reveals proxy exit/timing; no payload credential in URL |
| `tests/matrix/matrix-run.sh:10` | `www.google.com/generate_204` via local SOCKS5 proxy | GET; connectivity test, no user credential appended | Disposable lab only; binaries are launched, global-name `pkill` used |
| `manuals/xkeen-keenetic.md:29-31,51,61,65` | Entware installer tarballs; XKeen JSON token template `2.0.1_Beta`; XKeen `main/install.sh` raw GitHub or jsDelivr | Manual GET; user later writes Keenetic access token into router JSON, **not** into download request | Entware/XKeen shell code executes on router; manual commands lack independent hash pin. jsDelivr revision `@main` is not a username/password credential |
| `README.md:7-9,88-89`, `index.html:3-5`, tool headers/footers and manuals | Shields badges, GitHub/GitHub Pages, Keenetic support, CloudTips, Buy Me a Coffee | Browser GET only on page render/click/redirect; normal metadata/cookies | `DOC`: no connection-password upload in audited tool code; SVG drawings are local assets |
| Installer package steps (`3x-ui.sh:199-202,756,917`, `hysteria2.sh:83-87`), manual `opkg` | Configured APT/OPKG mirrors (not literal domains) | Package metadata/archive GET; system package-manager trust/config applies | Packages contain privileged executable code; DNS/mirror/CA/maintainer hooks not fully enumerated by this repo |
| `tests/supply_chain/fetch_pinned.py:24-36` | URLs inherited from the local executable-resource lock below | HTTPS GET when explicitly run; no application credentials; populates a specified local audit cache | Test-preparation downloader, not an offline regression. It reads an ACME archive member but never executes downloaded code. **Not run by `security-check.sh` or this audit.** |
| Certificate issuance and renewal delegated to upstream ACME/Hysteria | Configured ACME CA directory/challenge endpoints and user domains (dynamic, not all spelled in this repo) | ACME HTTPS GET/POST signed with account key; email/IP/domain disclosed to CA; HTTP challenge inbound port 80 | Certificate protocol, not app telemetry. No CA-account secret intentionally posted to arbitrary project endpoints |

The complete set of concrete URLs/hosts by file is in Appendix A. Automatic redirect targets, release/CDN storage hosts, downloaded-package dependencies, external proxy endpoints chosen by users, runtime DNS-resolved addresses, CA configuration, and OS mirrors are **dynamic**, not an exhaustive static allowlist. No DNS lookups were used to invent a supposed observed traffic list.

## New locked executable resource inventory

Source: `scripts/supply-chain.lock.json`; transport implemented by `scripts/supply-chain.py:25-46`. All rows are HTTPS **GET**, no project bearer/password intentionally attached. The helper validates initial GitHub-family host, rejects URI credentials, ignores curlrc, requires HTTPS redirects, and verifies the **locally recorded** SHA256 before atomic replacement. The lockfile is the trusted policy; a checksum only authenticates a resource if this lock/bundle is itself trusted. File hashes and downloaded code were not independently refetched by this auditor. Transitive server/OS behavior remains outside this static table.

| Asset / eventual use | Version / revision | URL | Locked SHA256 |
|---|---|---|---|
| `x-ui.sh` — root shell installer/menu/init | `7ef22f94c950ff09f0870e2295fa65ad5968742c` | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.sh` | `7f64543f783b0939dbf803bb24b835c80edb04daca70dbcb3ecf69e2a5ce3ab5` |
| `x-ui.rc` — root shell installer/menu/init | `7ef22f94c950ff09f0870e2295fa65ad5968742c` | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.rc` | `987847aecb523d911cacb465e98f0892a7a95b476311947cc6baad51dcb98a56` |
| `x-ui.service.debian` — systemd executable service definition | `7ef22f94c950ff09f0870e2295fa65ad5968742c` | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.service.debian` | `513f84fd2be16e3eec41e61acdd72c32cc639715eb4105e6dd9dc5ff190e5aec` |
| `x-ui.service.arch` — systemd executable service definition | `7ef22f94c950ff09f0870e2295fa65ad5968742c` | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.service.arch` | `4d55c7cdfd05cbdf1ed54b0d5fecdc79ca8fbe8d48fc7a1460db1d89c3762242` |
| `x-ui.service.rhel` — systemd executable service definition | `7ef22f94c950ff09f0870e2295fa65ad5968742c` | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.service.rhel` | `8669748361612b2ee17f2d03ffc43520c91ef39b0cb343712608bfc965ab518c` |
| `acme.tar.gz` — ACME shell code | `807da6498377ee5e0cf43a78091f46f12dc59a89` | `https://codeload.github.com/acmesh-official/acme.sh/tar.gz/807da6498377ee5e0cf43a78091f46f12dc59a89` | `ddbe1bcbd1a44a2623a2af167ebdc678669e6e2eb396742f2d1d28e02dc14220` |
| `x-ui-linux-386.tar.gz` — panel/native + bundled helpers | `v3.8.5` | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-386.tar.gz` | `f13691655dc274479ebbdd1cba5eb32c978728df2457c0b73f9f687a0eca09ac` |
| `x-ui-linux-amd64.tar.gz` — panel/native + bundled helpers | `v3.8.5` | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-amd64.tar.gz` | `6a85c110a04a727613c933c54ae602b8d37dab8876c6e20a6d46623010dd9d3c` |
| `x-ui-linux-arm64.tar.gz` — panel/native + bundled helpers | `v3.8.5` | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-arm64.tar.gz` | `2dd601a32426fb19b0eafdffaead374a9cdb66be4dfb39407f9f50fa4e7234e7` |
| `x-ui-linux-armv5.tar.gz` — panel/native + bundled helpers | `v3.8.5` | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-armv5.tar.gz` | `fe90376169675d40f5e3e67364b1b157e38f16441c41b01023e20fc79a7c5d2d` |
| `x-ui-linux-armv6.tar.gz` — panel/native + bundled helpers | `v3.8.5` | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-armv6.tar.gz` | `b01518d413086caef719f29f7c81c15dbeec0939cc55a4bf63a1d4edcdb94dea` |
| `x-ui-linux-armv7.tar.gz` — panel/native + bundled helpers | `v3.8.5` | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-armv7.tar.gz` | `2f19d148b05611c3245f50cbad24b9bb13cf52754981ee2a4fc24cc332402473` |
| `x-ui-linux-s390x.tar.gz` — panel/native + bundled helpers | `v3.8.5` | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-s390x.tar.gz` | `f5fc7593c35c3135f7e905f77c727a2a5becea3880273255ab57a62430441148` |
| `hashes.txt` — checksum data (not execution) | `2.12.3` | `https://github.com/HyNetworks/hysteria/releases/download/app/v2.12.3/hashes.txt` | `a06953ac984ece521b564dae9348bd652942f7ddc07f985707ea67ce54474ad9` |
| `hysteria-linux-amd64` — native Hysteria server | `2.12.3` | `https://github.com/HyNetworks/hysteria/releases/download/app/v2.12.3/hysteria-linux-amd64` | `8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e` |
| `hysteria-linux-arm64` — native Hysteria server | `2.12.3` | `https://github.com/HyNetworks/hysteria/releases/download/app/v2.12.3/hysteria-linux-arm64` | `c8dc653c3ba0a28d29a26b8fa52d2086f27c0927afddce95c09965e7174e78b0` |
| `Xray-linux-32.zip` — native proxy core | `v26.6.27` | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-32.zip` | `a30a7bc601ca4be80675ab862cbeae4cadb0bc3242ffb687fb6865b67b8c4e8f` |
| `Xray-linux-64.zip` — native proxy core | `v26.6.27` | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-64.zip` | `b3e5902d06d6282fe53cfa2fc426058b9aeaa429b2c812e20887cd47f26d08bf` |
| `Xray-linux-arm32-v5.zip` — native proxy core | `v26.6.27` | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-arm32-v5.zip` | `cec3aad9095bba4fdfcbff6dedaa11bc98f945e35186a1f228efaaa28e99c8b2` |
| `Xray-linux-arm32-v6.zip` — native proxy core | `v26.6.27` | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-arm32-v6.zip` | `d6a48164f73281e5213a27ee46cac4078df786acf15014c3bad1cb49d1bc1ec6` |
| `Xray-linux-arm32-v7a.zip` — native proxy core | `v26.6.27` | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-arm32-v7a.zip` | `c77245cf9bfd6b8ae0fa8247cd65a3478f1951e9712fcde0f0dda4a31e2ac26c` |
| `Xray-linux-arm64-v8a.zip` — native proxy core | `v26.6.27` | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-arm64-v8a.zip` | `13a251379bea366c2cf10363ad71e75734193d401f26f518bf0c25e5c8f8c931` |
| `Xray-linux-s390x.zip` — native proxy core | `v26.6.27` | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-s390x.zip` | `be883d2b998b238421838fe29e8dd7b4b731e23def7712c3bbdac04e16319524` |
| `xui-install.sh` — root shell installer/menu/init | `7ef22f94c950ff09f0870e2295fa65ad5968742c` | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/install.sh` | `4e3fe7fe00ef8e904ce6a0e9c36fd8a0c7179fe5e786f23e31801aee84c6347d` |

## Browser privacy, persisted credentials and exposure findings

### Confirmed vulnerability

1. **Medium: sing-box Hysteria2 pin silently downgrades to no verification.** `BASE tools/lib/singbox.js:47-50` maps a non-empty certificate pin to `tls.insecure: true`; it does not implement pin validation. A link intending to authenticate one self-signed certificate becomes vulnerable to MITM when consumed through this builder. Reproduced offline by `tests/security_browser.test.js` using a synthetic proxy: generated `tls.insecure` is true. Production source was intentionally left untouched. Prefer a trusted certificate or an actually supported pin mechanism; warn/refuse unsupported pin-only links instead of disabling verification. This also affects matrix output at `matrix-gen.js:29`, not either interactive HTML generator (which uses Xray/Mihomo).
2. **Medium, fixed in allowed scope: blanket chmod made matrix private key world-readable.** `BASE tests/matrix/mk-inbounds.sh:9` applied 0644 to `/root/cert/*`. Replaced only with 0600 for `key`, 0644 for `crt`; static regression verifies no wildcard permission broadening. Actual unprivileged readability additionally depends on parent directory permissions (`/root` commonly restricts traversal). No lab/server installation was run to claim live permission proof.

### Intentional or standard design (with residual risk)

- **No browser exfiltration/telemetry path found in inspected source.** Interactive pages load only relative JS/CSS and an inline data favicon; no fetch, XHR, WebSocket, beacon, analytics SDK, iframe, remote script, cookie or service-worker code. DOM output uses `textContent` or HTML escaping; hostile fixture names/errors remained escaped in the VM check. An absence-of-pattern assertion is a regression check, not a sandbox/proof against future obfuscated code or a compromised hosting origin.
- **localStorage is preferences-only.** `tools/lib/ui.js:7-10` uses `pm:xray` and `pm:mihomo`; exact payloads at `tools/xray/index.html:126`, `tools/mihomo/index.html:94` persist selected services/bases/flags/tag. They omit pasted links, subscription URL, controller secret, proxy/direct domains, passwords and private keys. Pasted links and output remain in page memory/DOM until navigation; browser form recovery/extensions/clipboard/download retention are outside project guarantees. Mihomo secret is generated in memory from 12 random bytes, not stored by `store.set`.
- **Generated files intentionally contain plaintext connection credentials.** JSON/YAML outputs, clipboard/QR and downloaded files contain passwords/private keys/bearer URLs. `UI.routerCommand` writes quoted, collision-resistant heredocs to constant directories/filenames; an offline test confirms shell substitutions in config text remain literal. It does **not** set a restrictive umask/chmod. Router file confidentiality depends on directory/default umask, backups, shell scrollback and clipboard. This audit did not alter the generator. Protect configuration files at 0600/parent 0700 and clear shared clipboard/terminal history as appropriate.
- **Mihomo controller is LAN-exposed by design.** `tools/lib/mihomo.js:188,194-197` sets `allow-lan: true`, controller `0.0.0.0:9090`, random secret and auto-downloaded latest dashboard. Generator help uses plain HTTP to router `192.168.1.1:9090/ui`. Secret authentication is present; plaintext LAN transport and unpinned UI increase risk. Prefer loopback/trusted-LAN restriction, no WAN publication, TLS/SSH tunnel, version-pinned reviewed UI. Live router firewall reachability was not tested.
- **BASE firewall rules are additive, not an allowlist reset.** `scripts/3x-ui.sh:319-329` / `hysteria2.sh:212-225` add required UFW ports and enable UFW; pre-existing rules/listeners remain. `--no-ufw` explicitly opts out; UFW failure warns and continues. Claims of “only these ports exposed” require an actual UFW/nftables/cloud firewall/listener check. Exposing proxy/SSH ports for their intended users is not itself a vulnerability.
- **BASE single-port external ingress is still public.** nginx listens IPv4+IPv6 443 (`3x-ui.sh:819-827`); random panel path and password protect panel access, not port secrecy. Internal panel/protocol/subscription listeners become loopback; multi-port trusted-certificate mode opens panel/subscription/protocol ports, while certificate-less panel/subscription are loopback. Extra UDP proxy ports remain intentionally external. Provider/IPv6 firewalls and actual binding were not exercised.
- **Subscription path is authentication material.** Sharing/logging a URL can reveal all delivered connection credentials. User-Agent format detection is not an access-control check. BASE nginx disables access logging, kit-sub disables standard request logs, and result files are intended root-only; errors/upstream-library logging still require review (owned by backend hardening).
- **Persistent server secrets:** `BASE 3x-ui.sh:350-361` writes `/root/3x-ui.txt` after umask 077; `/etc/kit/kit.env` gets 0600 and `/etc/kit` 0700 (`718-727`); config `/etc/kit-sub/config.json` 0600 (`936`); self/imported TLS private keys 0600 (`196,417`). Panel credential `.env` is sourced from upstream installer, whose ownership/mode was not established by this audit. `/var/log/3x-ui-install.log` is created before umask tightening and may contain upstream installer credentials: log contents/mode not live-verified. Hysteria state/users/key are 0600, config root:hysteria 0640, directories 0750, service runs as hysteria with restricted capabilities (`hysteria2.sh:124-203,305-323`). Backups/results/terminal output must be treated as sensitive.
- Admin credentials in `curl -H`, POST data and `jq --arg` are process-argument exposure on hosts permitting other users to inspect argv. Secrets in a protected file are not therefore absent from process listings. Use stdin/protected descriptors where practical; live `/proc` policy is unknown.

### Confirmed functional defect

- Both HTML pages use `JSON.parse(store.get(...) || '{}')` without catching malformed persisted JSON (`xray:69`, `mihomo:66`). A corrupted preference entry can stop rendering; clearing that localStorage entry recovers it. No remote exploit or credential disclosure is established.

### Unverified hypothesis / not tested

- Installed panel upstream authentication/session behavior, transitive binary telemetry, real proxy-provider/rule data behavior, CA/account state, trusted TLS checks in actual clients, WAN/IPv6/cloud firewall exposure, installed config ownership, service restart/reboot, and every row of the real protocol matrix. Prior author matrix results are not current audit results.
- External code dependency CVEs were not checked online; no unsupported CVE claims are made.

### Installation decision

Source audit and offline checks are suitable for parent review, **not production acceptance**. The unchanged sing-box pin downgrade, router file-permission/controller/UI risks, and dynamically trusted rules remain. Concurrent kit-sub root-refusal needs its matching non-root service/TLS integration; `KIT_SUB_INTEGRATION.md` is a proposal until the parent applies and verifies it. Do not infer that current installer/service changes were deployed or validated on Linux.

## Tests and secret-fixture provenance

- `tools/test/links.test.js` originated in upstream commits `aebfb157809b` (initial generators), `78935727bede` (protocol expansion), `5958eceefbf4` (latest fixture form), all predating the supplied BASE. Fixtures use RFC 5737 documentation networks `203.0.113.0/24`, `198.51.100.0/24`, and example.com hosts; WireGuard placeholders encode short dummy words, public REALITY keys are not private signing credentials. The long Shadowsocks password is in a documentation-network test fixture, not evidence of a live account. No secret value is reproduced in this report.
- SVG installation drawings are upstream example illustrations, not captured user-server outputs: documentation IPs/example.com, drawn usernames/passwords/links. `script-hy2-add.svg` traces to `5edd23bd2b87`; Hysteria illustration revisions to `5edd23bd2b87` / `2b938baa31ba`; 3X-UI drawings to `5edd23bd2b87`, `2b938baa31ba`, `5958eceefbf4`, `58aaf726905c`, `201e3d781173`.
- Scanner exemptions are **path + entire normalized-LF SHA256**, never a blanket test-directory rule. Changing a fixture invalidates the exemption, and a test proves a newly appended provider token is caught. Exact fixture digests and explanatory provenance are in `scripts/security_scan.py:REVIEWED_FIXTURES`. One exact synthetic HTTP user/password authority in `tests/test_kit_sub.py` is value-fingerprinted and path-scoped. Explicit non-live `synthetic` marker is not a provider-token exemption. New regression credentials are generated in disposable temp directories, not copied from accounts; test Git history is local synthetic temp history, never a commit in this project.
- `tests/matrix/matrix-gen.js:7` recursively removes its output directory; writes secret-bearing config files without mode control (`23-33`), sets weak test controller secret, and enables insecure TLS when PIN is supplied (`11-13`). `singbox.js` also turns a pin into insecure mode. `matrix-run.sh` starts proxy binaries, makes actual outbound Google requests and kills **all same-name client processes** with `pkill` (`6-14`). `awg-set.sh` modifies server config via POST and prints secret-bearing VPN links (`21-23`). `mk-inbounds.sh` creates API inbounds with wildcard/default listen. These were not run; README now warns to use an isolated disposable lab only.

## Offline tooling and actual local verification

Run from a checkout with Bash, Python 3.9+ and Node.js 18+:

```bash
bash scripts/security-check.sh
bash scripts/security-check.sh --history
python -B scripts/security_scan.py --history --json
```

`security-check.sh` only syntax-checks shell/Python/JS and runs the inspected Node tests plus scanner/matrix guard regressions. It never runs installation entrypoints or the network matrix. ShellCheck is optional, explicitly reported `NOT_TESTED` if absent; no automatic installs or online audits.

Scanner rules cover provider tokens (GitHub/AWS/Google/Slack/Stripe/Telegram/OpenAI/Anthropic), PEM/OpenSSH private-key markers, JWT/Bearer/query credentials, contextual literal passwords/keys, URI authority secrets and encoded VPN/VMess/Shadowsocks payloads. The scanner reads tracked plus non-ignored untracked files; tracked caches are not exempt, only **untracked** generated `__pycache__` is skipped. Git history scans every locally reachable blob across refs without network access. ZIP/TAR/GZIP members are inspected in memory, not extracted/executed; per blob/archive limits are 16 MiB, 512 members, nesting depth 4. Unreadable/unsafe/unsupported encrypted/binary store or exceeded limit returns **2 (incomplete)**, candidates return **1**, no unsuppressed candidates returns **0**. Output includes only path/line/rule, never value/context/prefix. Unknown opaque values, custom encodings, encrypted stores, ignored/unreachable Git objects and provider-side dangling history are not covered; no candidate does **not** prove absence of all secrets.

Executed locally on Python **3.14.7**, Node **26.7.0**: original Node suite **14/14 pass**; original + added browser/security audit checks **20/20 pass**; scanner/matrix/wrapper regressions **13/13 pass**; shell/Python/JS syntax checks pass; offline current tree (**46 files**, including this report) + **178 locally reachable history blobs**, **0 unsuppressed candidates**, **0 scan errors** (15 exact reviewed fixture file/blob exemptions). ShellCheck absent. No installers, Docker protocol matrix, or live firewall/service were run. `git diff --check` now passes; concurrent hardening is captured only at the declared snapshot. Counts above identify the literal-source snapshot; current scan includes the newly created report when re-run.

## Appendix A: complete file-indexed literal inventory

Every row is a source literal/template/reference, **not measured traffic**. Proxy authority, encoded credential payloads and sensitive query values are redacted; identical redacted references in one file are merged. Runtime-expanded endpoints are listed in the main map; variables/fragments remain literal rather than guessed/normalized to an invented hostname. `scheme://` is a format placeholder, not a transport. Classification covers purpose, GET/POST/other, credentials and execution using the class table above. A URL can appear both as a URL and its host: counts describe records, not unique network flows. Generic URI schemes and domain/IPv4 literals were inventoried across every source/document file in Appendix B. Generated bundles/ignored local data, `.git` internals and this report are excluded; there were no tracked binary archive inputs. Dynamic downstream dependencies are described above, not claimed as a complete static allowlist.

### `KIT_SUB_INTEGRATION.md`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://127.0.0.1:$SUB_INTERNAL` | 176, 180 | LOCAL / SUB (proposed service integration) |
| host | `0.0.0.0` | 181 | LOCAL / SUB (proposed service integration) |
| host | `127.0.0.1` | 176, 177, 180 | LOCAL / SUB (proposed service integration) |

### `README.md`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://buymeacoffee.com/relo.cate` | 103 | DOC |
| URL | `https://github.com/MHSanaei/3x-ui` | 8, 18, 139 | DOC |
| URL | `https://github.com/MetaCubeX/mihomo` | 141 | DOC |
| URL | `https://github.com/RockBlack-VPN/ip-address` | 93 | DOC |
| URL | `https://github.com/XTLS/Xray-core` | 140 | DOC |
| URL | `https://github.com/amnezia-vpn` | 143 | DOC |
| URL | `https://github.com/apernet/hysteria` | 142 | DOC |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 48, 130 | DOC |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT/commits` | 9 | DOC |
| URL | `https://github.com/jameszeroX/XKeen` | 91, 144 | DOC |
| URL | `https://github.com/jameszeroX/XKeen/wiki` | 91 | DOC |
| URL | `https://github.com/zordanexe/3X-UI_KIT/releases/download/secure-v1.0.0/3X-UI_KIT-secure-v1.0.0.tar.gz` | 53 | DOC → CODE (authenticated release bundle) |
| URL | `https://github.com/zordanexe/3X-UI_KIT/releases/download/secure-v1.0.0/SHA256SUMS` | 54 | DOC → CODE (authenticated release bundle) |
| URL | `https://github.com/zxc-rv/XKeen-UI` | 92 | DOC |
| URL | `https://img.shields.io/badge/3X--UI-v3.8.5-3fb950` | 8 | DOC |
| URL | `https://img.shields.io/badge/протоколов-11-3fb950` | 7 | DOC |
| URL | `https://img.shields.io/github/last-commit/itsnotkubrick/3X-UI_KIT?label=обновлено&color=3fb950` | 9 | DOC |
| URL | `https://itsnotkubrick.github.io/3X-UI_KIT/tools/mihomo/` | 87 | DOC |
| URL | `https://itsnotkubrick.github.io/3X-UI_KIT/tools/xray/` | 86 | DOC |
| URL | `https://pay.cloudtips.ru/p/d4f9e3d1` | 102 | DOC |
| host | `buymeacoffee.com` | 103 | DOC |
| host | `github.com` | 8, 9, 18, 48, 53, 54, 91, 92, 93, 130, 139, 140, 141, 142, 143, 144 | DOC |
| host | `img.shields.io` | 7, 8, 9 | DOC |
| host | `itsnotkubrick.github.io` | 86, 87 | DOC |
| host | `pay.cloudtips.ru` | 102 | DOC |

### `SUPPLY_CHAIN_NOTES.md`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://api.github.com/repos/HyNetworks/hysteria/releases/tags/app/v2.12.3` | 34 | DOC (pin provenance; GET, no project credentials) |
| URL | `https://api.github.com/repos/MHSanaei/3x-ui/commits/v3.8.5` | 29 | DOC (pin provenance; GET, no project credentials) |
| URL | `https://api.github.com/repos/MHSanaei/3x-ui/releases/tags/v3.8.5` | 30 | DOC (pin provenance; GET, no project credentials) |
| URL | `https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.6.27` | 35 | DOC (pin provenance; GET, no project credentials) |
| URL | `https://api.github.com/repos/acmesh-official/acme.sh/commits/3.1.6` | 32 | DOC (pin provenance; GET, no project credentials) |
| URL | `https://codeload.github.com/acmesh-official/acme.sh/tar.gz/807da6498377ee5e0cf43a78091f46f12dc59a89` | 33 | DOC (pin provenance; GET, no project credentials) |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/install.sh` | 31 | DOC (pin provenance; GET, no project credentials) |
| host | `api.github.com` | 29, 30, 32, 34, 35 | DOC (pin provenance; GET, no project credentials) |
| host | `codeload.github.com` | 33 | DOC (pin provenance; GET, no project credentials) |
| host | `raw.githubusercontent.com` | 31 | DOC (pin provenance; GET, no project credentials) |

### `docs/SECURITY_MODEL.md`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 3 | DOC |
| host | `127.0.0.1` | 25 | DOC |
| host | `203.0.113.10` | 23 | DOC |
| host | `github.com` | 3 | DOC |
| host | `localhost` | 25 | LOCAL |

### `index.html`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 3, 4, 5 | DOC |
| host | `github.com` | 3, 4, 5 | DOC |

### `manuals/3x-ui.md`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://github.com/MHSanaei/3x-ui` | 5 | DOC |
| URL | `tg://` | 90, 104 | DOC |
| URL | `vpn://` | 90, 104 | DOC |
| host | `github.com` | 5 | DOC |
| host | `www.samsung.com` | 118 | DOC |

### `manuals/assets/banner.svg`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 1 | NS |
| host | `www.w3.org` | 1 | NS |

### `manuals/assets/entware-installer.svg`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 1 | NS |
| host | `192.168.1.1` | 1 | FIXTURE |
| host | `www.w3.org` | 1 | NS |

### `manuals/assets/keenetic-components.svg`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 1 | NS |
| host | `www.w3.org` | 1 | NS |

### `manuals/assets/keenetic-opkg.svg`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 1 | NS |
| host | `www.w3.org` | 1 | NS |

### `manuals/assets/script-3x-ui.svg`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 1 | NS |
| URL | `https://203.0.113.10/[REDACTED-SUBSCRIPTION-OR-PANEL-PATH]` | 1 | FIXTURE |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 1 | FIXTURE |
| URL | `https://raw.githubusercontent.com/…/scripts/3x-ui.sh` | 1 | FIXTURE |
| host | `203.0.113.10` | 1 | FIXTURE |
| host | `dl.google.com` | 1 | FIXTURE |
| host | `github.com` | 1 | FIXTURE |
| host | `raw.githubusercontent.com` | 1 | FIXTURE |
| host | `www.w3.org` | 1 | NS |

### `manuals/assets/script-hy2-add.svg`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 1 | NS |
| URL | `hy2://[REDACTED]@hy.example.com:443/?sni=hy.example.com#friend` | 1 | FIXTURE |
| host | `hy.example.com` | 1 | FIXTURE |
| host | `www.w3.org` | 1 | NS |

### `manuals/assets/script-hysteria2.svg`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 1 | NS |
| URL | `https://raw.githubusercontent.com/…/scripts/hysteria2.sh` | 1 | FIXTURE |
| URL | `hy2://[REDACTED]@hy.example.com:443/?sni=hy.example.com#admin` | 1 | FIXTURE |
| host | `example.com` | 1 | FIXTURE |
| host | `hy.example.com` | 1 | FIXTURE |
| host | `raw.githubusercontent.com` | 1 | FIXTURE |
| host | `www.w3.org` | 1 | NS |

### `manuals/assets/xkeen-configs.svg`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 1 | NS |
| host | `www.w3.org` | 1 | NS |

### `manuals/hysteria2.md`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://github.com/HyNetworks/hysteria` | 5 | DOC |
| URL | `hy2://` | 17, 38, 46 | DOC |
| host | `github.com` | 5 | DOC |

### `manuals/xkeen-keenetic.md`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz` | 31 | DOC → CODE if manually executed |
| URL | `https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz` | 29 | DOC → CODE if manually executed |
| URL | `https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz` | 30 | DOC → CODE if manually executed |
| URL | `https://github.com/jameszeroX/XKeen` | 5, 59 | DOC |
| URL | `https://github.com/jameszeroX/XKeen/releases/download/2.0.1_Beta/xkeen.json` | 51 | DOC |
| URL | `https://github.com/jameszeroX/XKeen/wiki/Порядок-установки` | 53 | DOC |
| URL | `https://github.com/zxc-rv/XKeen-UI` | 94 | DOC |
| URL | `https://itsnotkubrick.github.io/3X-UI_KIT/tools/mihomo/` | 80 | DOC |
| URL | `https://itsnotkubrick.github.io/3X-UI_KIT/tools/xray/` | 77 | DOC |
| URL | `https://support.keenetic.ru/ultra/kn-1811/ru/31543-dot-and-doh-proxy-servers-for-dns-requests-encryption.html` | 45 | DOC |
| URL | `vless://` | 78 | DOC |
| host | `192.168.1.1` | 27 | DOC |
| host | `bin.entware.net` | 29, 30, 31 | DOC → CODE if manually executed |
| host | `github.com` | 5, 51, 53, 59, 94 | DOC |
| host | `itsnotkubrick.github.io` | 77, 80 | DOC |
| host | `support.keenetic.ru` | 45 | DOC |

### `scripts/3x-ui.sh`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `grpc://127.0.0.1:$port` | 822 | API / SUB / LOCAL (see runtime map) |
| URL | `http://127.0.0.1:$SUB_INTERNAL` | 949, 952 | API / SUB / LOCAL (see runtime map) |
| URL | `http://127.0.0.1:$SUB_PORT$SUB_PATH$SUBID` | 935 | API / SUB / LOCAL (see runtime map) |
| URL | `http://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH` | 376 | API / SUB / LOCAL (see runtime map) |
| URL | `http://127.0.0.1:$port` | 811 | API / SUB / LOCAL (see runtime map) |
| URL | `http://127.0.0.1:${INNER[sub]}` | 872 | API / SUB / LOCAL (see runtime map) |
| URL | `https://$HOST$SUB_PATH` | 916 | SUB / LOCAL template |
| URL | `https://$HOST$SUB_PATH$SUBID` | 934 | SUB / LOCAL template |
| URL | `https://$HOST/${XUI_WEB_BASE_PATH#/}` | 371 | SUB / LOCAL template |
| URL | `https://$HOST:$SUB_PORT$SUB_PATH` | 915 | SUB / LOCAL template |
| URL | `https://$HOST:$SUB_PORT$SUB_PATH$SUBID` | 935 | SUB / LOCAL template |
| URL | `https://$HOST:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH` | 374 | SUB / LOCAL template |
| URL | `https://127.0.0.1:$XUI_PANEL_PORT` | 876 | API / SUB / LOCAL (see runtime map) |
| URL | `https://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/panel/api` | 298 | API / SUB / LOCAL (see runtime map) |
| URL | `https://api.ipify.org` | 84 | PROBE |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 2, 145 | DOC |
| URL | `https://ifconfig.me/ip` | 84 | PROBE |
| URL | `https://ipv4.icanhazip.com` | 84 | PROBE |
| URL | `scheme://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/panel/api` | 289 | DOC / FORMAT (not a real connection) |
| URL | `scheme://127.0.0.1:$port$SUB_PATH$id` | 999 | DOC / FORMAT (not a real connection) |
| URL | `tg://` | 993 | PROBE / configured destination |
| URL | `vpn://` | 383, 417, 993 | PROBE / configured destination |
| host | `0.0.0.0` | 954 | LOCAL / DNS configuration |
| host | `1.1.1.1` | 88, 665 | LOCAL / DNS configuration |
| host | `1.2.3.4` | 237, 1020 | FIXTURE |
| host | `10.0.0.0` | 629 | LOCAL / DNS configuration |
| host | `10.0.0.2` | 630 | LOCAL / DNS configuration |
| host | `10.8.1.0` | 670 | LOCAL / DNS configuration |
| host | `10.8.1.2` | 670 | LOCAL / DNS configuration |
| host | `10.8.2.0` | 671 | LOCAL / DNS configuration |
| host | `10.8.2.2` | 671 | LOCAL / DNS configuration |
| host | `127.0.0.1` | 289, 298, 304, 307, 337, 376, 479, 482, 789, 790, 803, 804, 805, 811, 822, 829, 840, 841, 842, 843, 859, 864, 872, 876, 918, 935, 949, 950, 952, 999 | API / SUB / LOCAL (see runtime map) |
| host | `149.154.167.51` | 675 | PROBE / configured destination |
| host | `149.154.175.50` | 675 | PROBE / configured destination |
| host | `8.8.8.8` | 665 | LOCAL / DNS configuration |
| host | `91.108.56.130` | 675 | PROBE / configured destination |
| host | `api.ipify.org` | 84 | PROBE |
| host | `dl.google.com` | 43 | PROBE / configured destination |
| host | `example.com` | 244 | FIXTURE |
| host | `github.com` | 2, 145 | DOC |
| host | `ifconfig.me` | 84 | PROBE |
| host | `ipv4.icanhazip.com` | 84 | PROBE |
| host | `localhost` | 51, 384, 518, 948 | LOCAL |
| host | `www.amazon.com` | 43 | PROBE / configured destination |
| host | `www.cloudflare.com` | 255, 693 | PROBE / configured destination |
| host | `www.samsung.com` | 43 | PROBE / configured destination |
| host | `www.yahoo.com` | 43 | PROBE / configured destination |

### `scripts/hysteria2.sh`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://api.ipify.org` | 85 | PROBE |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 2 | DOC |
| URL | `https://ifconfig.me/ip` | 85 | PROBE |
| URL | `https://ipv4.icanhazip.com` | 85 | PROBE |
| URL | `hy2://` | 9 | SUB / LOCAL template |
| URL | `hy2://[REDACTED]@$HOST:$PORT/?$q#$u@$HOST` | 358 | SUB / LOCAL template |
| host | `1.1.1.1` | 89 | LOCAL / DNS configuration |
| host | `1.2.3.4` | 299, 488 | FIXTURE |
| host | `api.ipify.org` | 85 | PROBE |
| host | `example.com` | 286, 484 | FIXTURE |
| host | `github.com` | 2 | DOC |
| host | `ifconfig.me` | 85 | PROBE |
| host | `ipv4.icanhazip.com` | 85 | PROBE |
| host | `www.bing.com` | 307, 487 | LOCAL certificate SNI / SAN (no automatic third-party fetch) |

### `scripts/kit-sub.py`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 4 | DOC |
| URL | `tg://` | 142, 143, 152 | PROBE / configured destination |
| URL | `vpn://` | 142, 143, 152 | PROBE / configured destination |
| host | `0.0.0.0` | 75, 441 | LOCAL / DNS configuration |
| host | `127.0.0.1` | 6, 75, 291, 441 | API / SUB / LOCAL (see runtime map) |
| host | `github.com` | 4 | DOC |

### `scripts/kit.sh`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://127.0.0.1:$SUB_INTERNAL$SUB_PATH$sid$suffix` | 156 | API / SUB / LOCAL (see runtime map) |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 3 | DOC |
| URL | `scheme://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/panel/api` | 49 | DOC / FORMAT (not a real connection) |
| URL | `tg://` | 242 | PROBE / configured destination |
| URL | `tg://${N}` | 119 | PROBE / configured destination |
| URL | `vpn://` | 119, 242 | PROBE / configured destination |
| host | `127.0.0.1` | 49, 156 | API / SUB / LOCAL (see runtime map) |
| host | `github.com` | 3 | DOC |

### `scripts/security_scan.py`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| host | `example.com` | 26 | DOC |

### `scripts/supply-chain.lock.json`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://codeload.github.com/acmesh-official/acme.sh/tar.gz/807da6498377ee5e0cf43a78091f46f12dc59a89` | 31 | CODE |
| URL | `https://github.com/HyNetworks/hysteria/releases/download/app/v2.12.3/hashes.txt` | 63 | CODE |
| URL | `https://github.com/HyNetworks/hysteria/releases/download/app/v2.12.3/hysteria-linux-amd64` | 67 | CODE |
| URL | `https://github.com/HyNetworks/hysteria/releases/download/app/v2.12.3/hysteria-linux-arm64` | 71 | CODE |
| URL | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-386.tar.gz` | 35 | CODE |
| URL | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-amd64.tar.gz` | 39 | CODE |
| URL | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-arm64.tar.gz` | 43 | CODE |
| URL | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-armv5.tar.gz` | 47 | CODE |
| URL | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-armv6.tar.gz` | 51 | CODE |
| URL | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-armv7.tar.gz` | 55 | CODE |
| URL | `https://github.com/MHSanaei/3x-ui/releases/download/v3.8.5/x-ui-linux-s390x.tar.gz` | 59 | CODE |
| URL | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-32.zip` | 75 | CODE |
| URL | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-64.zip` | 79 | CODE |
| URL | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-arm32-v5.zip` | 83 | CODE |
| URL | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-arm32-v6.zip` | 87 | CODE |
| URL | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-arm32-v7a.zip` | 91 | CODE |
| URL | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-arm64-v8a.zip` | 95 | CODE |
| URL | `https://github.com/XTLS/Xray-core/releases/download/v26.6.27/Xray-linux-s390x.zip` | 99 | CODE |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/install.sh` | 103 | CODE |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.rc` | 15 | CODE |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.service.arch` | 23 | CODE |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.service.debian` | 19 | CODE |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.service.rhel` | 27 | CODE |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/x-ui.sh` | 11 | CODE |
| host | `codeload.github.com` | 31 | CODE |
| host | `github.com` | 35, 39, 43, 47, 51, 55, 59, 63, 67, 71, 75, 79, 83, 87, 91, 95, 99 | CODE |
| host | `raw.githubusercontent.com` | 11, 15, 19, 23, 27, 103 | CODE |

### `scripts/supply-chain.py`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://get.acme.sh` | 136 | CODE (adapter source; old URLs in replacement patterns need not execute) |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/${script_ref}/x-ui.rc` | 154 | CODE (adapter source; old URLs in replacement patterns need not execute) |
| URL | `https://raw.githubusercontent.com/MHSanaei/3x-ui/${script_ref}/x-ui.sh` | 153 | CODE (adapter source; old URLs in replacement patterns need not execute) |
| URL | `https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh` | 173 | CODE (adapter source; old URLs in replacement patterns need not execute) |
| host | `codeload.github.com` | 28 | CODE (adapter source; old URLs in replacement patterns need not execute) |
| host | `get.acme.sh` | 136 | CODE (adapter source; old URLs in replacement patterns need not execute) |
| host | `github.com` | 28 | CODE (adapter source; old URLs in replacement patterns need not execute) |
| host | `raw.githubusercontent.com` | 28, 153, 154, 173 | CODE (adapter source; old URLs in replacement patterns need not execute) |

### `tests/matrix/awg-set.sh`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/panel/api` | 4 | API |
| URL | `vpn://` | 23 | FIXTURE / PROBE template |
| host | `127.0.0.1` | 4 | API |

### `tests/matrix/matrix-gen.js`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| host | `127.0.0.1` | 21 | LOCAL |

### `tests/matrix/matrix-run.sh`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://www.google.com/generate_204` | 10 | PROBE / LOCAL |
| URL | `socks5h://127.0.0.1:$port` | 10 | PROBE / LOCAL |
| host | `127.0.0.1` | 10 | LOCAL |
| host | `www.google.com` | 10 | PROBE / LOCAL |

### `tests/matrix/mk-inbounds.sh`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://127.0.0.1:$XUI_PANEL_PORT/$XUI_WEB_BASE_PATH/panel/api` | 5 | API |
| host | `10.0.0.0` | 59 | FIXTURE / PROBE template |
| host | `10.0.0.2` | 59 | FIXTURE / PROBE template |
| host | `10.8.1.0` | 63 | FIXTURE / PROBE template |
| host | `10.8.1.2` | 63 | FIXTURE / PROBE template |
| host | `127.0.0.1` | 5 | API |
| host | `8.8.4.4` | 63 | FIXTURE / PROBE template |
| host | `8.8.8.8` | 63 | FIXTURE / PROBE template |
| host | `dl.google.com` | 29 | PROBE / LOCAL |
| host | `test.pm` | 8, 14 | FIXTURE certificate SNI / SAN (no automatic fetch) |
| host | `www.cloudflare.com` | 67 | FIXTURE / PROBE template |

### `tests/security_browser.test.js`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://example.invalid/sub/synthetic` | 61 | FIXTURE |
| URL | `hy2://` | 70 | FIXTURE |
| host | `0.0.0.0` | 64 | FIXTURE |
| host | `example.invalid` | 61, 70 | FIXTURE |

### `tests/security_scan_test.py`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://example.invalid/sub?token=[REDACTED]` | 103 | FIXTURE |
| URL | `hy2://[REDACTED]@example.invalid:443` | 80 | FIXTURE |
| URL | `hy2://user:` | 181 | FIXTURE |
| URL | `nvless://[REDACTED]@example.invalid:443` | 80 | FIXTURE |
| URL | `postgresql://user:` | 178 | FIXTURE |
| URL | `trojan://` | 180 | FIXTURE |
| URL | `vless://` | 179 | FIXTURE |
| URL | `vpn://` | 145 | FIXTURE |
| host | `example.invalid` | 80, 103, 162, 165, 178, 179, 180, 181 | FIXTURE |

### `tests/supply_chain/test_supply_chain.py`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://github.com/test` | 47 | FIXTURE |
| URL | `https://[REDACTED]@github.com/asset` | 47 | FIXTURE |
| URL | `https://evil.example/asset` | 47 | FIXTURE |
| URL | `https://github.com/test/asset` | 28, 42 | FIXTURE |
| host | `evil.example` | 47 | FIXTURE |
| host | `github.com` | 28, 42, 47 | FIXTURE |
| host | `raw.githubusercontent.com` | 131 | FIXTURE |

### `tests/test_kit_sub.py`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://127.0.0.1/sub/synthetic` | 182 | FIXTURE |
| URL | `http://127.0.0.1/synthetic` | 153 | FIXTURE |
| URL | `http://127.0.0.1:1` | 217 | FIXTURE |
| URL | `http://127.0.0.1:2097` | 19 | FIXTURE |
| URL | `http://127.0.0.1:2097#fragment` | 89 | FIXTURE |
| URL | `http://127.0.0.1:2097/private` | 88 | FIXTURE |
| URL | `http://127.0.0.1:2097?token=[REDACTED]` | 88 | FIXTURE |
| URL | `http://127.0.0.1:{server.server_port}` | 206 | FIXTURE |
| URL | `http://169.254.169.254:80` | 86 | FIXTURE |
| URL | `http://[::1]:2097` | 94, 95 | FIXTURE |
| URL | `http://[REDACTED]@127.0.0.1:2097` | 87 | FIXTURE |
| URL | `http://example.test:80` | 86 | FIXTURE |
| URL | `http://localhost:2097` | 86 | FIXTURE |
| URL | `https://127.0.0.1:2097` | 87 | FIXTURE |
| URL | `ntg://synthetic` | 466 | FIXTURE |
| URL | `ntrojan://synthetic` | 466, 467 | FIXTURE |
| URL | `nvless://synthetic` | 502 | FIXTURE |
| URL | `nvpn://synthetic` | 466 | FIXTURE |
| URL | `ttg://synthetic` | 502 | FIXTURE |
| URL | `vless://synthetic` | 412, 417, 466, 467, 503 | FIXTURE |
| URL | `vpn://[REDACTED]` | 502 | FIXTURE |
| host | `0.0.0.0` | 99 | FIXTURE |
| host | `127.0.0.1` | 19, 20, 54, 66, 87, 88, 89, 131, 135, 136, 140, 142, 153, 182, 202, 206, 217, 324, 394 | FIXTURE |
| host | `169.254.169.254` | 86 | FIXTURE |
| host | `evil.example.test` | 207, 227 | FIXTURE |
| host | `example.test` | 86 | FIXTURE |
| host | `localhost` | 86, 310 | FIXTURE |
| host | `test.invalid` | 425, 474 | FIXTURE |
| host | `vpn.example.test` | 20 | FIXTURE |

### `tools/lib/links.js`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `hy2://` | 1 | FIXTURE / SUB format |
| URL | `ss://` | 1, 147 | FIXTURE / SUB format |
| URL | `ss://[REDACTED]@` | 174 | FIXTURE / SUB format |
| URL | `tg://proxy` | 269, 281 | FIXTURE / SUB format |
| URL | `trojan://` | 1 | FIXTURE / SUB format |
| URL | `vless://` | 1 | FIXTURE / SUB format |
| URL | `vmess://` | 1, 119 | FIXTURE / SUB format |
| URL | `vpn://` | 263, 264 | FIXTURE / SUB format |
| host | `t.me` | 269, 281 | FIXTURE / SUB format |

### `tools/lib/mihomo.js`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://IP-роутера:9090/ui` | 256 | LOCAL |
| URL | `https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip` | 197 | DASH |
| URL | `https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/` | 6 | RULE |
| URL | `https://itsnotkubrick.github.io/3X-UI_KIT/tools/mihomo/` | 254 | DOC |
| URL | `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/` | 5 | RULE |
| URL | `https://www.gstatic.com/generate_204` | 211, 219 | PROBE |
| host | `0.0.0.0` | 194 | LOCAL |
| host | `github.com` | 6, 197 | RULE / DASH |
| host | `itsnotkubrick.github.io` | 254 | DOC |
| host | `raw.githubusercontent.com` | 5 | RULE |
| host | `www.gstatic.com` | 211, 219 | PROBE |

### `tools/lib/singbox.js`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://www.gstatic.com/generate_204` | 83 | PROBE |
| host | `0.0.0.0` | 60 | LOCAL |
| host | `127.0.0.1` | 81 | LOCAL |
| host | `www.gstatic.com` | 83 | PROBE |

### `tools/lib/xray.js`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://www.gstatic.com/generate_204` | 175 | PROBE |
| host | `0.0.0.0` | 71 | LOCAL |
| host | `www.gstatic.com` | 175 | PROBE |

### `tools/mihomo/index.html`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://` | 101 | DOC |
| URL | `http://192.168.1.1:9090/ui` | 116 | LOCAL |
| URL | `http://www.w3.org/2000/svg` | 8 | NS |
| URL | `https://` | 101 | DOC |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 13 | DOC |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT/tree/main/tools` | 57 | DOC |
| URL | `https://…` | 28 | DOC |
| URL | `vless://…&#10;hy2://…&#10;По` | 25 | FIXTURE / SUB format |
| URL | `vpn://` | 30 | FIXTURE / SUB format |
| URL | `wireguard://` | 30 | FIXTURE / SUB format |
| host | `192.168.1.1` | 113, 116 | LOCAL |
| host | `chat.example.org` | 46 | FIXTURE / SUB format |
| host | `example.com` | 46 | FIXTURE / SUB format |
| host | `github.com` | 13, 57 | DOC |
| host | `mybank.ru` | 48 | FIXTURE / SUB format |
| host | `www.w3.org` | 8 | NS |

### `tools/test/links.test.js`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `https://t.me/proxy?server=m.example.com&port=8445&secret=[REDACTED]` | 109 | FIXTURE |
| URL | `hy2://[REDACTED]@h:443-500` | 75 | FIXTURE / SUB format |
| URL | `hy2://[REDACTED]@hy.example.com:443/?sni=hy.example.com&insecure=1&pinSHA256=AB:CD:EF&obfs=salamander&obfs-password=[REDACTED]#hy` | 16 | FIXTURE / SUB format |
| URL | `ss://` | 13, 15 | FIXTURE / SUB format |
| URL | `ss://[REDACTED]@198.51.100.8:443#ss22` | 14 | FIXTURE / SUB format |
| URL | `tg://proxy?server=m.example.com&port=8445&secret=[REDACTED]` | 108 | FIXTURE / SUB format |
| URL | `trojan://[REDACTED]@t.example.com:443?type=grpc&serviceName=gun&security=tls&sni=t.example.com#grpc` | 11 | FIXTURE / SUB format |
| URL | `tuic://[REDACTED]@t.example.com:8444?alpn=h3&congestion_control=bbr&udp_relay_mode=native#tuic` | 99 | FIXTURE / SUB format |
| URL | `tuic://[REDACTED]@y:1` | 60 | FIXTURE / SUB format |
| URL | `vless://@h:443` | 73 | FIXTURE / SUB format |
| URL | `vless://[REDACTED]@203.0.113.10:443?type=tcp&security=reality&pbk=Fj98Liz-8fJCAaK_hcsGDJRSd9ztkw0TDR2v4kqK7TA&fp=chrome&sni=www.microsoft.com&sid=2831cdcf4a278ac2&spx=%2F&flow=xtls-rprx-vision#%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F` | 8 | FIXTURE / SUB format |
| URL | `vless://[REDACTED]@cdn.example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1#ws` | 9 | FIXTURE / SUB format |
| URL | `vless://[REDACTED]@h:443?security=reality` | 74 | FIXTURE / SUB format |
| URL | `vless://[REDACTED]@h:99999` | 76 | FIXTURE / SUB format |
| URL | `vless://[REDACTED]@x.example.com:443?type=xhttp&security=reality&pbk=abc&sid=01&sni=www.apple.com&path=%2Fx&mode=packet-up#xhttp` | 10 | FIXTURE / SUB format |
| URL | `vmess://` | 12 | FIXTURE / SUB format |
| URL | `vpn://` | 98, 105, 124 | FIXTURE / SUB format |
| URL | `wireguard://[REDACTED]@w.example.com:51820?address=10.0.0.2%2F32&mtu=1420&publickey=cHVi#wg` | 102 | FIXTURE / SUB format |
| host | `10.0.0.2` | 102, 103 | FIXTURE |
| host | `10.8.1.2` | 104 | FIXTURE |
| host | `10.8.2.2` | 123 | FIXTURE |
| host | `198.51.100.7` | 13 | FIXTURE |
| host | `198.51.100.8` | 14 | FIXTURE |
| host | `198.51.100.9` | 15, 48 | FIXTURE |
| host | `203.0.113.10` | 8 | FIXTURE |
| host | `a.example.com` | 104, 123 | FIXTURE |
| host | `cdn.example.com` | 9 | FIXTURE |
| host | `hy.example.com` | 16 | FIXTURE |
| host | `m.example.com` | 108, 109 | FIXTURE |
| host | `t.example.com` | 11, 99 | FIXTURE |
| host | `t.me` | 109 | FIXTURE |
| host | `v.example.com` | 12 | FIXTURE |
| host | `w.example.com` | 102 | FIXTURE |
| host | `www.apple.com` | 10 | FIXTURE |
| host | `www.microsoft.com` | 8 | FIXTURE |
| host | `x.example.com` | 10 | FIXTURE |

### `tools/xray/index.html`

| Kind | Literal (credentials redacted) | Line(s) | Class |
|---|---|---|---|
| URL | `http://www.w3.org/2000/svg` | 8 | NS |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT` | 13 | DOC |
| URL | `https://github.com/itsnotkubrick/3X-UI_KIT/tree/main/tools` | 60 | DOC |
| URL | `ss://` | 7 | FIXTURE / SUB format |
| URL | `trojan://` | 7 | FIXTURE / SUB format |
| URL | `vless://` | 7 | FIXTURE / SUB format |
| URL | `vless://…&#10;По` | 25 | FIXTURE / SUB format |
| URL | `vmess://` | 7 | FIXTURE / SUB format |
| host | `192.168.1.1` | 146 | LOCAL |
| host | `chat.example.org` | 46 | FIXTURE / SUB format |
| host | `example.com` | 46 | FIXTURE / SUB format |
| host | `github.com` | 13, 60 | DOC |
| host | `mybank.ru` | 48 | FIXTURE / SUB format |
| host | `www.w3.org` | 8 | NS |

## Appendix B: inventory snapshot file digests

SHA256 of source bytes with CRLF normalized to LF (same convention as immutable fixture exemptions); these are **snapshot evidence**, not a signed release manifest or a remote binary hash. Files without literals are included to establish complete source coverage.

| Source file | SHA256 (normalized LF) |
|---|---|
| `.nojekyll` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `KIT_SUB_INTEGRATION.md` | `63821f5be3f72ad8f9561c93d110596813875f0172f7321aca5d9419e2f082f6` |
| `README.md` | `b235d091267a704bc303145a9427f4e5d6c2b964bf751fd41e9117f44b95100e` |
| `SUPPLY_CHAIN_NOTES.md` | `5e14e7eec41bbd99fe266afae3f0b159ea00ea184c8e57e38e7651df01095b63` |
| `docs/SECURITY_MODEL.md` | `110f6ea2a5b81feecf2eaf3485d6808f8a6e1653de49108253ebf15e631f20ce` |
| `index.html` | `2d1290c86c1dfed5d51a88ed1c4a44abeeb5377b72cfbabfc0ddd753db80bf16` |
| `manuals/3x-ui.md` | `8c52249180dd5679ec0cac6f70961987e98aae0c52b425fe822d54393548f6a2` |
| `manuals/assets/banner.svg` | `8cc82e8b4e3c3c3282a30f1c244ddab953f5cf7264346027c83efb6e77658507` |
| `manuals/assets/entware-installer.svg` | `8e85af54d2e4cf8fc5678a6d9b0aac1830653ad018f20a23c1bb10568a0a02df` |
| `manuals/assets/keenetic-components.svg` | `42870d80bb73fca33c1168b542500e44442a0a7bf93b759c62958a650a320079` |
| `manuals/assets/keenetic-opkg.svg` | `ace8b5920d3869b5c235b7cf52423fe9220f5c5541d6a57702b78429139b6eb7` |
| `manuals/assets/script-3x-ui.svg` | `5c85aa51a51dfb4fc27f8eaa454070a7271c5a9e5cc6c2543157599a11579a3c` |
| `manuals/assets/script-hy2-add.svg` | `bb734196ae6339afdeaf8d93aba2db22e6fc56ae9af199d96120f127634ac3da` |
| `manuals/assets/script-hysteria2.svg` | `0917093aac37b18fd3cb04d9716360b0377d69527d57c7d7f8eb84d6043c154d` |
| `manuals/assets/xkeen-configs.svg` | `1edfcde03cca42e54402bed76d45325e1445d8c573db217b0490cc4bd35ec39f` |
| `manuals/hysteria2.md` | `b5e4b86351ac4205ed543b8c23e5572ed9536837ace11ae29df37458a06e11b3` |
| `manuals/xkeen-keenetic.md` | `9635de630152cb5799cbaaf03d179b0cc63c9a5982a6f107f61e85a999bbef81` |
| `scripts/3x-ui.sh` | `e08db96a17d6b9f5640ef774472f90d6d5f73969712c68082089614186c9f098` |
| `scripts/hysteria2.sh` | `d05b68b08ef79376736ae0a0ac210a320b49f61370375e3106922a356422c909` |
| `scripts/kit-sub.py` | `c525bc172bf8d8b2785338fa2b0c0548d0d7bba2c88caf00ab94de06a036f1be` |
| `scripts/kit.sh` | `5367b352b12c5a8aaa426f54ff4f2a036a91bb873cf515676eed618b3eed1b71` |
| `scripts/security-check.sh` | `cc500fbb26b6ff6a04588e87e44f3321f0a2f095dcf2fd1790236a9ccadd5759` |
| `scripts/security_scan.py` | `26810ced4a195e53cac192823bd2e8079e12f34215aadd0c4a3b3c9e2e5f35f3` |
| `scripts/supply-chain.lock.json` | `fe42b62f2916b04d5d2a62d6d0621f57ffdddabaadc2512acd85a9d972684df9` |
| `scripts/supply-chain.py` | `10ac0491b227d347da4c2d339c12bb0dd7a98a586595b7c77bc9c30555ce3801` |
| `tests/matrix/README.md` | `586d44b39fcaae1fb158757dcedf03d06d10aff2c1d79bd3660a6a2ee4adc9ed` |
| `tests/matrix/awg-set.sh` | `d26832f7dba8688e8c103b2b517ac9989e0424ce162d5dcf62a8cdb8b9b0ab86` |
| `tests/matrix/matrix-gen.js` | `348ae8d2ae23157a72a6296b7c6b1cb645bc0a2b743a1e33a6e4ddfb0d43b101` |
| `tests/matrix/matrix-run.sh` | `2e02cd039998270ce4266fb6451a1adfed3e35daf13da6cccf559acc0664c535` |
| `tests/matrix/mk-inbounds.sh` | `24d2b70520a5c9fdb5be38abe1b22867d232b8f93e9c3c8ac3b94207ad1cd4f7` |
| `tests/security_browser.test.js` | `c1c73ab155c3934ab7c11d564032c0f2f7e34169775d4a9f8e65acdc9e8ec799` |
| `tests/security_scan_test.py` | `1adeca06c69940383bda4a59524c8a4208af6fe86aebd6a0c745789053cf6be8` |
| `tests/supply_chain/fetch_pinned.py` | `4a16875dccfad13bc8582fa4c1e482015a456911f4ba661e61d099359c96195d` |
| `tests/supply_chain/test_supply_chain.py` | `40ef8117e4ad953ea36e1b7e4def779dd5ac1685714858b3039bed9533120f37` |
| `tests/test_kit_sub.py` | `a0bb99b560b3a4e60ca01e718591307671b1054616bce8742c6ae09542dfd80c` |
| `tools/index.html` | `7d7d302a940874be4d523450c62585e40dcfca3434e92d1b1b4480ba26faefe0` |
| `tools/lib/links.js` | `31dba7751bed7252f74421a2dd0e0336e89438423d0f6e9fe902d5f6af211adc` |
| `tools/lib/mihomo.js` | `130c0bc832509272ff07ee5ea6a98db27744c66834c5490ba5452e7e13a7cffe` |
| `tools/lib/singbox.js` | `adf1f5e5279ee0e33d6fc530398a7c3081479f05e24249bc115d17e35f2083ec` |
| `tools/lib/ui.css` | `a142df45604f870c024ccad9b94efa19b0c77b6cf3f2ee5146891263a64911c8` |
| `tools/lib/ui.js` | `afba979c8af9f9f3364822a3cd65a27dd0f776ce6ba93b0541e497a7e8a322b8` |
| `tools/lib/xray.js` | `2ad7c424d650ef74336d233e9f1afd1f3ce71b3a622c3c17b4519bd0d0d1b0ec` |
| `tools/mihomo/index.html` | `55506ecfc6db5a9ad83f053e7fb0bc4236f94fb2b146431bc9ea97e0733aff62` |
| `tools/test/links.test.js` | `ed2a85357b9aeb8d63685c36bee7469a7189f8ea7d3f2e17dc550f294688c75d` |
| `tools/xray/index.html` | `19507d20ea31cb2759cf4be92e57e9f7de679b8a626059d377898935384cee3d` |
