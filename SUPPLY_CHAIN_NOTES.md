# Supply-chain audit and pin provenance

Scope: `scripts/3x-ui.sh`, `scripts/hysteria2.sh`, `scripts/kit.sh`, and the new supply-chain helper/lock/tests. No installers, services, downloaded executables, container builds, commits or pushes were run. Upstream attribution is retained. The kit-sub service least-privilege change belongs to the separate parent-reviewed patch, not this change.

## Trust boundary and bundle contract

- Installation starts from an **operator-authenticated release archive**. The agreed release contract is `3X-UI_KIT-secure-v1.0.0.tar.gz`, intended for publication by `zordanexe/3X-UI_KIT` under `secure-v1.0.0`; this task did not publish or verify the existence of that kit release. The publisher is trusted to review source and pins. An externally obtained archive digest/signature must be authenticated before extraction/execution. This change does not pretend that a checksum obtained beside an untrusted download authenticates its publisher.
- Extracted layout is `scripts/` adjacent to a root `SHA256SUMS`. Its entries cover **all files actually included in the release bundle, except SHA256SUMS itself**. The separate release-asset SHA256SUMS covers the archive and the four directly published kit scripts; it is not interchangeable with the internal manifest. Packaging must use LF shell scripts/manifest and regenerate hashes **after** every parent/child edit.
- Each Bash entrypoint checks its helper, lock and four kit scripts before executing helper code. Python then rejects malformed/duplicate manifest entries, traversal, manifest self-listing, missing required files, unlisted files and symlinks. There is no network fallback for kit.sh, kit-sub.py or hysteria2.sh, and no KIT_SUB_SRC override. Use a dedicated extracted release directory, not a checkout with additional unmanifested files.
- `/usr/local/lib/3x-ui-kit/<manifest SHA256>/` retains the complete verified bundle. `kit` and `hy2` symlink to their scripts inside it, so their helper, pins and adjacent components survive removal of the original extracted download.
- `hy2 update [bundle-directory]` uses a local verified bundle. Without an argument it uses its existing installed bundle and current pinned version; it does not discover a new release. Operators must separately authenticate a new release before supplying its directory.
- SHA256 pins detect changed bytes and tag/release-asset replacement relative to this reviewed lock. They **do not prove upstream code is benign**, authenticate the first acquisition independently of GitHub/TLS, guarantee reproducible upstream builds, or defend against root/administrator compromise. The script/interpreter, PATH, package repositories, root-owned state/hooks and release-publisher identity are trusted. Editing a manifest with its files defeats checksum-only local tamper detection.

## Exact upstream inputs

All lock values were calculated from actual downloaded bytes without executing them. Every SHA256 in `scripts/supply-chain.lock.json` has a corresponding download; no hashes were invented or copied solely from descriptions.

| Input | Selected identity | SHA256 of downloaded bytes |
|---|---|---|
| MHSanaei/3x-ui installer | v3.8.5; commit `7ef22f94c950ff09f0870e2295fa65ad5968742c` | `4e3fe7fe00ef8e904ce6a0e9c36fd8a0c7179fe5e786f23e31801aee84c6347d` |
| Matched upstream x-ui.sh | same commit | `7f64543f783b0939dbf803bb24b835c80edb04daca70dbcb3ecf69e2a5ce3ab5` |
| acmesh-official/acme.sh source archive | 3.1.6; commit `807da6498377ee5e0cf43a78091f46f12dc59a89` | `ddbe1bcbd1a44a2623a2af167ebdc678669e6e2eb396742f2d1d28e02dc14220` |
| Hysteria amd64 | HyNetworks/hysteria app/v2.12.3 | `8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e` |
| Hysteria arm64 | same release | `c8dc653c3ba0a28d29a26b8fa52d2086f27c0927afddce95c09965e7174e78b0` |

The lock also records every 3x-ui archive and Xray zip for `amd64`, `386`, `arm64`, `armv5`, `armv6`, `armv7`, `s390x`, and the three distro service files plus OpenRC script. Xray remains `v26.6.27` for the upstream kit's client-compatibility requirement. Release binary digests matched GitHub release API `digest` values. Hysteria hashes additionally matched the downloaded release `hashes.txt`, whose digest is itself recorded in the lock. That file is provenance evidence, **not** a runtime authority: runtime Hysteria validation uses embedded reviewed pins.

Sources:
- https://api.github.com/repos/MHSanaei/3x-ui/commits/v3.8.5
- https://api.github.com/repos/MHSanaei/3x-ui/releases/tags/v3.8.5
- https://raw.githubusercontent.com/MHSanaei/3x-ui/7ef22f94c950ff09f0870e2295fa65ad5968742c/install.sh
- https://api.github.com/repos/acmesh-official/acme.sh/commits/3.1.6
- https://codeload.github.com/acmesh-official/acme.sh/tar.gz/807da6498377ee5e0cf43a78091f46f12dc59a89
- https://api.github.com/repos/HyNetworks/hysteria/releases/tags/app/v2.12.3
- https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.6.27

## Audited execution paths and implemented changes

Baseline evidence refers to commit `4f1e5d98ccd0e34083e844ed7f4c0849658be7dd` (local line numbers shift after hardening).

| Classification / severity | Baseline evidence and trigger | Impact / remediation / check |
|---|---|---|
| Confirmed vulnerability / HIGH | `scripts/3x-ui.sh:236` downloads the tagged installer without an independently locked byte digest; transitive `install.sh:357-393,1419-1501` bootstraps ACME/TUIC/menu/service inputs | Upstream/tag/content replacement runs changed code as root. Commit source + artifact SHA256 pins and source-hash-checked offline adapters remove those executable fetches; mismatch/adaptation tests refuse changed bytes. |
| Confirmed vulnerability / HIGH | `scripts/3x-ui.sh:913-925` uses mutable main or KIT_SUB_SRC for privileged subscription code; `:736-742` reintroduces mutable bootstrap guidance | Changed remote/internal code gains privileged execution. Only verified adjacent bundle components are used; static checks forbid mutable main/override and installed-bundle tampering is refused. |
| Confirmed vulnerability / HIGH | `scripts/hysteria2.sh:15,97-112,429-430` authenticates binary only against the same release sidecar, downloads the CLI from mutable main, then executes self-update as root | Replacement of upstream/sidecar/self-update can change executable code. Embedded pins, atomic authenticated binary replacement and persistent local-bundle update replace these paths; negative fetch tests preserve the trusted target. |
| Confirmed vulnerability / HIGH | `scripts/3x-ui.sh:283` asks the privileged panel API to install Xray without this kit's verified executable digest | Changed upstream release input can run as root. Download/verify/extract the locked Xray zip locally before replacement; all seven supported archives prepared without execution. |
| Intentional or standard design | Root environment/configuration hooks and OS repositories are trusted; GeoIP/GeoSite menu updates are data | Not a root sandbox or independent reproducible-build attestation. Preserve operator controls and document remaining trust; live acceptance below remains NOT_TESTED. |

### 3x-ui.sh

The original installer download selected a tag, but did not authenticate its bytes. Its upstream child installer fetched a release archive and a same-server checksum with a tolerated 404, downloaded the menu/service files, bootstrapped acme through get.acme.sh, enabled automatic code upgrades and could fetch TUIC. The kit then requested an Xray download through the panel API without a reviewed digest.

The helper now downloads and verifies the commit-pinned installer/menu/service inputs and selected release archive **before invoking any upstream code**. It validates archive member paths/types, prepares a narrowly adapted offline upstream installer, and retains installation/configuration/certificate/fail2ban logic. Exact-source hash checks and exact replacement counts refuse source drift. TUIC and MTProto executable bytes are authenticated as part of the panel archive; there is no unverified TUIC fallback. Upstream does not provide bundled TUIC on armv5/armv6/s390x; those upstream limitations remain. Xray is downloaded/verified directly, and its binary is replaced locally rather than using `server/installXray`.

ACME installs from the authenticated commit archive. Its online installer and upgrade function cannot download/execute replacement code, and automatic code upgrades are disabled while the existing renewal cron and certificate hooks remain. Both upstream menu copies are hardened before installation: mutable install/update/dev/legacy/menu replacement paths refuse and explain that a verified release bundle is needed. The speedtest menu can run an already installed speedtest, but cannot bootstrap third-party repository shell code. Ordinary panel/service/user/certificate management is retained. The installation log is mode 0600 and failure handling does not dump credentials from it to stderr.

IP-echo responses are used as data, not code. Panel/API/subscription curl calls target loopback and use `-k` because of local TLS; this is not artifact-download TLS policy. Telegram checks use fixed IPs and do not fetch code. The upstream menu's operator-triggered GeoIP/GeoSite ruleset update remains mutable **data**, not executable code; malicious ruleset replacement can still alter routing, and those datasets are outside the executable artifact lock. Root-owned install-result.env is sourced as before and therefore remains a trusted executable state file.

### hysteria2.sh

The original same-release hashes.txt comparison could be defeated by replacement of both the binary and sidecar, and self-install/update could fetch mutable main and execute it as root. Runtime binary pins now come from the verified local lock. No mutable script download remains, and the CLI preserves its complete local bundle. Update always verifies/replaces the pinned binary; it does not run an old binary to decide whether its self-reported version is trusted. Failed verification leaves the installed binary untouched; download temporary files are cleaned. Management state remains root-owned and sourced. Existing legacy state migration is retained but is no longer a top-level file-load action.

### kit.sh

There is no remote code-install path. It now requires the same verified bundle and validates the presence of the existing API token. A raw-byte audit of HEAD and the working tree confirmed that the apparently masked API header in tool views was **display redaction**, not a literal placeholder in source: upstream uses `$XUI_API_TOKEN` (and 3x-ui.sh uses `$TOKEN`/`$XUI_API_TOKEN`). No token value was printed and no authentication placeholder was introduced. The two root state files remain executable trusted inputs. API and subscription responses are JSON/text data and are not executed.

## Verification and remaining risk

The safe tests exercise real helper behavior for checksum refusal/atomic replacement, hardened curl flags, URL/credential rejection, manifest validation/persistence, isolated Bash bootstrap refusal, unsafe archive rejection, real pinned upstream adaptation and static entrypoint checks. Dependency preparation uses actual downloaded upstream bytes; adapted upstream scripts receive only `bash -n`, never execution. The isolated bootstrap and the local Python test/helper CLIs are exercised separately without invoking installation entrypoints. Fetch transport is mocked for deterministic negative cases. `tests/supply_chain/fetch_pinned.py CACHE_DIRECTORY` reproduces the reviewed input cache without executing any dependencies; set `KIT_SC_AUDIT_CACHE` to that directory to include the upstream integration tests.

Classification: the mutable/unverified root execution paths are **Confirmed vulnerability** findings, remediated within this entrypoint boundary. Root-managed configuration and signed OS package-manager trust are **Intentional or standard design**. The apparent masked API header is not a **Confirmed functional defect**; raw source uses the intended variable. Linux/runtime compatibility remains an **Unverified hypothesis** until the below acceptance checks are performed. Installation decision: suitable for parent review and controlled Linux acceptance, not a claim of production acceptance.

Observed safe verification: 16 unit/static/integration tests passed with the real upstream cache enabled (no skipped upstream cases); all 24 locked artifacts matched actual-byte SHA256, 17 matched saved GitHub release API digest values, both Hysteria binary pins matched the release sidecar, and both source commits matched saved GitHub commit responses. All seven supported panel/Xray architecture pairs prepared successfully without execution; adapted installer/menu/ACME syntax passed `bash -n` for each. Real helper CLI verify/persist/read-back succeeded and subsequent installed-bundle tampering was refused. Scoped shell syntax, Python parsing, LF-only files and `git diff --check` passed. ShellCheck is unavailable. These are local verification receipts, not reproducible-build claims or runtime acceptance.

NOT_TESTED: Linux installation, real systemd lifecycle/reboot, certificate issuance/renewal, VPN connectivity or all supported CPU execution. Docker daemon is unavailable. Package-manager installs rely on the configured OS repositories and signed package metadata, not this artifact lock. Root may still deliberately update components through the panel's own privileged UI/API or manually replace files; this change is not a sandbox/egress policy for the installed upstream binary. Runtime-panel update handlers and root-managed preexisting configuration are outside the three-script supply-chain boundary. Least-privilege service changes are handled separately by the parent.

Changing pins is a reviewed maintenance operation: download new identities, independently review upstream changes, calculate actual hashes, update the exact adapters/tests, run the safe suite, then regenerate both release manifests. Updating a version string alone must never silently accept new executable bytes.
