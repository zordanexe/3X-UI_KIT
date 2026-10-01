# Security model / модель безопасности

Security-hardened fork of [itsnotkubrick/3X-UI_KIT](https://github.com/itsnotkubrick/3X-UI_KIT). Исходный автор и история сохранены. Это не независимая реализация и не гарантия отсутствия уязвимостей.

## Trust boundaries

Installer выполняется root **только на предназначенном для VPN Linux VPS**, изменяет пакеты, службы, firewall и сертификаты. Не запускайте его на основной Windows-машине. Статический аудит не заменяет установку на disposable Ubuntu 22.04/24.04 и Debian 12/13. Обновляемые APT-пакеты доверяют подписи и ключам дистрибутива; snapshots пакетов здесь не закреплены, побитовая воспроизводимость всего VPS не заявляется.

Release SHA256 фиксирует байты, но не доказывает авторство. Манифест, загруженный с того же GitHub release, защищает от случайной порчи и несогласованного bundle, а не от компрометации GitHub account. Сверяйте SHA256 archive с сохранённым независимо проверенным значением. Git tags и release assets технически могут быть изменены владельцем; идентичность обеспечивается commit SHA и заранее доверенным hash, а не названием тега.

## Secrets

**SUBSCRIPTION URL = SECRET / BEARER CREDENTIAL.** Имеющий ссылку может получить конфигурацию доступа. Не публикуйте ссылки, ключи, QR-коды, логи установки и screenshots в chats/issues. При компрометации удалите/отключите пользователя через `kit user off`/`kit user del`, создайте новые credentials и обновите клиенты; простая смена URL не отзывает уже раскрытые protocol credentials. Отдельно смените панельный password/API token при их утечке.

`/root/3x-ui.txt` и `/etc/x-ui/install-result.env` должны быть root:root 0600. `/etc/kit/kit.env` также содержит secrets. kit-sub получает только собственный config и необходимые TLS copies; он не должен читать базу панели, install-result.env, REALITY/WireGuard private keys или root home. Сертификат публичен, private key — нет. Не используйте `chmod 644 /root/cert/*`.

Обычный access log подписки отключён. Настройки внешнего CDN, reverse proxy, Xray и логирование клиентов находятся вне этого контроля: отключите URL logging там отдельно. Терминальный вывод `kit user link` намеренно раскрывает secrets оператору; не записывайте его в публичный transcript. Installer сохраняет credentials в root-only `/root/3x-ui.txt` без вывода secrets/QR.

## Hardening admin panel (optional, manual deployment mode)

Случайный URL панели не является полноценным access-control. Tailscale не требуется. Default маршрутизация не меняется автоматически.

В single-port/nginx deployment сохраните subscription `location $SUB_PATH` без allowlist, а **только** в сгенерированном panel `location` добавьте allowlist, например `allow 203.0.113.10; deny all;` (замените documentation IP собственным). `real_ip_header proxy_protocol` допустим только при loopback внутреннем listener и единственном локальном stream proxy; не открывайте этот listener наружу. Сделайте backup `/etc/nginx/conf.d/kit.conf`, выполните `nginx -t`, только затем reload; при повторном запуске installer конфиг генерируется заново — повторно проверьте allowlist.

Для SSH-only режима в panel location разрешите только `127.0.0.1`/`::1` и отклоните всё остальное. Убедитесь, что сама панель слушает loopback и прямой panel port закрыт firewall; наличие nginx allowlist не закрывает обход через отдельный открытый panel port. Tunnel пример: `ssh -N -L 18443:127.0.0.1:443 root@VPS_HOST`, затем откройте HTTPS `localhost:18443/<panel-path>/`; certificate hostname может не совпасть. Не отключайте глобально TLS validation ради этого. Subscription остаётся публичным bearer endpoint. Этот режим требует отдельного acceptance test панели и подписки на VPS; статическим Windows аудитом он не считается runtime-проверенным.

Перед сменой firewall оставьте существующий SSH session открытым и проверьте второй; не вводите глобальный default deny без rollback.

## External connections / telemetry

IP detection обращается к внешним public-IP сервисам; они видят source IP и стандартные HTTP/TLS metadata. Credentials VPN им не требуются. REALITY SNI проверки выполняют внешние TLS probes: remote SNI host видит IP сервера и handshake. ACME CA получает IP/domain, account/contact metadata и challenge. Подробности — [EXTERNAL_CONNECTIONS.md](EXTERNAL_CONNECTIONS.md).

Генераторы — локальная обработка введённых VPN URLs в браузере. Это не делает CDN, upstream-hosted pages или полученные generated configs доверенными автоматически. Для аудированной версии используйте локальную копию tools из проверенного bundle. Dynamic rulesets, connectivity probes и optional dashboard resources в generated config — отдельные runtime connections клиента. Не передавайте private URLs публичным paste services.

## Upgrade / rollback

Не применяйте unattended `latest` updates через upstream panel. Resume по существующему `install-result.env` сначала сравнивает реально установленные panel/sidecar binaries, обе menu copies, service unit и ACME code/hooks с закреплёнными bytes/adapters; root ownership или version string не являются provenance. Legacy/plain upstream и неполные/изменённые установки отклоняются до административных изменений. При недоступности verification восстановите Python/network и повторите, не удаляя state. Для deliberate migration сначала остановите свои службы/renewal jobs и сохраните root-only backup data, затем замените legacy code проверенным bundle; не запускайте старый uninstaller и не удаляйте один env ради обхода защиты. Это не автоматический upgrade старой установки.

Обновление критических executable компонентов требует нового reviewed pin/hash и нового release bundle. До installer upgrade сделайте защищённый backup конфигурации, базы панели, сертификатов и firewall вне Git. Git revert откатывает **исходный код fork**, не состояние установленного VPS. Re-run installer может перезаписать конфиги и credentials; не считать его универсальным rollback. Matrix tests предназначены исключительно для disposable hosts.

## Upstream / License status

На момент fork commit `4f1e5d98ccd0e34083e844ed7f4c0849658be7dd` явная LICENSE исходного 3X-UI_KIT не обнаружена. Новая LICENSE для чужого кода не добавлена; разрешение на произвольное распространение вне GitHub fork не предполагается. GitHub fork сохраняет upstream relation и attribution.

Отдельные компоненты имеют собственные лицензии, подтверждённые GitHub license API: MHSanaei/3x-ui — GPL-3.0; XTLS/Xray-core — MPL-2.0; apernet/hysteria — MIT; MetaCubeX/mihomo — MIT. Эти лицензии не распространяются автоматически на KIT. Для AmneziaWG, TUIC и других встроенных компонентов применимы их собственные notices; не приписывайте им неподтверждённую лицензию.
